from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from config import fernet
import base64, datetime, time, redis, random, string
import database
from email_utils import send_verification_email

app = FastAPI(title="Microsserviço de Autenticação (Inseguro)")

redis_client = redis.Redis(host='localhost', port=6379, db=0)

class SignupData(BaseModel):
    email: str
    doc_number: str
    password: str
    username: str
    full_name: str

class LoginData(BaseModel):
    login: str
    password: str

class RecoverRequest(BaseModel):
    email: str
    document: str

class RecoverVerify(BaseModel):
    email: str
    document: str
    code: str
    new_password: str

def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def generate_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

def make_token(email: str, doc_number: str) -> str:
    raw = f"{email}:{doc_number}".encode()
    token = fernet.encrypt(raw)
    return token.decode()

def decrypt_token(token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except:
        return None

def extract_token_from_header(auth_header: str | None) -> str | None:
    if not auth_header:
        raise HTTPException(status_code=401, detail="Token inválido")

    token = auth_header.strip().replace('"', '')
    if not token.startswith("SDWork "):
        raise HTTPException(status_code=401, detail="Token inválido")

    token = token[len("SDWork "):].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token inválido")

    return token

def check_throttling(token: str):
    key = f"throttle_me:{token}"
    count = redis_client.incr(key)

    if count == 1:
        redis_client.expire(key, 60)

    if count == 2:
        delay = 3
    elif count == 3:
        delay = 5
    else:
        delay = 0

    if delay > 0:
        print(f"[THROTTLING] Atrasando resposta em {delay}s (requisição nº {count})")
        time.sleep(delay)

def apply_rate_limit(identifier: str, limit: int = 3, window_seconds: int = 60):
    key = f"ratelimit:{identifier}"
    current = redis_client.get(key)

    if current is None:
        redis_client.setex(key, window_seconds, 1)
    else:
        count = int(current)
        if count >= limit:
            ttl = redis_client.ttl(key)
            raise HTTPException(
                status_code=429,
                detail=f"Muitas requisições. Aguarde {ttl if ttl > 0 else window_seconds} segundos."
            )
        else:
            redis_client.incr(key)

RATE_LIMITS = {
    "/api/v1/auth/signup": (3, 60),
    "/api/v1/auth/recovery/request": (1, 60),
    "/api/v1/auth/me": (3, 60),
    "/api/v1/test/ratelimit": (3, 60),
    "default": (5, 60),
}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    try:
        public_routes = ["/docs", "/openapi.json", "/api/v1/auth/login"]

        if request.url.path in public_routes:
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if auth_header:
            try:
                token = extract_token_from_header(auth_header)
                identifier = token or request.client.host
            except HTTPException as e:
                return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
        else:
            identifier = request.client.host

        path = request.url.path
        limit, window = RATE_LIMITS.get(path, RATE_LIMITS["default"])

        try:
            apply_rate_limit(identifier, limit=limit, window_seconds=window)
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})

        response = await call_next(request)
        return response

    except Exception:
        return JSONResponse(status_code=500, content={"detail": "Erro interno do servidor"})

@app.post("/api/v1/auth/signup")
def signup(data: SignupData, request: Request):
    now = now_str()
    try:
        database.execute_query('''
            INSERT INTO users (email, doc_number, password, username, full_name, loggedin, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        ''', (data.email, data.doc_number, data.password, data.username, data.full_name, now, now))
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            raise HTTPException(status_code=400, detail="E-mail ou documento já cadastrado")
        raise HTTPException(status_code=500, detail=str(e))

    user = database.execute_query(
        "SELECT id FROM users WHERE email=? AND doc_number=?",
        (data.email, data.doc_number),
        fetch=True
    )
    if not user:
        raise HTTPException(status_code=500, detail="Erro ao recuperar usuário cadastrado")

    user_id = user[0][0]
    token_encoded = make_token(data.email, data.doc_number)
    existing = database.execute_query(
        "SELECT id FROM tokens WHERE id_user=? AND token=?",
        (user_id, token_encoded),
        fetch=True
    )
    if not existing:
        database.execute_query('''
            INSERT INTO tokens (id_user, token, created_at)
            VALUES (?, ?, ?)
        ''', (user_id, token_encoded, now))

    return {"token": token_encoded}


@app.post("/api/v1/auth/login")
def login(data: LoginData):
    user_row = database.execute_query(
        "SELECT id, email, doc_number, password FROM users WHERE email=?",
        (data.login,),
        fetch=True
    )
    if not user_row:
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

    user_id, email, doc_number, correct_password = user_row[0]

    last_fail = database.execute_query(
        "SELECT attempt_time FROM login_attempts WHERE id_user=? AND successful=0 ORDER BY attempt_time DESC LIMIT 1",
        (user_id,),
        fetch=True
    )

    if last_fail:
        last_attempt_time = datetime.datetime.strptime(last_fail[0][0], "%Y-%m-%d %H:%M:%S")
        now = datetime.datetime.now()
        diff_minutes = (now - last_attempt_time).total_seconds() / 60

        fail_count = database.execute_query(
            "SELECT COUNT(*) FROM login_attempts WHERE id_user=? AND successful=0",
            (user_id,),
            fetch=True
        )[0][0]

        if fail_count >= 3 and diff_minutes < 10:
            raise HTTPException(status_code=403, detail="Usuário temporariamente bloqueado após múltiplas falhas.")

    now = now_str()

    if data.password != correct_password:
        database.execute_query(
            "INSERT INTO login_attempts (id_user, attempt_time, successful) VALUES (?, ?, ?)",
            (user_id, now, 0)
        )
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

    database.execute_query("DELETE FROM login_attempts WHERE id_user=?", (user_id,))
    database.execute_query(
        "INSERT INTO login_attempts (id_user, attempt_time, successful) VALUES (?, ?, ?)",
        (user_id, now, 1)
    )

    token_encoded = make_token(email, doc_number)
    database.execute_query("UPDATE users SET loggedin=1, updated_at=? WHERE id=?", (now, user_id))

    existing = database.execute_query(
        "SELECT id FROM tokens WHERE id_user=? AND token=?",
        (user_id, token_encoded),
        fetch=True
    )
    if not existing:
        database.execute_query(
            "INSERT INTO tokens (id_user, token, created_at) VALUES (?, ?, ?)",
            (user_id, token_encoded, now)
        )

    return {"token": token_encoded}


@app.post("/api/v1/auth/recovery/request")
def request_recovery(data: RecoverRequest, request: Request):
    user = database.execute_query(
        "SELECT id FROM users WHERE email=? AND doc_number=?",
        (data.email, data.document),
        fetch=True
    )
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    code = generate_code()
    redis_client.setex(f"recovery:{data.email}", 600, code)

    send_verification_email(data.email, code)
    return {"message": "Código de verificação enviado para o e-mail."}


@app.post("/api/v1/auth/recuperar-senha")
def recuperar_senha(data: RecoverVerify):
    stored_code = redis_client.get(f"recovery:{data.email}")
    if not stored_code:
        raise HTTPException(status_code=400, detail="Código expirado ou inexistente")

    if stored_code.decode() != data.code:
        raise HTTPException(status_code=401, detail="Código de verificação incorreto")

    user = database.execute_query(
        "SELECT id, email, doc_number FROM users WHERE email=? AND doc_number=?",
        (data.email, data.document),
        fetch=True
    )
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user_id = user[0][0]
    now = now_str()
    database.execute_query(
        "UPDATE users SET password=?, updated_at=? WHERE id=?",
        (data.new_password, now, user_id)
    )

    redis_client.delete(f"recovery:{data.email}")

    token_encoded = make_token(data.email, data.document)
    database.execute_query(
        "INSERT INTO tokens (id_user, token, created_at) VALUES (?, ?, ?)",
        (user_id, token_encoded, now)
    )
    return {"message": "Senha redefinida com sucesso", "token": token_encoded}


@app.post("/api/v1/auth/logout")
def logout(authorization: str | None = Header(default=None, alias="Authorization")):
    token = extract_token_from_header(authorization)
    if not token:
        raise HTTPException(status_code=400, detail="Token não fornecido")

    token_row = database.execute_query("SELECT id, id_user FROM tokens WHERE token=?", (token,), fetch=True)
    if not token_row:
        raise HTTPException(status_code=400, detail="Token inválido")

    token_id, user_id = token_row[0][0], token_row[0][1]
    database.execute_query("DELETE FROM tokens WHERE id=?", (token_id,))
    now = now_str()
    database.execute_query("UPDATE users SET loggedin=0, updated_at=? WHERE id=?", (now, user_id))

    return {"message": "Logout realizado com sucesso"}


@app.get("/api/v1/auth/me")
def me(request: Request, authorization: str | None = Header(default=None, alias="Authorization")):
    token = extract_token_from_header(authorization)
    if not token:
        raise HTTPException(status_code=400, detail="Token não fornecido")

    check_throttling(token)

    token_row = database.execute_query(
        "SELECT id_user FROM tokens WHERE token=?", (token,), fetch=True
    )
    if not token_row:
        raise HTTPException(status_code=400, detail="Token inválido")

    user_id = token_row[0][0]
    user_row = database.execute_query(
        "SELECT id, email, doc_number, password, username, full_name, loggedin, created_at, updated_at FROM users WHERE id=?",
        (user_id,),
        fetch=True
    )
    if not user_row:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    uid, email, doc_number, password, username, full_name, loggedin, created_at, updated_at = user_row[0]
    return {
        "id": uid,
        "email": email,
        "doc_number": doc_number,
        "password": password,
        "username": username,
        "full_name": full_name,
        "loggedin": bool(loggedin),
        "created_at": created_at,
        "updated_at": updated_at
    }


@app.get("/api/v1/test/ratelimit")
def test_rate_limit():
    return {"message": "Requisição aceita"}
