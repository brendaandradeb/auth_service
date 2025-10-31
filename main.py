from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import base64
import datetime
import database
import redis

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

class RecoverData(BaseModel):
    document: str
    email: str
    new_password: str

def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def make_token(email: str, doc_number: str) -> str:
    raw = f"{email}:{doc_number}"
    return base64.b64encode(raw.encode()).decode()

def extract_token_from_header(auth_header: str | None) -> str | None:

    if not auth_header:
        return None
    auth_header = auth_header.strip()
    if auth_header.startswith("SDWork "):
        return auth_header[len("SDWork "):].strip()
    return auth_header

def check_rate_limit(user_id: int, limit: int = 5, window_seconds: int = 50):
    key = f"rate_limit_{user_id}"
    current = redis_client.get(key)
    if current
@app.post("/api/v1/auth/signup")
def signup(data: SignupData):
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

    ten_minutes_ago = (datetime.datetime.now() - datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    fail_count = database.execute_query(
        "SELECT COUNT(*) FROM login_attempts WHERE id_user=? AND successful=0 AND attempt_time>=?",
        (user_id, ten_minutes_ago),
        fetch=True
    )[0][0]

    if fail_count >= 3:
        raise HTTPException(status_code=403, detail="Usuário temporariamente bloqueado. Tente novamente mais tarde.")

    now = now_str()

    if data.password != correct_password:
        database.execute_query(
            "INSERT INTO login_attempts (id_user, attempt_time, successful) VALUES (?, ?, ?)",
            (user_id, now, 0)
        )
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

    database.execute_query(
        "INSERT INTO login_attempts (id_user, attempt_time, successful) VALUES (?, ?, ?)",
        (user_id, now, 1)
    )

    token_encoded = make_token(email, doc_number)
    database.execute_query("UPDATE users SET loggedin=1, updated_at=? WHERE id=?", (now, user_id))

    existing = database.execute_query("SELECT id FROM tokens WHERE id_user=? AND token=?", (user_id, token_encoded), fetch=True)
    if not existing:
        database.execute_query("INSERT INTO tokens (id_user, token, created_at) VALUES (?, ?, ?)", (user_id, token_encoded, now))

    return {"token": token_encoded}


@app.post("/api/v1/auth/recuperar-senha")
def recuperar_senha(data: RecoverData):
    user = database.execute_query(
        "SELECT id, email, doc_number FROM users WHERE email=? AND doc_number=?",
        (data.email, data.document),
        fetch=True
    )
    if not user:
        raise HTTPException(status_code=404, detail="Documento e e-mail não encontrados ou não correspondem")

    user_id, email, doc_number = user[0][0], user[0][1], user[0][2]
    now = now_str()

    database.execute_query("UPDATE users SET password=?, updated_at=? WHERE id=?", (data.new_password, now, user_id))

    token_encoded = make_token(email, doc_number)

    database.execute_query("INSERT INTO tokens (id_user, token, created_at) VALUES (?, ?, ?)", (user_id, token_encoded, now))

    return {"token": token_encoded}

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
def me(authorization: str | None = Header(default=None, alias="Authorization")):
    token = extract_token_from_header(authorization)
    if not token:
        raise HTTPException(status_code=400, detail="Token não fornecido")

    token_row = database.execute_query("SELECT id_user FROM tokens WHERE token=?", (token,), fetch=True)
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
