import smtplib
from email.mime.text import MIMEText

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "brendabarbosaand@gmail.com"
SENDER_PASSWORD = "nao vou colocar minha senha aqui"

def send_verification_email(receiver_email, code):
    subject = "Recuperação de Senha - [NÃO RESPONDA!]"
    body = f"""
    Olá!

    Você solicitou a recuperação de senha.
    Seu código de verificação é: {code}

    O código expira em 10 minutos.
    Caso não tenha solicitado, ignore este e-mail.
    """

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print(f"[E-MAIL] Código enviado para {receiver_email}")
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")
