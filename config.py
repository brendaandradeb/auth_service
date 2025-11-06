from cryptography.fernet import Fernet

SECRET_KEY = Fernet.generate_key()
fernet = Fernet(SECRET_KEY)
