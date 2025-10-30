import sqlite3

conn = sqlite3.connect('auth.db', timeout=10, check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    doc_number TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    username TEXT NOT NULL,
    full_name TEXT NOT NULL,
    loggedin BOOLEAN DEFAULT 0,
    created_at TEXT,
    updated_at TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER,
    token TEXT,
    created_at TEXT
)
''')
cursor.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER NOT NULL,
    attempt_time TEXT NOT NULL,
    successful BOOLEAN NOT NULL
)
''')
conn.commit()
conn.close()

print("Banco de dados criado com sucesso!")