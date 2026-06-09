import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "data" / "a3_threats.db"

def get_connection():
    return sqlite3.connect(DB_PATH)

def initialize():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        threat_type TEXT,

        severity TEXT,

        score INTEGER,

        name TEXT,

        details TEXT,

        flags TEXT
    )
    """)

    conn.commit()
    conn.close()