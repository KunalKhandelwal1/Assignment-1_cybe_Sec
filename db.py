import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "classmates.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    is_new = not os.path.exists(DB_PATH)
    conn = get_db()
    cursor = conn.cursor()

    if is_new:
        cursor.execute("""
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                display_name TEXT NOT NULL,
                message_ciphertext TEXT,
                message_iv TEXT
            );
        """)
    else:
        cursor.execute("PRAGMA table_info(accounts)")
        columns = [row["name"] for row in cursor.fetchall()]

        if "message_ciphertext" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_ciphertext TEXT")

        if "message_iv" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_iv TEXT")

        if "message_encrypted_key" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_encrypted_key TEXT")

        if "message_filename" not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN message_filename TEXT")

    seed_accounts = [
        ("arjun", "Football123", "Arjun"),
        ("meera", "SummerFun2024", "Meera"),
        ("kabir", "ChessMaster9", "Kabir"),
        ("zara", "RainbowUnicorn", "Zara"),
        ("vedant", "12345678", "Vedant")
    ]

    upsert_sql = """
        INSERT INTO accounts (username, password, display_name, message_ciphertext, message_iv)
        VALUES (?, ?, ?, NULL, NULL)
        ON CONFLICT(username) DO UPDATE SET
            password = excluded.password,
            display_name = excluded.display_name,
            message_ciphertext = COALESCE(accounts.message_ciphertext, excluded.message_ciphertext),
            message_iv = COALESCE(accounts.message_iv, excluded.message_iv)
    """

    for username, password, display_name in seed_accounts:
        cursor.execute(upsert_sql, (username, password, display_name))

    conn.commit()
    conn.close()
    print("Set up classmates.db with the expected sample accounts.")

if __name__ == "__main__":
    init_db()
