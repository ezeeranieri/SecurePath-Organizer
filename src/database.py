"""
Database operations module for transaction logging.
"""
import sqlite3
from pathlib import Path
from datetime import datetime
from config import logger, db_lock


def log_transaction(conn: sqlite3.Connection, filename: str, original_path: str, new_path: str):
    """
    Log a file transfer transaction to the SQLite database.
    
    Args:
        conn: SQLite connection
        filename: Name of the file being transferred
        original_path: Source path of the file
        new_path: Destination path of the file
    """
    timestamp = datetime.now().isoformat()
    with db_lock:
        try:
            conn.execute(
                "INSERT INTO transfers (filename, original_path, new_path, timestamp) VALUES (?, ?, ?, ?)",
                (filename, original_path, new_path, timestamp)
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Integrity check failed. Database commit dropped for '{filename}': {e}")


def init_database(db_path: Path) -> sqlite3.Connection:
    """
    Initialize the SQLite database with the transfers table.
    
    Args:
        db_path: Path to the SQLite database file
        
    Returns:
        SQLite connection object
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_path TEXT NOT NULL,
                new_path TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
    except Exception as e:
        logger.critical(f"SQLite initialization failed: {e}")
        conn.close()
        raise
    return conn
