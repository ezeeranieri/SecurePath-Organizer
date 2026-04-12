import os
import argparse
import logging
import shutil
import json
import urllib.request
import sqlite3
from pathlib import Path
from datetime import datetime
import concurrent.futures
import threading

# ==========================================
# CENTRALIZED CONFIGURATION
# ==========================================
CONFIG = {
    "WEBHOOK_URL": None,
    "EXTENSION_MAPPING": {
        '.jpg': 'Images', '.jpeg': 'Images', '.png': 'Images', '.gif': 'Images', '.svg': 'Images',
        '.pdf': 'Documents', '.docx': 'Documents', '.doc': 'Documents', '.txt': 'Documents',
        '.xlsx': 'Documents', '.csv': 'Documents', '.pptx': 'Documents',
        '.zip': 'Compressed', '.rar': 'Compressed', '.tar': 'Compressed', '.gz': 'Compressed',
        '.mp4': 'Videos', '.mkv': 'Videos', '.mp3': 'Audio', '.wav': 'Audio'
    },
    "SUSPICIOUS_EXTENSIONS": {'.exe', '.bat', '.sh', '.vbs', '.cmd', '.msi', '.ps1'}
}

# ==========================================
# FORENSIC LOGGING
# ==========================================
def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler("organizer.log", encoding='utf-8')
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

logger = setup_logger()

# Global Locks
db_lock = threading.Lock()
fs_lock = threading.Lock()

# ==========================================
# ASYNC WEBHOOK ALERT
# ==========================================
def _dispatch_alert(filename: str, threat_type: str):
    if not CONFIG["WEBHOOK_URL"]: 
        return
    try:
        data = {
            "content": f"⚠️ **Security Alert:**\n**Threat:** `{threat_type}`\n**File:** `{filename}`\nSent to quarantine."
        }
        req = urllib.request.Request(CONFIG["WEBHOOK_URL"], data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req)
        logger.info("Security alert broadcasted asynchronously.")
    except Exception as e:
        logger.error(f"Failed broadcasting webhook alert: {e}")

def send_alert_async(filename: str, threat_type: str):
    """Fires Webhook in background bridging wait times to zero."""
    threading.Thread(target=_dispatch_alert, args=(filename, threat_type), daemon=True).start()

# ==========================================
# SQLITE TRANSACTION SYSTEM
# ==========================================
def log_transaction(conn: sqlite3.Connection, filename: str, original_path: str, new_path: str):
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

# ==========================================
# SOLID RESPONSIBILITY ARCHITECTURE (SRP)
# ==========================================
def detect_threat(filepath: Path) -> str:
    """Security Layer: Biometrics and Extension logic."""
    ext = filepath.suffix.lower()
    
    # 1. Magic Bytes Validation
    try:
        with open(filepath, 'rb') as f:
            header = f.read(8)
            if header.startswith(b'MZ'):
                if ext not in CONFIG["SUSPICIOUS_EXTENSIONS"]:
                    return "Identity Spoofing (Executable disguised with safe extension)"
                
            elif ext == '.pdf' and not header.startswith(b'%PDF-'):
                return "Identity Spoofing (Extension claims PDF but bytes do not match)"
            elif ext in ('.jpeg', '.jpg') and not header.startswith(b'\xff\xd8\xff'):
                return "Identity Spoofing (Extension claims JPEG but bytes do not match)"
            elif ext in ('.zip', '.docx', '.xlsx', '.pptx') and not header.startswith(b'PK\x03\x04'):
                return "Identity Spoofing (Extension claims ZIP/Office but bytes do not match)"
            elif ext == '.png' and not header.startswith(b'\x89PNG'):
                return "Identity Spoofing (Extension claims PNG but bytes do not match)"
    except Exception as e:
        logger.warning(f"Failed binary forensic read on {filepath.name}: {e}")

    # 2. Strict Extension Validation
    if ext in CONFIG["SUSPICIOUS_EXTENSIONS"]:
        if len(filepath.suffixes) > 1:
            return "Double Extension Spoofing"
        return "Natively Dangerous Extension"
    
    return None

def decide_target(item: Path, threat_type: str) -> str:
    """Sorting Layer: Derives destination based on risk profile."""
    if threat_type:
        return 'QUARANTINE'
    return CONFIG["EXTENSION_MAPPING"].get(item.suffix.lower(), 'Others')

def execute_transfer(item: Path, source_path: Path, target_folder: str, threat_type: str, dry_run: bool, conn: sqlite3.Connection):
    """OS Execution Layer: Handles file I/O operations atomically."""
    target_dir = source_path / target_folder
    target_file = target_dir / item.name

    # Granular lock protecting ONLY destination assessment and creation
    with fs_lock:
        if target_file.exists():
            logger.warning(f"File transfer collision prevented. '{item.name}' already exists in destination.")
            return

        if dry_run:
            logger.info(f"[DRY RUN] Planned Move: {item.name} -> {target_folder}/")
            return
            
        target_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Preparing to transfer: {item.name} -> {target_folder}/")

    try:
        # Pre-move safety measures enforce secure state before attempting I/O transaction
        if target_folder == 'QUARANTINE':
            logger.warning(f"Threat Detected & Isolated!: {item.name} -> {threat_type}")
            os.chmod(str(item), 0o400)
            logger.warning(f"Permission stripped: {item.name} set to owner-read-only (0o400).")
            send_alert_async(item.name, threat_type)

        # File I/O happens fully parallel outside locks
        shutil.move(str(item), str(target_file))
        
        if target_folder != 'QUARANTINE':
            logger.info(f"Target Acquired & Moved: {item.name} -> {target_folder}/")
            
        if conn:
            log_transaction(conn, item.name, str(item), str(target_file))

    except Exception as e:
        logger.error(f"Halt on file '{item.name}': {e}")

# ==========================================
# MAIN BATCH ENGINE
# ==========================================
def _process_item_flow(item: Path, source_path: Path, dry_run: bool, conn: sqlite3.Connection):
    """Facade orchestrator handling the SRP pipeline."""
    current_script_name = Path(__file__).name
    if item.is_dir() or item.name in ("organizer.log", current_script_name, "rollback.py", "transfer_history.db"):
        return

    threat_type = detect_threat(item)
    target_folder = decide_target(item, threat_type)
    execute_transfer(item, source_path, target_folder, threat_type, dry_run, conn)

def organize_directory(source_dir_path: str, dry_run: bool = False):
    source_path = Path(source_dir_path).resolve()
    
    if not source_path.exists() or not source_path.is_dir():
        logger.error(f"Path '{source_path}' does not exist or is inaccessible.")
        return

    mode = "[DRY-RUN] " if dry_run else ""
    logger.info(f"=== Initiating Security-Aware File Organizer {mode}on {source_path} ===")

    conn = None
    if not dry_run:
        db_path = source_path / "transfer_history.db"
        # Enable multi-thread persistence via robust lock protections downstream
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
            logger.critical(f"Aborting execution. SQLite initialization failed: {e}")
            conn.close()
            return
            
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_process_item_flow, item, source_path, dry_run, conn) for item in source_path.iterdir()]
            concurrent.futures.wait(futures)
    finally:
        if conn:
            conn.close()

    logger.info(f"=== Operation {mode}Completed Successfully ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security-Aware File Organizer using SQLite.")
    parser.add_argument("--path", type=str, required=True, help="Target directory path.")
    parser.add_argument("--dry-run", action="store_true", help="Dry run emitting logs without OS I/O.")
    args = parser.parse_args()
    organize_directory(args.path, dry_run=args.dry_run)
