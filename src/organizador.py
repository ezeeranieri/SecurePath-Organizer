import os
import argparse
import logging
import shutil
import json
import urllib.request
from urllib.error import URLError
from pathlib import Path
from datetime import datetime
import concurrent.futures
import threading

WEBHOOK_URL = "" 

def setup_logger():
    logger = logging.getLogger('organizer')
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

EXTENSION_MAPPING = {
    '.jpg': 'Images', '.jpeg': 'Images', '.png': 'Images', '.gif': 'Images', '.svg': 'Images',
    '.pdf': 'Documents', '.docx': 'Documents', '.doc': 'Documents', '.txt': 'Documents',
    '.xlsx': 'Documents', '.csv': 'Documents', '.pptx': 'Documents',
    '.zip': 'Compressed', '.rar': 'Compressed', '.tar': 'Compressed', '.gz': 'Compressed',
    '.mp4': 'Videos', '.mkv': 'Videos', '.mp3': 'Audio', '.wav': 'Audio'
}

SUSPICIOUS_EXTENSIONS = {'.exe', '.bat', '.sh', '.vbs', '.cmd', '.msi', '.ps1'}

journal_lock = threading.Lock()

# ==========================================
# ZERO-TRUST MANAGEMENT AND ALERTS
# ==========================================
def send_alert(filename: str, source_path: Path, threat_type: str = "General Threat"):
    if not WEBHOOK_URL: return
    try:
        data = {
            "content": f"⚠️ **Zero-Trust Alert:**\n**Threat:** `{threat_type}`\n**File:** `{filename}`\n**Path:** `{source_path}`\nSent to quarantine."
        }
        req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req)
        logger.info("Zero-Trust alert broadcasted.")
    except Exception as e:
        logger.error(f"Failed broadcasting webhook alert: {e}")

def get_threat_type(filepath: Path) -> str:
    """Zero Trust model validation. Returns descriptive risk string or None if safe."""
    ext = filepath.suffix.lower()
    
    # 1. Computational Biometric Analysis (Magic Bytes)
    try:
        with open(filepath, 'rb') as f:
            header = f.read(8)
            
            # Check executable MZ signature
            if header.startswith(b'MZ'):
                if ext not in SUSPICIOUS_EXTENSIONS:
                    return "Identity Spoofing (Executable disguised with safe extension)"
                return "Known Executable (MZ Signature)"
                
            # Check PDF
            if ext == '.pdf' and not header.startswith(b'%PDF-'):
                return "Identity Spoofing (Extension claims PDF but bytes do not match)"
                
            # Check JPEG
            if ext in ('.jpeg', '.jpg') and not header.startswith(b'\xff\xd8\xff'):
                return "Identity Spoofing (Extension claims JPEG but bytes do not match)"
                
            # Check ZIP/Docx formats
            if ext in ('.zip', '.docx', '.xlsx', '.pptx') and not header.startswith(b'PK\x03\x04'):
                return "Identity Spoofing (Extension claims ZIP/Office but bytes do not match)"
                
            # Check PNG
            if ext == '.png' and not header.startswith(b'\x89PNG'):
                return "Identity Spoofing (Extension claims PNG but bytes do not match)"
                
    except Exception as e:
        logger.warning(f"Failed binary read on {filepath.name}: {e}. Evaluating via secondary rules...")

    # 2. Raw Extension Analysis
    if ext in SUSPICIOUS_EXTENSIONS:
        return "Natively Dangerous Extension"
    
    # Check double extension attack
    if len(filepath.suffixes) > 1 and filepath.suffixes[-2:] != ['.tar', '.gz']:
        return "Double Extension Attack Detected"
        
    return None

# ==========================================
# ATOMIC TRANSACTIONAL LOGGING
# ==========================================
def _commit_transaction(source_path: Path, transaction: dict):
    """Atomically appends a successful file transfer to the local database."""
    history_file = source_path / "transfer_history.json"
    temp_file = source_path / "transfer_history.tmp.json"
    
    with journal_lock:
        existing = []
        if history_file.exists():
            try:
                with open(history_file, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
            except Exception as e:
                logger.error(f"Previous transaction log logic failed/corrupted. Starting fresh...: {e}")
                
        existing.append(transaction)
        
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(existing, f, indent=4, ensure_ascii=False)
            os.replace(temp_file, history_file)
            logger.info(f"💾 Atomic Journal Commit: {transaction['filename']} logged safely.")
        except Exception as e:
            logger.error(f"Critical I/O error saving atomic journal: {e}")

# ==========================================
# CORE BATCH ENGINE LOGIC
# ==========================================
def _process_file(item: Path, source_path: Path, dry_run: bool):
    # App metadata exclusion
    if item.is_dir() or item.name in ("organizer.log", "organizador.py", "rollback.py", "transfer_history.json", "transfer_history.tmp.json", "transfer_history.bak.json"):
        return None

    threat_type = get_threat_type(item)
    
    if threat_type:
        target_folder = 'QUARANTINE'
        logger.warning(f"Threat Detected & Isolated!: {item.name} -> {threat_type}")
        if not dry_run:
            send_alert(item.name, source_path, threat_type)
    else:
        target_folder = EXTENSION_MAPPING.get(item.suffix.lower(), 'Others')

    target_dir = source_path / target_folder
    target_file = target_dir / item.name

    if target_file.exists():
        logger.info(f"Skipping overwrite: '{item.name}' already exists in target destination.")
        return None

    if dry_run:
        logger.info(f"[DRY RUN] Planned Move: {item.name} -> {target_folder}/")
        return None
    else:
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(item), str(target_file))
            
            transaction = {
                "filename": item.name,
                "original_path": str(item),
                "new_path": str(target_file),
                "timestamp": datetime.now().isoformat()
            }
            
            _commit_transaction(source_path, transaction)
            logger.info(f"Moving: {item.name} -> {target_folder}/")
            
        except Exception as e:
            logger.error(f"Halt on file '{item.name}': {e}")
            return None

def organize_directory(source_dir_path: str, dry_run: bool = False):
    source_path = Path(source_dir_path)
    
    if not source_path.exists() or not source_path.is_dir():
        logger.error(f"Path '{source_path}' does not exist or is inaccessible.")
        return

    mode_text = "[DRY-RUN] " if dry_run else ""
    logger.info(f"=== Initiating Cybersecure Engine {mode_text}on {source_path} ===")

    # Multithreading concurrency pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_process_file, item, source_path, dry_run) for item in source_path.iterdir()]
        concurrent.futures.wait(futures)

    logger.info(f"=== Operation {mode_text}Completed Successfully ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Trust Organizer Architecture & Thread-safe Journaling.")
    parser.add_argument("--path", type=str, required=True, help="Target directory path.")
    parser.add_argument("--dry-run", action="store_true", help="Dry run emitting logs without I/O ops.")
    args = parser.parse_args()
    organize_directory(args.path, dry_run=args.dry_run)
