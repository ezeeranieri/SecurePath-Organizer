"""
File transfer operations and alerting module.
"""
import os
import shutil
import json
import urllib.request
import threading
import sqlite3
from pathlib import Path
from datetime import datetime
from config import CONFIG, logger, fs_lock


# ==========================================
# ASYNC WEBHOOK ALERT
# ==========================================
def _dispatch_alert(filename: str, threat_type: str):
    """Internal function to dispatch webhook alert synchronously."""
    if not CONFIG["WEBHOOK_URL"]: 
        return
    try:
        data = {
            "content": f"⚠️ **Security Alert:**\n**Threat:** `{threat_type}`\n**File:** `{filename}`\nSent to quarantine."
        }
        req = urllib.request.Request(
            CONFIG["WEBHOOK_URL"], 
            data=json.dumps(data).encode('utf-8'), 
            headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
        )
        urllib.request.urlopen(req)
        logger.info("Security alert broadcasted asynchronously.")
    except Exception as e:
        logger.error(f"Failed broadcasting webhook alert: {e}")


def send_alert_async(filename: str, threat_type: str):
    """Fires Webhook in background bridging wait times to zero."""
    threading.Thread(target=_dispatch_alert, args=(filename, threat_type), daemon=True).start()


# ==========================================
# FILE TRANSFER OPERATIONS
# ==========================================
def execute_transfer(
    item: Path, 
    source_path: Path, 
    target_folder: str, 
    threat_type: str, 
    dry_run: bool, 
    conn: sqlite3.Connection,
    log_transaction_func=None
):
    """
    OS Execution Layer: Handles file I/O operations atomically.
    
    Args:
        item: Path to the file being transferred
        source_path: Root directory being organized
        target_folder: Destination folder name
        threat_type: Threat classification (if any)
        dry_run: If True, only log without performing I/O
        conn: SQLite connection for transaction logging
        log_transaction_func: Callback function for logging transactions
    """
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
            
        if conn and log_transaction_func:
            log_transaction_func(conn, item.name, str(item), str(target_file))

    except Exception as e:
        logger.error(f"Halt on file '{item.name}': {e}")
