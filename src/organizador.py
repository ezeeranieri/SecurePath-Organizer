"""
SecurePath Organizer - Main orchestration module.

This module serves as the entry point and orchestrator, delegating to:
- config: Configuration and logging
- security: Threat detection and classification
- database: SQLite transaction logging
- transfer: File operations and alerting
"""
import argparse
import sqlite3
from pathlib import Path
import concurrent.futures

from config import logger
from security import detect_threat, decide_target
from database import init_database, log_transaction
from transfer import execute_transfer

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
    execute_transfer(item, source_path, target_folder, threat_type, dry_run, conn, log_transaction)

def organize_directory(source_dir_path: str, dry_run: bool = False):
    """
    Main entry point for organizing a directory.
    
    Args:
        source_dir_path: Path to the directory to organize
        dry_run: If True, only simulate operations without moving files
    """
    source_path = Path(source_dir_path).resolve()
    
    if not source_path.exists() or not source_path.is_dir():
        logger.error(f"Path '{source_path}' does not exist or is inaccessible.")
        return

    mode = "[DRY-RUN] " if dry_run else ""
    logger.info(f"=== Initiating Security-Aware File Organizer {mode}on {source_path} ===")

    conn = None
    if not dry_run:
        db_path = source_path / "transfer_history.db"
        try:
            conn = init_database(db_path)
        except Exception:
            logger.critical("Aborting execution. Database initialization failed.")
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
