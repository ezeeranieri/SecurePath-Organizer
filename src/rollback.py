import argparse
import logging
import shutil
import sqlite3
from pathlib import Path
import os

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def rollback_directory(target_dir_path: str):
    """
    Rollback procedure: Uses SQLite transfer_history.db to revert only 
    approved movements without damaging the rest of the user's organic filesystem environment.
    """
    base_path = Path(target_dir_path)
    db_path = base_path / "transfer_history.db"
    
    if not db_path.exists():
        logger.error(f"Application state database missing ({db_path.name}). Safe rollback is impossible.")
        return

    logger.info(f"--- Rolling back changes on {base_path} ---")

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Standard SQLite LIFO fetch
        cursor.execute("SELECT id, filename, original_path, new_path FROM transfers ORDER BY id DESC")
        transactions = cursor.fetchall()
        
        if not transactions:
            logger.warning("Relocation history has no recorded blocks.")
            return

        successful_rollbacks = 0
        
        for tx_id, filename, original_path_str, new_path_str in transactions:
            original = Path(original_path_str)
            current = Path(new_path_str)
            
            if not current.exists():
                logger.warning(f"Temporal desynchronization: {current.name} is no longer found in {current.parent}. Skipping.")
                continue

            if original.exists():
                logger.warning(f"Overwrite Risk: A new file already exists at {original}. Skipping rollback for this node.")
                continue

            # Execute OS reversion
            try:
                # Reactivate permissions if it was forced to basic read-only
                if "QUARANTINE" in current.parts:
                    os.chmod(str(current), 0o666)  # Give write logic to move back securely
            except Exception:
                pass

            shutil.move(str(current), str(original))
            logger.info(f"Rolling back changes: {current.name} -> {original.parent}/")
            
            # Strip it from DB dynamically to persist partial rollbacks securely
            conn.execute("DELETE FROM transfers WHERE id = ?", (tx_id,))
            conn.commit()
            
            successful_rollbacks += 1
                
    except Exception as e:
        logger.critical(f"Integrity check failed. SQLite database is corrupted or locked: {e}")
        return
    finally:
        if conn:
            conn.close()

    # Garbage Collect: Sweep directory bridge structures if they have been left empty
    try:
        checked_folders = set()
        for _, _, _, new_path_str in transactions:
            folder = Path(new_path_str).parent
            if folder not in checked_folders and folder.exists() and folder.is_dir():
                checked_folders.add(folder)
                try:
                    folder.rmdir() # Throws OSError if NOT empty
                    logger.info(f"♻️ Empty bridge folder destroyed by GC: {folder.name}/")
                except OSError:
                    pass 
    except Exception as e:
        logger.warning(f"Garbage collection encountered minor issues: {e}")

    # Post-mortem DB treatment
    if successful_rollbacks == len(transactions):
        try:
            backup_db = base_path / "transfer_history.bak.db"
            if backup_db.exists():
                backup_db.unlink()
            db_path.rename(backup_db)
            logger.info(f"✅ History cleanly rotated to '.bak.db'. 100% of the {len(transactions)} nodes safely reverted. Atomic Rollback Successful.")
        except Exception as e:
            logger.warning(f"Could not backup historical state database: {e}")
    else:
        logger.warning(f"⚠️ Alert: Partial rollback completed. Only {successful_rollbacks} of {len(transactions)} nodes were safely sanitized.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Revert file movements to a previous SQLite database snapshot.")
    parser.add_argument("--path", type=str, required=True, help="Root path where transfer_history.db lies.")
    
    args = parser.parse_args()
    rollback_directory(args.path)
