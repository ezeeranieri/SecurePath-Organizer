import argparse
import logging
import shutil
import json
from pathlib import Path
import os

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def rollback_directory(target_dir_path: str):
    """
    Enterprise Rollback: Uses transfer_history.json to revert only 
    approved movements without damaging the rest of the user's organic filesystem environment.
    """
    base_path = Path(target_dir_path)
    history_file = base_path / "transfer_history.json"
    
    if not history_file.exists():
        logging.error(f"Application state history missing ({history_file.name}). Safe rollback is impossible.")
        return

    logging.info(f"--- Rolling back changes on {base_path} ---")

    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            transactions = json.load(f)
    except Exception as e:
        logging.critical(f"Integrity check failed. JSON database is corrupted: {e}")
        return

    if not transactions:
        logging.warning("Relocation history has no recorded blocks.")
        return

    successful_rollbacks = 0
    # Iterate LIFO (Last In - First Out). Standard DB principle.
    for idx, tx in enumerate(reversed(transactions)):
        try:
            original = Path(tx["original_path"])
            current = Path(tx["new_path"])
            
            if not current.exists():
                logging.warning(f"Temporal desynchronization: {current.name} is no longer found in {current.parent}. Skipping.")
                continue

            if original.exists():
                logging.warning(f"Overwrite Risk: A new file already exists at {original}. Skipping rollback for this node.")
                continue

            shutil.move(str(current), str(original))
            logging.info(f"Rolling back changes: {current.name} -> {original.parent}/")
            successful_rollbacks += 1
            
        except Exception as e:
            logging.error(f"Blocking error restoring '{tx['filename']}': {e}")
            
    # Garbage Collect: Try to sweep directory bridge structures if they have been left empty
    checked_folders = set()
    for tx in transactions:
        folder = Path(tx["new_path"]).parent
        if folder not in checked_folders and folder.exists() and folder.is_dir():
            checked_folders.add(folder)
            try:
                # rmdir throws OSError if NOT empty, which is exactly the defensive behavior we want
                folder.rmdir()
                logging.info(f"♻️ Empty bridge folder destroyed by GC: {folder.name}/")
            except OSError:
                pass 

    # Post-mortem historical record treatment
    if successful_rollbacks == len(transactions):
        try:
            backup_file = base_path / "transfer_history.bak.json"
            if backup_file.exists():
                backup_file.unlink()
            history_file.rename(backup_file)
            logging.info(f"✅ History cleanly rotated to '.bak.json'. 100% of the {len(transactions)} nodes safely reverted. Atomic Rollback Successful.")
        except Exception as e:
            logging.warning(f"Could not backup historical state file: {e}")
    else:
        logging.warning(f"⚠️ Alert: Partial rollback completed. Only {successful_rollbacks} of {len(transactions)} nodes were safely sanitized.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transactional Script to revert system to a valid DB Snapshot.")
    parser.add_argument("--path", type=str, required=True, help="Root path where transfer_history.json lies.")
    
    args = parser.parse_args()
    rollback_directory(args.path)
