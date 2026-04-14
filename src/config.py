"""
Centralized configuration and logging for SecurePath Organizer.
"""
import logging
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
# GLOBAL LOCKS
# ==========================================
db_lock = threading.Lock()
fs_lock = threading.Lock()

# ==========================================
# FORENSIC LOGGING
# ==========================================
def setup_logger():
    """Configure and return the application logger."""
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
