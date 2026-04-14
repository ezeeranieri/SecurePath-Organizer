"""
Security analysis module for threat detection and file classification.
"""
from pathlib import Path
from config import CONFIG, logger


def detect_threat(filepath: Path) -> str:
    """
    Security Layer: Biometrics and Extension logic.
    
    Analyzes file magic bytes to detect potential identity spoofing
    and identifies suspicious extensions.
    
    Args:
        filepath: Path to the file to analyze
        
    Returns:
        Threat type string if threat detected, None otherwise
    """
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
    """
    Sorting Layer: Derives destination based on risk profile.
    
    Args:
        item: Path to the file
        threat_type: Threat classification from detect_threat, or None
        
    Returns:
        Target folder name (e.g., 'Images', 'QUARANTINE', 'Others')
    """
    if threat_type:
        return 'QUARANTINE'
    return CONFIG["EXTENSION_MAPPING"].get(item.suffix.lower(), 'Others')
