import sys
import tempfile
import os
import sqlite3
from pathlib import Path
import pytest
import shutil

# Add src folder to PYTHONPATH to allow imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import organizador
import rollback
from config import CONFIG

@pytest.fixture
def workspace():
    """Builds a temporary directory as a safe workspace."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)

def create_file(path: Path, content: bytes = b'text'):
    """Utility to create files with raw binary/text content."""
    with open(path, 'wb') as f:
        f.write(content)

def test_full_system_lifecycle_with_sqlite_transactional_engine(workspace):
    """
    Simulates a full run of the Security-Aware File Organizer and an Atomic Rollback 
    leveraging the SQLite DB footprint instead of JSON.
    """
    # 1. Provide Context
    safe_file = workspace / "photo.jpg"
    fake_ext_file = workspace / "invoice.pdf"
    malware_file = workspace / "script.bat"
    healthy_double_ext = workspace / "backup.v1.zip"
    
    # Safe file is a real JPEG (magic bytes match)
    create_file(safe_file, b'\xff\xd8\xff\xe0\x00\x10\x4A\x46')
    
    # Fake PDF (has a PDF extension but starts with executable MZ bytes)
    create_file(fake_ext_file, b'MZ\x00\x00malicious_content')
    
    # Native Malware file (natively suspicious extension)
    create_file(malware_file, b'echo "Destroy disk"')
    
    # Legal double extension (Should be organized nicely, not quarantined)
    create_file(healthy_double_ext, b'PK\x03\x04\x00\x00\x00')

    assert safe_file.exists()
    assert fake_ext_file.exists()
    assert malware_file.exists()
    assert healthy_double_ext.exists()
    
    # 2. Execute the Organizer
    organizador.organize_directory(str(workspace), dry_run=False)
    
    # 3. Verify files went to targeted destinations
    # Safe JPGE went to Images folder
    assert (workspace / "Images" / "photo.jpg").exists()
    assert not safe_file.exists()
    
    # Healthy double-extension went to Compressed folder
    assert (workspace / "Compressed" / "backup.v1.zip").exists()
    assert not healthy_double_ext.exists()
    
    # Fake PDF (Identity Spoofing) went to QUARANTINE
    assert (workspace / "QUARANTINE" / "invoice.pdf").exists()
    assert not fake_ext_file.exists()
    
    # Native Malware (.bat) went to QUARANTINE
    assert (workspace / "QUARANTINE" / "script.bat").exists()
    assert not malware_file.exists()
    
    # Verify transaction SQLite DB exists
    db_path = workspace / "transfer_history.db"
    assert db_path.exists()
    
    # Execute forensic read over SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM transfers")
    count = cursor.fetchone()[0]
    conn.close()
    
    # 4 files were processed and safely registered in the database
    assert count == 4

    # 4. Execute standard Atomic Rollback
    rollback.rollback_directory(str(workspace))
    
    # 5. Verify the files are exactly where they started 
    assert safe_file.exists()
    assert fake_ext_file.exists()
    assert malware_file.exists()
    assert healthy_double_ext.exists()
    
    # And their temporal sub-directories were cleared out by Garbage Collector
    assert not (workspace / "Images").exists()
    assert not (workspace / "Compressed").exists()
    assert not (workspace / "QUARANTINE").exists()
    
    # Verify the database was migrated into a .bak
    assert not db_path.exists()
    assert (workspace / "transfer_history.bak.db").exists()
