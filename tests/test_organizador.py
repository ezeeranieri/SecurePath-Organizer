import sys
import tempfile
import os
import json
from pathlib import Path
import pytest
import shutil

# Add src folder to PYTHONPATH to allow imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import organizador
import rollback

@pytest.fixture
def workspace():
    """Builds a temporary directory as a safe workspace."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)

def create_file(path: Path, content: bytes = b'text'):
    """Utility to create files with raw binary/text content."""
    with open(path, 'wb') as f:
        f.write(content)

def test_full_system_lifecycle_with_magic_bytes(workspace):
    """
    Simulates a full run of the Zero-Trust Organizer and an Atomic Rollback.
    """
    # 1. Provide Context
    safe_file = workspace / "photo.jpg"
    fake_ext_file = workspace / "invoice.pdf"
    malware_file = workspace / "script.bat"
    
    # Safe file is a real JPEG (magic bytes match)
    create_file(safe_file, b'\xff\xd8\xff\xe0\x00\x10\x4A\x46')
    
    # Fake PDF (has a PDF extension but starts with executable MZ bytes)
    create_file(fake_ext_file, b'MZ\x00\x00malicious_content')
    
    # Native Malware file (natively suspicious extension)
    create_file(malware_file, b'echo "Destroy disk"')

    assert safe_file.exists()
    assert fake_ext_file.exists()
    assert malware_file.exists()
    
    # 2. Execute the Organizer
    organizador.organize_directory(str(workspace), dry_run=False)
    
    # 3. Verify files went to targeted destinations
    # Safe JPGE went to Images folder
    assert (workspace / "Images" / "photo.jpg").exists()
    assert not safe_file.exists()
    
    # Fake PDF (Identity Spoofing) went to QUARANTINE
    assert (workspace / "QUARANTINE" / "invoice.pdf").exists()
    assert not fake_ext_file.exists()
    
    # Native Malware (.bat) went to QUARANTINE
    assert (workspace / "QUARANTINE" / "script.bat").exists()
    assert not malware_file.exists()
    
    # Verify transaction JSON exists
    history_file = workspace / "transfer_history.json"
    assert history_file.exists()
    
    with open(history_file, 'r', encoding='utf-8') as f:
        transactions = json.load(f)
        assert len(transactions) == 3

    # 4. Execute standard Atomic Rollback
    rollback.rollback_directory(str(workspace))
    
    # 5. Verify the files are exactly where they started 
    assert safe_file.exists()
    assert fake_ext_file.exists()
    assert malware_file.exists()
    
    # And their temporal sub-directories were cleared out by Garbage Collector
    assert not (workspace / "Images").exists()
    assert not (workspace / "QUARANTINE").exists()
    
    # Verify the history file was migrated into a .bak
    assert not history_file.exists()
    assert (workspace / "transfer_history.bak.json").exists()
