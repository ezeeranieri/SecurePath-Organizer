import sys
import tempfile
import os
import stat
from pathlib import Path
import pytest

# Add src folder to PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import organizador
import rollback

@pytest.fixture
def workspace():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)

def create_file(path: Path, content: bytes = b'text'):
    with open(path, 'wb') as f:
        f.write(content)

def get_mode(path: Path):
    return stat.S_IMODE(os.lstat(path).st_mode)

def test_quarantine_permissions_are_restricted(workspace):
    # Create a suspicious file
    malware_file = workspace / "test.exe"
    create_file(malware_file, b"MZ...") # Fake executable
    
    # Run organizer
    organizador.organize_directory(str(workspace), dry_run=False)
    
    quarantined_file = workspace / "QUARANTINE" / "test.exe"
    assert quarantined_file.exists()
    
    # Check permissions
    # Note: On Windows, chmod only affects the read-only flag.
    # On POSIX, we expect 0o400.
    mode = get_mode(quarantined_file)
    
    if os.name == 'nt':
        # On Windows, 0o400 makes it read-only.
        # We check if it's read-only.
        assert not (os.access(quarantined_file, os.W_OK))
    else:
        assert mode == 0o400

def test_rollback_quarantine_permissions(workspace):
    # Create a suspicious file
    malware_file = workspace / "malware.exe"
    create_file(malware_file, b"MZ...")
    
    # Organize (quarantine)
    organizador.organize_directory(str(workspace), dry_run=False)
    
    quarantined_file = workspace / "QUARANTINE" / "malware.exe"
    assert quarantined_file.exists()
    
    # Rollback
    rollback.rollback_directory(str(workspace))
    
    # Should be back to original location
    assert malware_file.exists()
    
    # Check permissions
    if os.name == 'nt':
        # Should NOT be read-only anymore (since we did 0o600)
        assert os.access(malware_file, os.W_OK)
    else:
        # On POSIX, should be 0o600
        assert get_mode(malware_file) == 0o600
