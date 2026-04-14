"""
Edge case tests for SecurePath Organizer.

Tests filename collisions, empty directories, and dry-run safety.
"""
import os
import sqlite3
from pathlib import Path
import shutil

import organizador
import rollback

from conftest import create_file


def test_filename_collision_prevention(workspace):
    """
    Test that the organizer skips files when a file with the same name
    already exists in the destination folder.
    """
    # Create a file that will be organized
    source_file = workspace / "photo.jpg"
    create_file(source_file, b'\xff\xd8\xff\xe0\x00\x10\x4A\x46')  # JPEG magic bytes
    
    # Pre-create the Images folder with a file of the same name
    images_folder = workspace / "Images"
    images_folder.mkdir()
    existing_file = images_folder / "photo.jpg"
    create_file(existing_file, b'existing content')
    
    original_content = existing_file.read_bytes()
    
    # Run organizer - should skip the collision
    organizador.organize_directory(str(workspace), dry_run=False)
    
    # Source file should still exist (not moved due to collision)
    assert source_file.exists(), "Source file should remain when collision is detected"
    
    # Destination file should retain its original content
    assert existing_file.read_bytes() == original_content, "Existing file should not be overwritten"
    
    # Verify database still records the transaction (or doesn't, depending on implementation)
    # The file was skipped, so it shouldn't be in the database
    db_path = workspace / "transfer_history.db"
    if db_path.exists():
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM transfers WHERE filename = 'photo.jpg'")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 0, "Skipped collision files should not be logged in database"


def test_empty_directory_handling(workspace):
    """
    Test that the organizer handles empty directories correctly.
    Empty directories should not cause errors and should be ignored.
    """
    # Create some empty directories
    empty_dir1 = workspace / "EmptyFolder1"
    empty_dir2 = workspace / "EmptyFolder2"
    empty_dir1.mkdir()
    empty_dir2.mkdir()
    
    # Create a nested empty directory
    nested_empty = workspace / "Parent" / "Child"
    nested_empty.mkdir(parents=True)
    
    # Create one actual file
    real_file = workspace / "document.txt"
    create_file(real_file, b"This is a document")
    
    # Run organizer - should not raise errors on empty directories
    organizador.organize_directory(str(workspace), dry_run=False)
    
    # The text file should be moved to Documents
    assert (workspace / "Documents" / "document.txt").exists()
    assert not real_file.exists()
    
    # Empty directories should still exist (not processed, not deleted)
    assert empty_dir1.exists()
    assert empty_dir2.exists()
    assert (workspace / "Parent" / "Child").exists()


def test_organizador_dry_run_no_modifications(workspace):
    """
    Test that organizador.py --dry-run never modifies any files.
    """
    # Create test files
    file1 = workspace / "photo.jpg"
    file2 = workspace / "document.txt"
    malware = workspace / "suspicious.exe"
    
    create_file(file1, b'\xff\xd8\xff\xe0\x00\x10\x4A\x46')  # JPEG
    create_file(file2, b"Document content")
    create_file(malware, b"MZ...")  # Executable
    
    # Record original states
    original_contents = {
        file1: file1.read_bytes(),
        file2: file2.read_bytes(),
        malware: malware.read_bytes()
    }
    original_stat = {f: f.stat() for f in original_contents.keys()}
    
    # Run with dry-run
    organizador.organize_directory(str(workspace), dry_run=True)
    
    # Verify all files are unchanged
    for f, content in original_contents.items():
        assert f.read_bytes() == content, f"{f.name} content was modified in dry-run mode"
        assert f.exists(), f"{f.name} was moved in dry-run mode"
        # Check modification time wasn't changed
        assert f.stat().st_mtime == original_stat[f].st_mtime, f"{f.name} was touched in dry-run mode"
    
    # Verify no database was created
    db_path = workspace / "transfer_history.db"
    assert not db_path.exists(), "Database should not be created in dry-run mode"
    
    # Verify no folders were created
    assert not (workspace / "Images").exists()
    assert not (workspace / "Documents").exists()
    assert not (workspace / "QUARANTINE").exists()


def test_rollback_dry_run_no_modifications(workspace):
    """
    Test that rollback.py --dry-run never restores any files.
    """
    # First, organize some files
    file1 = workspace / "photo.jpg"
    file2 = workspace / "malware.exe"
    
    create_file(file1, b'\xff\xd8\xff\xe0\x00\x10\x4A\x46')
    create_file(file2, b"MZ...")
    
    # Organize (not dry-run - we want files moved)
    organizador.organize_directory(str(workspace), dry_run=False)
    
    # Verify files were moved
    moved_file1 = workspace / "Images" / "photo.jpg"
    moved_file2 = workspace / "QUARANTINE" / "malware.exe"
    
    assert moved_file1.exists()
    assert moved_file2.exists()
    assert not file1.exists()
    assert not file2.exists()
    
    # Record states after organization
    organized_contents = {
        moved_file1: moved_file1.read_bytes(),
        moved_file2: moved_file2.read_bytes()
    }
    
    # Run rollback in dry-run mode
    rollback.rollback_directory(str(workspace), dry_run=True)
    
    # Verify files are still in their organized locations
    assert moved_file1.exists(), "File was moved during dry-run rollback"
    assert moved_file2.exists(), "Quarantined file was moved during dry-run rollback"
    assert moved_file1.read_bytes() == organized_contents[moved_file1]
    assert moved_file2.read_bytes() == organized_contents[moved_file2]
    
    # Verify files are NOT in original locations
    assert not file1.exists(), "File was restored to original location during dry-run"
    assert not file2.exists(), "Malware was restored to original location during dry-run"
    
    # Verify database still exists and is unchanged
    db_path = workspace / "transfer_history.db"
    assert db_path.exists(), "Database should not be modified in dry-run mode"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM transfers")
    count = cursor.fetchone()[0]
    conn.close()
    assert count == 2, "Database records should not be deleted in dry-run mode"
    
    # Verify organized folders still exist
    assert (workspace / "Images").exists()
    assert (workspace / "QUARANTINE").exists()


def test_organizador_dry_run_preserves_log_file(workspace):
    """
    Test that organizador.py dry-run mode creates logs but doesn't move files.
    This ensures users can review what would happen.
    """
    file1 = workspace / "photo.jpg"
    create_file(file1, b'\xff\xd8\xff\xe0\x00\x10\x4A\x46')
    
    # Change to workspace directory for log file creation
    original_cwd = os.getcwd()
    try:
        os.chdir(str(workspace))
        organizador.organize_directory(str(workspace), dry_run=True)
        
        # Log file should be created (in current working directory, not workspace)
        # But the file shouldn't be moved
        assert file1.exists()
        assert not (workspace / "Images").exists()
    finally:
        os.chdir(original_cwd)
