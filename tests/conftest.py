"""
Shared fixtures and utilities for SecurePath Organizer test suite.

This module provides common pytest fixtures and helper functions used across
all test files to eliminate code duplication.
"""
import sys
import tempfile
from pathlib import Path
import pytest

# Add src folder to PYTHONPATH to allow imports in all test files
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def workspace():
    """
    Builds a temporary directory as a safe workspace.
    
    Yields:
        Path: Temporary directory path that is cleaned up after the test
    """
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)


def create_file(path: Path, content: bytes = b'text'):
    """
    Utility to create files with raw binary/text content.
    
    Args:
        path: Path where the file should be created
        content: Binary content to write to the file (default: b'text')
    """
    with open(path, 'wb') as f:
        f.write(content)
