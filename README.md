# SecurePath Organizer

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=ezeeranieri_SecurePath-Organizer)](https://sonarcloud.io/summary/new_code?id=ezeeranieri_SecurePath-Organizer)

A concurrent file organizer built in Python, designed to categorize files while performing basic security checks. It relies on magic bytes validation to detect potentially masked extensions and uses an embedded SQLite database to track file operations, providing a reliable rollback mechanism.

## Core Features

- **Concurrent Processing**: Utilizes `ThreadPoolExecutor` to handle file I/O operations in parallel, improving performance on large directories.
- **Basic Threat Validation**: Analyzes files using magic bytes (e.g., verifying `MZ` headers) instead of exclusively trusting standard file extensions to prevent basic identity spoofing.
- **Transactional Rollback**: File movements are logged into a local SQLite database (`transfer_history.db`). A dedicated rollback script allows reverting operations sequentially (LIFO) if needed.
- **Quarantine & Permission Management**: Files classified as suspicious are moved to a dedicated `QUARANTINE` folder, and their read-only attribute is flagged (`chmod 0o444`) to prevent accidental modifications.

## Requirements

- Python 3.8+
- pytest

## Installation & Usage

**1. Clone the repository**
```bash
git clone https://github.com/ezeeranieri/SecurePath-Organizer.git
cd SecurePath-Organizer
```

**2. Dry-Run Execution**
Test the categorization logic and review logs without altering actual files on disk:
```bash
python src/organizador.py --path "C:\Path\To\Your\Downloads" --dry-run
```

**3. Run Organizer**
Execute the file organization process:
```bash
python src/organizador.py --path "C:\Path\To\Your\Downloads"
```

**4. Rollback Operations**
Revert the last batch of file movements to restore the directory to its previous state:
```bash
python src/rollback.py --path "C:\Path\To\Your\Downloads"
```

## Engineering Decisions

- **Granular File-System Locks**: To prevent race conditions during concurrent directory validation without halting the entire pool, a `threading.Lock()` is placed strictly around path validation and folder creation. The actual I/O move operation (`shutil.move`) is kept outside the lock to prevent blocking the thread pool.
- **SQLite over JSON for Tracking**: Transitioning from a flat JSON file array to SQLite prevents JSON serialization overhead and file locks during concurrent logging, reducing memory overhead when organizing deeply populated local directories.
- **Fail-Safe Operation Order**: Process order dictates that threat logging and permission attributes (`os.chmod`) are applied prior to moving the file. If a file-system exception halts the transfer, the file's attribute modifications are already in place in the source directory.

## Roadmap
- [ ] Implement external configuration via YAML/JSON arrays to map file extensions.
- [ ] Add metric reporting for processing using `tqdm`.
- [ ] Add native support for Multi-OS Path normalization and cross-platform permissions.

---
Released under the **MIT License**.
