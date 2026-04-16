# SecurePath Organizer

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=ezeeranieri_SecurePath-Organizer)](https://sonarcloud.io/summary/new_code?id=ezeeranieri_SecurePath-Organizer)
[![codecov](https://codecov.io/github/ezeeranieri/SecurePath-Organizer/graph/badge.svg?token=TOH06FVHVU)](https://codecov.io/github/ezeeranieri/SecurePath-Organizer)

A concurrent file organizer built in Python, designed to categorize files while performing basic security checks. It relies on magic bytes validation to detect potentially masked extensions and uses an embedded SQLite database to track file operations, providing a reliable rollback mechanism.

## Quick Overview

**Organizes files + detects threats + allows safe rollback**

```
Scan → Analyze → Classify → Move → Log → Rollback
```

1. **Scan**: Discovers all files in the target directory (concurrent thread pool)
2. **Analyze**: Performs magic bytes validation to detect spoofed extensions
3. **Classify**: Categorizes files by type (Documents, Images, Executables, etc.)
4. **Move**: Transfers files to destination folders with atomic operations
5. **Log**: Records every operation in SQLite for full traceability
6. **Rollback**: Restores original state if needed (LIFO recovery)

## Tech Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Core Language | Python 3.8+ | Zero external dependencies for base functionality |
| Concurrency | `ThreadPoolExecutor` | I/O-bound workloads, lighter than multiprocessing |
| Persistence | SQLite | ACID transactions, concurrent-safe writes |
| Security | Magic bytes validation | Forensic-grade file identification |
| Testing | pytest | Industry-standard test runner |

## Core Features

- **Concurrent Processing**: Utilizes `ThreadPoolExecutor` to handle file I/O operations in parallel, improving performance on large directories.
- **Lightweight Threat Validation**: Analyzes files using magic bytes (e.g., verifying `MZ` headers) instead of exclusively trusting standard file extensions to prevent basic identity spoofing.
- **Transactional Rollback**: File movements are logged into a local SQLite database (`transfer_history.db`). A dedicated rollback script allows reverting operations sequentially (LIFO) if needed.
- **Quarantine & Permission Management**: Files classified as suspicious are moved to a dedicated `QUARANTINE` folder, and their read-only attribute is flagged (`chmod 0o400`) to prevent accidental modifications.

## Why Rollback?

File operations are **irreversible by default**. Once moved, files lose their original context and location metadata permanently.

This system introduces a **transactional layer** using SQLite to enable safe rollback:

- Every file movement is recorded as an atomic transaction with original path, destination, and checksum
- Operations can be reverted in LIFO order (last moved, first restored)
- Even quarantined files retain full restoration capability
- Database survives crashes and power failures (ACID properties)

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
python src/organizador.py --path "/home/user/Downloads" --dry-run
# Or on Windows:
# python src/organizador.py --path "C:\Path\To\Your\Downloads" --dry-run
```

**3. Run Organizer**
Execute the file organization process:
```bash
python src/organizador.py --path "/home/user/Downloads"
# Or on Windows:
# python src/organizador.py --path "C:\Path\To\Your\Downloads"
```

**4. Rollback Operations**
Revert the last batch of file movements to restore the directory to its previous state:
```bash
python src/rollback.py --path "/home/user/Downloads"
# Or on Windows:
# python src/rollback.py --path "C:\Path\To\Your\Downloads"
```

**5. Rollback Dry-Run**
Preview what files would be restored without actually moving them:
```bash
python src/rollback.py --path "/home/user/Downloads" --dry-run
# Or on Windows:
# python src/rollback.py --path "C:\Path\To\Your\Downloads" --dry-run
```

## Running Tests

**1. Install test dependencies**
```bash
pip install -r requirements-dev.txt
```

**2. Run the test suite**
```bash
python -m pytest
```

For verbose output with coverage:
```bash
python -m pytest -v --cov=src
```

## Project Structure

```
src/
├── config.py          # Centralized configuration, logging, and global locks
├── security.py        # Threat detection (magic bytes) and file classification
├── database.py        # SQLite transaction logging and database initialization
├── transfer.py        # File I/O operations, permission management, and alerting
├── organizador.py     # Main orchestration module and CLI entry point
└── rollback.py        # Rollback operations with dry-run support
```

## Security Approach

Three design decisions make this tool security-focused:

### 1. Magic Bytes vs Extension Validation
Extensions are user-editable metadata. Anyone can rename `malware.exe` to `invoice.pdf`.

This tool validates the **binary signature** (magic bytes) instead:
- `MZ` header detection → Windows executables
- PDF starts with `%PDF` → Validates PDF structure
- File classification uses magic bytes as primary signal, extension as secondary

> Result: A file named `photo.jpg` with an `MZ` header gets flagged as "Identity Spoofing" and quarantined.

### 2. Active Quarantine (not just detection)

Many tools detect threats but do nothing. This system:
- **Isolates** suspicious files to `QUARANTINE/` subdirectory
- **Strips execution permissions** (`chmod 0o400`) before moving
- **Prevents accidental double-click execution** even on misconfigured systems

### 3. Permission Locking

- Normal files: Standard permissions preserved
- Quarantined files: **Read-only**, owner-restricted
- Rollback restores original permissions exactly

## Engineering Decisions

- **Granular File-System Locks**: To prevent race conditions during concurrent directory validation without halting the entire pool, a `threading.Lock()` is placed strictly around path validation and folder creation. The actual I/O move operation (`shutil.move`) is kept outside the lock to prevent blocking the thread pool.

- **Concurrency Model: ThreadPoolExecutor vs ProcessPool**: We chose `ThreadPoolExecutor(max_workers=8)` over `ProcessPoolExecutor` because file organization is I/O-bound (disk operations), not CPU-bound. Threads are lighter weight than processes and share memory space, avoiding the serialization overhead of multiprocessing. However, this choice introduces the Global Interpreter Lock (GIL) limitation—true CPU parallelism is not achieved, but since disk I/O releases the GIL during wait times, threads efficiently interleave operations. The trade-off: simpler shared state and lower memory footprint vs. no true parallelism for CPU-intensive tasks (which this tool does not perform).

- **Two-Lock Strategy**: We maintain separate locks for database operations (`db_lock`) and filesystem operations (`fs_lock`). This allows concurrent database writes and directory validations to proceed independently—if a thread is committing to SQLite, another thread can still validate a destination path without blocking.

- **SQLite over JSON for Tracking**: Transitioning from a flat JSON file array to SQLite prevents JSON serialization overhead and file locks during concurrent logging, reducing memory overhead when organizing deeply populated local directories. SQLite handles concurrent writes safely through its own internal locking, while JSON would require coarse-grained locks on the entire file.

- **Fail-Safe Operation Order**: Process order dictates that threat logging and permission attributes (`os.chmod`) are applied prior to moving the file. If a file-system exception halts the transfer, the file's attribute modifications are already in place in the source directory.

## Challenges & Learnings

**Single Responsibility Principle Refactoring**: The initial monolithic `organizador.py` contained configuration, security logic, database operations, file transfers, and orchestration all in one file. Refactoring into separate modules (`config.py`, `security.py`, `database.py`, `transfer.py`) improved testability and made the codebase more maintainable. The key challenge was ensuring circular imports didn't occur—`config.py` must be importable by all other modules without itself importing from them.

**Two-Lock Concurrency Strategy**: During concurrent file processing, we discovered race conditions where two threads could attempt to create the same destination folder simultaneously. The solution was granular locking: `fs_lock` for filesystem operations (path validation, folder creation) and `db_lock` for database writes. This allows database commits and filesystem operations to overlap, maximizing throughput while preventing data corruption.

**SQLite vs JSON Decision**: Early prototypes used JSON for transaction logging, but we encountered file corruption when multiple threads attempted simultaneous writes. SQLite's built-in row-level locking solved this without requiring coarse-grained application locks. The migration also reduced memory usage—JSON required loading the entire transaction history into memory, while SQLite streams results on demand.

**Magic Bytes Detection Complexity**: Implementing reliable magic bytes validation required handling partial file reads, varying header lengths, and edge cases where files are too small to have valid headers. We learned that magic bytes alone aren't sufficient—combining them with extension validation provides defense in depth. The quarantine mechanism was added after realizing that simply detecting threats wasn't enough; we needed to actively prevent accidental execution.

## Roadmap
- [ ] Implement external configuration via YAML/JSON arrays to map file extensions.
- [ ] Add metric reporting for processing using `tqdm`.
- [ ] Add native support for Multi-OS Path normalization and cross-platform permissions.

## Frequently Asked Questions (FAQ)

**What problem does this solve?**
SecurePath Organizer automates the cleanup of cluttered directories (like your Downloads folder) by categorizing files into logical subfolders (Images, Documents, Compressed, etc.). Unlike simple scripts that only look at file extensions, it adds a security layer that detects hidden executables and prevents accidental execution of suspicious files.

**What happens if a .pdf file is actually an executable?**
The tool performs binary signature validation on every file. If it detects an `MZ` header (typical of Windows executables) inside a file named `invoice.pdf`, it marks it as "Identity Spoofing". The file is then isolated in a `QUARANTINE` directory, its permissions are stripped to read-only (`0o400`), and an optional security alert is triggered via Webhook.

**What is the rollback and when would I use it?**
The rollback (`src/rollback.py`) is a "safety net" script. Every file move is recorded in a transactional SQLite database. If you organize a folder and realize you preferred the original state, running the rollback will move everything back to its exact original path and restore permissions, even for quarantined files.

**Is it safe to run on my Downloads folder?**
Yes. For maximum safety, you should first use the `--dry-run` flag to see exactly what would happen without modifying any files. The tool is designed to be "self-aware"—it automatically ignores its own logs, database, and source code scripts to prevent moving itself.

**What technologies does it use and why?**
- **Python Standard Library**: To keep the tool lightweight with zero external dependencies (no `pip install` required for core features).
- **SQLite**: Used for transaction logging because it's more robust than JSON or text files, ensuring the rollback database won't corrupt during concurrent operations.
- **Multithreading (`ThreadPoolExecutor`)**: Speeds up the organization of thousands of files by handling I/O operations in parallel.
- **Magic Bytes Validation**: Uses binary headers to identify file types, a method used in digital forensics to bypass extension-based spoofing.

## Limitations

Honest assessment of current constraints:

- **SQLite concurrency limits**: Write operations are serialized at the database level (SQLite's WAL mode handles readers well, but concurrent writes queue)
- **CLI-only**: No graphical interface; requires terminal/command-line usage
- **Basic threat detection**: Magic bytes validation catches extension spoofing but not encrypted/obfuscated malware or advanced steganography
- **Single-host scope**: Database and operations are local to one machine
- **Rollback order**: LIFO (last-in-first-out) only; cannot selectively restore individual files out of order

---
Released under the **MIT License**.
