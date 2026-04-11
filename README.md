# 🛡️ SecurePath-Organizer

<p align="center">
  <em>A secure file organizer that detects disguised malware using file header analysis and ensures safe operations through transactional rollback.</em>
</p>

---

## 🎯 Objective
**SecurePath-Organizer** extends traditional file organization by adding basic security checks and safe rollback capabilities. It organizes cluttered directories (like Downloads) using a **Header-based verification** approach to analyze binary structures and detect disguised malware, ensuring that all relocations are executed through a reliable transactional engine.

### 📸 Example Output
```bash
2026-04-11 10:45:00 - WARNING - Threat Detected & Isolated!: invoice.pdf -> Identity Spoofing (Extension claims PDF but bytes do not match)
2026-04-11 10:45:00 - WARNING - Permission stripped: invoice.pdf set to read-only (0o444).
2026-04-11 10:45:00 - INFO - Moving: invoice.pdf -> QUARANTINE/
```

## ⚙️ Installation & Usage

**1. Clone the repository**
```bash
git clone https://github.com/YourUsername/SecurePath-Organizer.git
cd SecurePath-Organizer
```

**2. Dry-Run Execution (Safe Test Mode)**
Test the engine output logic without altering any real files on disk:
```bash
python src/organizador.py --path "C:\Path\To\Your\Downloads" --dry-run
```

**3. Production Execution**
Run the core engine safely using multi-threading for maximum performance.
```bash
python src/organizador.py --path "C:\Path\To\Your\Downloads"
```

**4. Emergency Atomic Rollback**
Revert the last transaction set seamlessly, leaving no trace behind:
```bash
python src/rollback.py --path "C:\Path\To\Your\Downloads"
```

## 🧠 Core Functions
- **`organizador.py`**: The core engine. Scans the directory using multi-threaded processing (`concurrent.futures`), processes files organically into logical categories (`Images`, `Documents`, etc.), filters out threats, strips their execution permissions, and generates a stateful `transfer_history.db` SQLite acting as an auditable local database.
- **`rollback.py`**: A surgical restorer that acts as an emergency reset button. It reads the SQLite database backwards (LIFO approach) and reverts every approved movement to its exact original location, dynamically clearing SQLite rows and destroying temporary empty folders behind itself to avoid trailing junk.

## 🔒 Security Features
- **Header-based Verification**: File extensions can be falsified. SecurePath-Organizer reads files in binary (`rb`) to inspect their headers. If it detects `MZ` signatures (Windows executables) masquerading as harmless documents, they are intercepted and classified as threats.
- **Automatic Quarantine & Permission Stripping**: Any potentially malicious payload (double extensions `.pdf.exe`, dangerous native extensions `.bat`, `.vbs`, etc.) gets completely isolated into a `QUARANTINE` folder. Execution permissions are strictly stripped (`0o444`), averting automated system attacks or accidental user clicks.
- **Webhook Alerts**: Threat detections can trigger an automated alert signaling the file location and threat typology. 

## 🏗️ Technical Trade-offs & Engineering Decisions
- **Granular File-System Locks vs Global Locks**: A simplistic thread-safe approach would involve locking the entire `shutil.move` operation. However, disk I/O is intrinsically slow. By applying a *granular lock* exclusively around the existence check (`target_file.exists()`) and directory creation (`mkdir`), we prevent Time-of-Check to Time-of-Use (TOCTOU) race conditions without blocking the actual file transfer. This isolates the bottleneck, allowing hundreds of threads to execute heavyweight I/O transfers dynamically in parallel, maximizing the `ThreadPoolExecutor` capabilities.
- **Persistent SQLite Connection (`check_same_thread=False`)**: Opening and closing a separate SQLite connection for every parsed file introduces massive overhead, file I/O locks, and excessive context switching. The system adopts a unified persistent connection instantiated once per run and passed down the call stack. Using `check_same_thread=False` combined with a strict atomic `db_lock` around the `INSERT` execution ensures blazing-fast, thread-safe journaling scalability without `WinError 32` connection leaks.
- **Fail-Safe Architecture (Order of Operations)**: Inside `execute_transfer()`, threat logging and strict OS permission stripping (`os.chmod(0o444)`) are purposely executed *prior* to moving the file to `QUARANTINE`. If the actual `shutil.move` crashes mid-flight due to a sudden Kernel block or disk failure, the dangerous payload remains functionally neutralized and visibly logged in the source folder.
- **LIFO for Rollbacks**: The `rollback.py` query reverses the SQL transaction log backwards (Last In, First Out). This structural pattern completely secures the integrity of the filesystem because files moved recently won't overlap with files moved originally, effectively avoiding overwrite collisions.
- **Magic Bytes Protocol**: A naive safety algorithm relies on `.pdf` text strings. Since advanced malware spoofs extensions to execute payloads disguised as safe documents, we read raw hexadecimal headers. Bypassing OS-level metadata guarantees the file's true identity, thwarting Identity Spoofing entirely.

## 🧪 What I Learned
- **Concurrency & Threads**: Coordinating parallel I/O tasks using `concurrent.futures.ThreadPoolExecutor` taught me why synchronization matters. Introducing a `threading.Lock()` was crucial to avoid database corruption when hundreds of threads try to log their transfer history simultaneously.
- **Transactional Consistency**: Implementing safe atomic barriers completely prevents corrupted tracking logs even if the program unexpectedly crashes or the system shuts down.
- **Basic Forensic Analysis**: Analyzing raw file bytecode footprints (`\xff\xd8\xff` for JPEG, `MZ` for EXEs) instead of relying on OS surface metrics developed a strong foundation in digital forensics and defensive programming.

## 🚀 Changelog: From Script to System (v1.0 → v2.0)
The 2.0 release bridges the gap between a standard automation script and a robust, scalable backend system. Key technical hurdles identified and resolved from the initial prototype include:
- **Scalability Breakthrough**: Escaped the O(n²) read/write bottleneck of serialized JSON array manipulation by migrating persistency to an embedded `SQLite` database. Operations are now mapped via SQL schemas, allowing near-instantaneous `INSERT` speed over massive file structures.
- **Concurrency (TOCTOU Resolution)**: Mitigated Time-Of-Check to Time-Of-Use (TOCTOU) race conditions occurring across the multithreaded pool context boundaries by encapsulating filesystem existence checks and SQLite assignments under strict atomic `threading.Lock()` constraints.
- **Architectural Shift (SRP)**: Dismantled the main monolith orchestrator applying the Single Responsibility Principle. Threat forensics (`detect_threat`), declarative routing (`decide_target`), and bare-metal OS operations (`execute_transfer`) are now thoroughly decoupled.
- **Forensic Fidelity (Double Extension Logic)**: Drastically reduced false positives by fine-tuning the Double Extension Spoofing trap. The heuristics now allow legitimate patterns like `archive.tar.gz` or `dataset.v2.csv` to process cleanly without polluting the `QUARANTINE` node.

## 🗺️ Roadmap
- [ ] Implement robust external configuration loading via YAML or JSON files.
- [ ] Add interactive progress bar metrics using `tqdm` for extreme large folders processing.
- [ ] Improve quarantine isolation via deeper file-system OS permissions (ACLs/Chroot).
- [ ] Multi-OS Path normalization support (currently optimized for Windows environments).

---
Released under the **MIT License**.
