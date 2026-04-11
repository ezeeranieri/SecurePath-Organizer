# 🛡️ SecurePath-Organizer

<p align="center">
  <em>A secure file organizer leveraging header-based verification and atomic transactions.</em>
</p>

---

## 🎯 Objective
**SecurePath-Organizer** goes beyond classic file automation. This system securely organizes cluttered directories (like Downloads) while heavily prioritizing cybersecurity. Using a **Header-based verification** approach, it analyzes binary structures to detect disguised malware, and uses a transactional engine to safely organize your files or revert them atomically if needed.

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
- **`organizador.py`**: The core engine. Scans the directory using heavy parallelization (`concurrent.futures`), processes files organically into logical categories (`Images`, `Documents`, etc.), filters out threats, strips their execution permissions, and generates a stateful `transfer_history.json` acting as an auditable local database.
- **`rollback.py`**: A surgical restorer that acts as an emergency reset button. It reads the JSON database backwards (LIFO approach) and reverts every approved movement to its exact original location, intelligently destroying temporary empty folders behind itself to avoid trailing junk.

## 🔒 Security Features
- **Header-based Verification**: File extensions can be falsified. SecurePath-Organizer reads files in binary (`rb`) to inspect their headers. If it detects `MZ` signatures (Windows executables) masquerading as harmless documents, they get caught.
- **Automatic Quarantine & Permission Stripping**: Any potentially malicious payload (double extensions `.pdf.exe`, dangerous native extensions `.bat`, `.vbs`, etc.) gets completely isolated into a `QUARANTINE` folder. Execution permissions are strictly stripped (`0o444`), averting automated system attacks or accidental user clicks.
- **Webhook Alerts**: Threat detections can trigger an automated alert signaling the file location and threat typology. 

## 🤔 Design Decisions
- **LIFO for Rollbacks**: The `rollback.py` reverses the JSON log backwards (Last In, First Out). This completely secures the integrity of the filesystem because files moved recently won't overlap with files moved originally, effectively avoiding overwrite collisions during mass migrations.
- **Magic Bytes Over Extensions**: A naive algorithm relies on `.pdf` text strings. Advanced malware spoofs extensions to execute malicious payloads disguised as safe filetypes. Reading the raw hexadecimal headers guarantees the file's true identity, thwarting spoofing entirely.

## 🧪 What I Learned
- **Concurrency & Threads**: Coordinating parallel I/O tasks using `concurrent.futures.ThreadPoolExecutor` taught me why synchronization matters. Introducing a `threading.Lock()` was crucial to avoid database corruption when hundreds of threads try to log their transfer history simultaneously.
- **Transactional Consistency**: Implementing a two-step `Atomic Journal Commit` (`.tmp` to `.json` file swap) prevents corrupted tracking logs if the program unexpectedly crashes or the system shuts down.
- **Basic Forensic Analysis**: Analyzing raw file bytecode footprints (`\xff\xd8\xff` for JPEG, `MZ` for EXEs) instead of relying on OS surface metrics developed a strong foundation in digital forensics and defensive programming.

## 🗺️ Roadmap
- [ ] Implement robust external configuration loading via YAML or JSON files.
- [ ] Add interactive progress bar metrics using `tqdm` for extreme large folders processing.
- [ ] Improve quarantine isolation via deeper file-system OS permissions (ACLs/Chroot).
- [ ] Multi-OS Path normalization support (currently optimized for Windows environments).

---
Released under the **MIT License**.
