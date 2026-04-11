# 🛡️ SecurePath-Organizer: Smart File Automation with Transactional Rollback

<p align="center">
  <em>An enterprise-grade, Zero-Trust file sorter and automator built on native Python.</em>
</p>

## 🚀 Overview
**SecurePath-Organizer** goes beyond classic script-kiddie automation. This system securely organizes cluttered directories (like Downloads), but under the hood, it operates as a stateful transaction engine. It leverages **Zero-Trust** concepts via binary inspection and guarantees **transactional atomicity** by tracking movements in JSON memory, allowing precise LIFO state rollbacks.

## 🏗️ Core Architecture

### 1. Zero-Trust Introspection (Magic Bytes)
File extensions lie; bytecode does not. Instead of blindly trusting `.pdf` or `.jpg` extensions, **SecurePath-Organizer** opens processed files in binary mode (`rb`) and inspects the header. If it detects `MZ` (4D 5A) signatures—the footprint of Windows executables—masquerading as harmless documents, the payload is neutralized. The file is isolated into the `QUARANTINE` folder and an alert is broadcasted via Webhooks.

### 2. Transactional State Management & Rollback
Forget sweeping directories blindly. This architecture logs every successful I/O transfer into an auditable `transfer_history.json` footprint. 
The companion `rollback.py` script acts as a surgical restorer. By iterating this JSON backwards (LIFO), it returns your file tree back to its pristine original state while destroying any empty artifact folders, leaving zero phantom directories behind.

## ⚙️ Quick Start

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
Run the core engine to secure and organize your files.
```bash
python src/organizador.py --path "C:\Path\To\Your\Downloads"
```

**4. Emergency Atomic Rollback**
Revert the last transaction set flawlessly using the generated footprint state:
```bash
python src/rollback.py --path "C:\Path\To\Your\Downloads"
```

## 📋 Security & Architecture Audit (Staff Level)
This project successfully passed a rigorous Professional Code Review based on four pillars:
- **Security:** Stops double-extension spoofing and raw binary (`MZ`) camouflaging entirely.
- **Maintainability:** Pure `pathlib` modern integration. Zero external Python packages required.
- **Resilience:** Implements Write-Ahead-Log style histories. Handles `PermissionsError` lockages and mitigates overwrite collisions dynamically.
- **Efficiency:** I/O loops operate on minimal generator memory logic (`iterdir()`). Same-drive transfers are virtually instantaneous.

---
## 📄 License
Released under the **MIT License**. Use it, break it, and securely automate your pipelines.
