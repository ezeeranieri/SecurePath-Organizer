# 🛡️ SecurePath-Organizer

<p align="center">
  <em>An enterprise-grade, Zero-Trust file sorter and automator built on native Python.</em><br>
  <em>Un organizador de archivos empresarial basado en arquitectura Zero-Trust, escrito en Python nativo.</em>
</p>

---

## 🇬🇧 English Documentation

### 🎯 Objective
**SecurePath-Organizer** goes beyond classic file automation. This system securely organizes cluttered directories (like Downloads) while heavily prioritizing cybersecurity. Using a **Zero-Trust** approach, it analyzes binary structures to detect disguised malware, and uses a transactional engine to safely organize your files or revert them atomically if needed.

### ⚙️ Installation & Usage

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

### 🧠 Core Functions
- **`organizador.py`**: The core engine. Scans the directory using heavy parallelization (`concurrent.futures`), processes files organically into logical categories (`Images`, `Documents`, etc.), filters out threats, and generates a stateful `transfer_history.json` acting as an auditable local database.
- **`rollback.py`**: A surgical restorer that acts as an emergency reset button. It reads the JSON database backwards (LIFO approach) and reverts every approved movement to its exact original location, intelligently destroying temporary empty folders behind itself to avoid trailing junk.

### 🔒 Security Features
- **Magic Bytes Validation**: File extensions can be falsified. SecurePath-Organizer reads files in binary (`rb`) to inspect their headers. If it detects `MZ` signatures (Windows executables) masquerading as harmless documents, they get caught.
- **Automatic Quarantine**: Any potentially malicious payload (double extensions `.pdf.exe`, dangerous native extensions `.bat`, `.vbs`, etc.) gets completely isolated into a `QUARANTINE` folder, averting automated system attacks.
- **Webhook Alerts**: Threat detections can trigger an automated alert (Discord, Slack, etc.) signaling the file location and threat typology. 

### 🗺️ Roadmap
- [ ] Implement robust logging aggregation via ElasticSearch or Loki.
- [ ] Multi-OS Path normalization support (currently optimized for Windows environments).
- [ ] User custom extensions configuration file loading via YAML/JSON.
- [ ] Add CLI progress bar metrics for extreme large folders processing.

---

## 🇪🇸 Documentación en Español

### 🎯 Objetivo
**SecurePath-Organizer** va más allá de la automatización clásica de archivos. Este sistema organiza de forma segura directorios desordenados (como tu carpeta de Descargas) priorizando la ciberseguridad. Gracias a un enfoque **Zero-Trust**, evalúa estructuras binarias para neutralizar malware camuflado, y utiliza un motor transaccional que permite ordenar tus archivos de manera rápida, segura y completamente reversible.

### ⚙️ Instalación y Uso

**1. Clonar el repositorio**
```bash
git clone https://github.com/YourUsername/SecurePath-Organizer.git
cd SecurePath-Organizer
```

**2. Simulacro (Modo Prueba - Dry-Run)**
Comprueba qué acciones se van a realizar sin realizar cambios reales en el disco:
```bash
python src/organizador.py --path "C:\Tu\Ruta\Descargas" --dry-run
```

**3. Ejecución en Producción**
Organiza todos tus archivos, utilizando procesamiento paralelo de alto rendimiento.
```bash
python src/organizador.py --path "C:\Tu\Ruta\Descargas"
```

**4. Rollback de Emergencia**
Revierte atómicamente el último bloque de operaciones y devuélvelo a la normalidad:
```bash
python src/rollback.py --path "C:\Tu\Ruta\Descargas"
```

### 🧠 Funciones Principales
- **`organizador.py`**: El motor base. Escanea la ruta usando procesamiento paralelo (`concurrent.futures`), ordena nativamente los archivos por categoría lógica (Imágenes, Documentos...), aparta amenazas y consolida todo en un archivo auditable `transfer_history.json`.
- **`rollback.py`**: Restaurador quirúrgico o botón de "reset". Lee la base de datos inversa (LIFO) y devuelve cada nodo orgánico a su posición nativa exacta, destruyendo por medio de un recolector de basura (GC) las carpetas temporales huérfanas que van quedando.

### 🔒 Sección de Seguridad Zero-Trust
- **Detección de Amenazas por Magic Bytes**: En lugar de confiar en la extensión `.jpg` o `.pdf`, la aplicación lee bytes del encabezado en binario puro buscando las firmas `MZ` correspondientes a ejecutables camuflados e interceptándolos nativamente.
- **Cuarentena Automática**: Cualquier elemento anómalo (como una doble extensión `.pdf.exe` o variables explícitamente maliciosas `.bat`, `.vbs`, etc.) es capturado, asilado e inaccesible mediante su intercepción hacia el enclave `QUARANTINE`.
- **Alertas Zero-Trust**: Cuenta con un sistema interno de Webhooks preparado para notificar instantáneamente la ubicación e intentona de infiltración maliciosa en repositorios como Discord u otras plataformas de mensajería empresarial.

### 🗺️ Roadmap Futuro
- [ ] Implementar un panel de Logs a través de ElasticSearch.
- [ ] Soporte para customización de tipo de extensiones mediante archivos YAML/JSON nativos.
- [ ] Soporte Universal para rutas Linux y MacOS (rutas relativas POSIX).
- [ ] Integrar barra de progreso interactivo (tqdm) para directorios de peso masivo.

---
Released under the **MIT License**.
