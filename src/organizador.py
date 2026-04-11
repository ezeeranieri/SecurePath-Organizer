import os
import argparse
import logging
import shutil
import json
import urllib.request
from urllib.error import URLError
from pathlib import Path
from datetime import datetime

WEBHOOK_URL = "" 

def setup_logger():
    logger = logging.getLogger('organizer')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler("organizer.log", encoding='utf-8')
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

logger = setup_logger()

EXTENSION_MAPPING = {
    '.jpg': 'Imágenes', '.jpeg': 'Imágenes', '.png': 'Imágenes', '.gif': 'Imágenes', '.svg': 'Imágenes',
    '.pdf': 'Documentos', '.docx': 'Documentos', '.doc': 'Documentos', '.txt': 'Documentos',
    '.xlsx': 'Documentos', '.csv': 'Documentos', '.pptx': 'Documentos',
    '.zip': 'Comprimidos', '.rar': 'Comprimidos', '.tar': 'Comprimidos', '.gz': 'Comprimidos',
    '.mp4': 'Videos', '.mkv': 'Videos', '.mp3': 'Audio', '.wav': 'Audio'
}

SUSPICIOUS_EXTENSIONS = {'.exe', '.bat', '.sh', '.vbs', '.cmd', '.msi', '.ps1'}

# ==========================================
# GESTIÓN ZERO-TRUST Y ALERTAS
# ==========================================
def send_alert(filename: str, source_path: Path, threat_type: str = "Peligro General"):
    if not WEBHOOK_URL: return
    try:
        data = {
            "content": f"⚠️ **Alerta Zero-Trust:**\n**Amenaza:** `{threat_type}`\n**Archivo:** `{filename}`\n**Ruta:** `{source_path}`\nEnviado a cuarentena."
        }
        req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req)
        logger.info("Alerta Zero-Trust emitida al canal.")
    except Exception as e:
        logger.error(f"Fallo emitiendo alerta vía webhook: {e}")

def get_threat_type(filepath: Path) -> str:
    """Implementa el modelo Zero Trust. Devuelve un texto descriptivo del riesgo o Nada si es seguro."""
    # 1. Análisis Biométrico Computacional (Magic Bytes)
    try:
        with open(filepath, 'rb') as f:
            header = f.read(2)
            # 4D 5A ('MZ') es la firma canónica de todo ejectuable DOS/Windows (.exe/.dll/.sys)
            if header == b'MZ':
                if filepath.suffix.lower() not in SUSPICIOUS_EXTENSIONS:
                    return "Suplantación de Identidad (Contenido Ejecutable camuflado con extensión inofensiva)"
                return "Ejecutable Comprobado (Firma de bytes MZ)"
    except Exception as e:
        logger.warning(f"Fallo en lectura binaria de {filepath.name}: {e}. Evaluando por reglas secundarias...")

    # 2. Análisis Crudo de Extensiones
    if filepath.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        return "Extensión Nativamente Peligrosa"
    
    if len(filepath.suffixes) > 1 and filepath.suffixes[-2:] != ['.tar', '.gz']:
        return "Ataque de doble extensión detectado"
        
    return None

# ==========================================
# ESTADO TRANSACCIONAL ALMACENADO (STATE LOG)
# ==========================================
def save_transaction_log(source_path: Path, transactions: list):
    """Añade o crea el historial de transferencias en un JSON maestro."""
    if not transactions:
        return
        
    history_file = source_path / "transfer_history.json"
    existing_history = []
    
    if history_file.exists():
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                existing_history = json.load(f)
        except Exception as e:
            logger.error(f"El registro de transacciones anterior está corrupto. Generando cola nueva...: {e}")
            
    existing_history.extend(transactions)
    
    try:
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(existing_history, f, indent=4, ensure_ascii=False)
        logger.info(f"💾 Consistencia Transaccional: Se han añadido {len(transactions)} operaciones al transfer_history.json.")
    except Exception as e:
        logger.error(f"Error de E/S Crítico al salvar historial: {e}")

# ==========================================
# LÓGICA CORE DE MOTOR DE CAMBIO
# ==========================================
def organize_directory(source_dir_path: str, dry_run: bool = False):
    source_path = Path(source_dir_path)
    
    if not source_path.exists() or not source_path.is_dir():
        logger.error(f"La ruta '{source_path}' no existe o no se puede acceder.")
        return

    mode_text = "[DRY-RUN] " if dry_run else ""
    logger.info(f"=== Iniciando Motor Ciberseguro {mode_text}en {source_path} ===")

    transactions = []

    for item in source_path.iterdir():
        # Exclusión rigurosa de metadatos de aplicación
        if item.is_dir() or item.name in ("organizer.log", "organizador.py", "rollback.py", "transfer_history.json", "transfer_history_backup.json"):
            continue

        threat_type = get_threat_type(item)
        
        if threat_type:
            target_folder = 'QUARANTINE'
            logger.warning(f"¡AMENAZA AISLADA!: {item.name} -> {threat_type}")
            if not dry_run:
                send_alert(item.name, source_path, threat_type)
        else:
            target_folder = EXTENSION_MAPPING.get(item.suffix.lower(), 'Otros')

        target_dir = source_path / target_folder
        target_file = target_dir / item.name

        if target_file.exists():
            logger.info(f"Omitiendo reescritura: '{item.name}' ya existía en destino.")
            continue

        if dry_run:
            logger.info(f"[SIMULACRO] Planificado: {item.name} -> {target_folder}/")
        else:
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.move(str(item), str(target_file))
                
                # Memoria de Base de Datos para el archivo JSON (Commit)
                transactions.append({
                    "filename": item.name,
                    "original_path": str(item),
                    "new_path": str(target_file),
                    "timestamp": datetime.now().isoformat()
                })
                
                logger.info(f"Migrado: {item.name} -> {target_folder}/")
            except Exception as e:
                logger.error(f"Detención en archivo '{item.name}': {e}")

    # Commit en Disco
    if not dry_run and transactions:
        save_transaction_log(source_path, transactions)

    logger.info(f"=== Operación {mode_text}Finalizada Satisfactoriamente ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Arquitectura de Organización Zero-Trust & DB Transaccional.")
    parser.add_argument("--path", type=str, required=True, help="Carpeta a limpiar/organizar.")
    parser.add_argument("--dry-run", action="store_true", help="Simulacro que emite logs sin ejecutar operaciones i/o.")
    args = parser.parse_args()
    organize_directory(args.path, dry_run=args.dry_run)
