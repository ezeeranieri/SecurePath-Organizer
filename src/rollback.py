import argparse
import logging
import shutil
import json
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def rollback_directory(target_dir_path: str):
    """
    Rollback Empresarial: A través del modelo de Git o Bases de Datos, 
    usamos transfer_history.json para revertir exclusivamente los movimientos 
    aprobados, sin dañar el resto del entorno orgánico del usuario.
    """
    base_path = Path(target_dir_path)
    history_file = base_path / "transfer_history.json"
    
    if not history_file.exists():
        logging.error(f"Falta el historial de estado de la aplicación ({history_file.name}). Imposible realizar un Rollback seguro.")
        return

    logging.info(f"--- Iniciando INYECCIÓN INVERSA (Rollback Transaccional) sobre {base_path} ---")

    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            transactions = json.load(f)
    except Exception as e:
        logging.critical(f"La base de datos en JSON está corrupta: {e}")
        return

    if not transactions:
        logging.warning("El historial de reubicación no tiene bloques registrados.")
        return

    successful_rollbacks = 0
    # Iteramos en formato LIFO (Último dentro - Primero fuera). Regla oro de BDs.
    for idx, tx in enumerate(reversed(transactions)):
        try:
            original = Path(tx["original_path"])
            current = Path(tx["new_path"])
            
            if not current.exists():
                logging.warning(f"Desincronización temporal: {current.name} ya no se encuentra en {current.parent}. Ignorando.")
                continue

            if original.exists():
                logging.warning(f"Peligro de Pisado: Ya existe un nuevo archivo en {original}. Omitiendo reversión de este nodo.")
                continue

            shutil.move(str(current), str(original))
            logging.info(f"Revertido Atómicamente: {current.name} -> {original.parent}/")
            successful_rollbacks += 1
            
        except Exception as e:
            logging.error(f"Error bloqueante restaurando '{tx['filename']}': {e}")
            
    # Intentar barrer (garbage collect) la estructura de carpetas si han quedado vacías
    checked_folders = set()
    for tx in transactions:
        folder = Path(tx["new_path"]).parent
        if folder not in checked_folders and folder.exists() and folder.is_dir():
            checked_folders.add(folder)
            try:
                # rmdir arroja OSError si NO está vacía, que es justo el comportamiento defensivo deseado
                folder.rmdir()
                logging.info(f"♻️ Carpeta puente vacía destruida por GC: {folder.name}/")
            except OSError:
                pass 

    # Tratamiento post-mortem del registro histórico
    if successful_rollbacks == len(transactions):
        try:
            # Transformamos el histórico para evitar dobles rollbacks
            backup_file = base_path / "transfer_history.bak.json"
            if backup_file.exists():
                backup_file.unlink()
            history_file.rename(backup_file)
            logging.info(f"✅ Histórico limpiado en '.bak.json'. 100% de los {len(transactions)} nodos revertidos con vida.")
        except Exception as e:
            logging.warning(f"No se pudo renombrar el archivo histórico: {e}")
    else:
        logging.warning(f"⚠️ Alerta: Rollback parcial completado. Solo se sanearon {successful_rollbacks} de {len(transactions)} nodos transferidos.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script Transaccional para devolver sistema a un Snapshot válido.")
    parser.add_argument("--path", type=str, required=True, help="Ruta de la raíz donde yace transfer_history.json")
    
    args = parser.parse_args()
    rollback_directory(args.path)
