#!/bin/bash
# setup_web.sh - Entorno Virtual y Dependencias de Python para M.A.R.A.N.D.U

echo "================================================================="
echo "=== [PASO 2] Instalando Dependencias Python como 'marandu' ====="
echo "================================================================="

# Validar que NO se esté corriendo como root directo para proteger los permisos del venv
if [ "$EUID" -eq 0 ]; then
  echo "[-] Error: No ejecutes este script directamente con sudo."
  echo "    Debes ejecutarlo delegando al usuario de la app con el comando:"
  echo "    sudo -u marandu ./setup_web.sh"
  exit 1
fi

# Detectar directorio de forma dinámica
PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="$PROJ_DIR/web/requirements.txt"

# 1. Gestión inteligente del Entorno Virtual (venv)
if [ -n "$VIRTUAL_ENV" ]; then
  echo "[+] Entorno virtual activo detectado en la sesión: $VIRTUAL_ENV"
else
  if [ -d "$PROJ_DIR/venv" ]; then
    echo "[+] Activando entorno virtual existente en $PROJ_DIR/venv..."
    source "$PROJ_DIR/venv/bin/activate"
  else
    echo "[+] Creando nuevo entorno virtual (venv) en la raíz..."
    python3 -m venv "$PROJ_DIR/venv"
    source "$PROJ_DIR/venv/bin/activate"
  fi
fi

# Asegurar que se activó correctamente
if [ -z "$VIRTUAL_ENV" ]; then
  echo "[-] Error crítico: No se pudo inicializar el entorno virtual."
  exit 1
fi

# 2. Instalar requerimientos del panel web
if [ -f "$REQ_FILE" ]; then
  echo "[+] Archivo de requerimientos localizado en: $REQ_FILE"
  echo "[+] Actualizando pip local..."
  pip install --upgrade pip
  
  echo "[+] Instalando librerías requeridas (FastAPI, Passlib, etc.)..."
  pip install -r "$REQ_FILE"
  
  echo "================================================================="
  echo "[OK] ¡Dependencias de Python instaladas con éxito dentro del venv!"
  echo "[*] Todo está listo. Para iniciar el servidor Web de M.A.R.A.N.D.U, ejecutá:"
  echo "    cd $PROJ_DIR/web && $PROJ_DIR/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000"
  echo "================================================================="
else
  echo "[-] Error crítico: No se encontró el archivo $REQ_FILE"
  exit 1
fi