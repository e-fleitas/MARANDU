#!/bin/bash
# ==============================================================================
# M.A.R.A.N.D.U. - Script de Configuración Web y Entorno Virtual
# ==============================================================================
#
# Además de crear el venv e instalar dependencias, este script deja la base
# de datos lista: crea las tablas y carga `configuracion_modulos` con los
# 3 niveles (minimo/moderado/agresivo) de cada grupo de alarma, respetando
# el piso de seguridad definido en prevention/strategia.py.
#
# Opcional: para que también se cargue la configuración de notificaciones
# SMTP, exportá estas variables antes de correr el script:
#   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ADMIN_EMAIL
# Si no están seteadas, el script avisa y podés volver a correr el seed
# más adelante con: python -m db.seed_config
# ==============================================================================
set -e

# Validar de forma estricta que no se esté ejecutando como root accidentalmente
if [ "$USER" != "marandu" ]; then
    echo "[!] Error de seguridad: Este script debe ser ejecutado exclusivamente por el usuario 'marandu'."
    echo "    Por favor usa: sudo -u marandu ./setup_web.sh"
    exit 1
fi

# Definición de rutas del ecosistema local
PROJ_DIR=$(pwd)
VENV_DIR="$PROJ_DIR/venv"
REQ_FILE="$PROJ_DIR/web/requirements.txt"

echo "=============================================================================="
echo "[+] Iniciando configuración del entorno virtual para la interfaz de M.A.R.A.N.D.U..."
echo "=============================================================================="

# 1. Inicializar el entorno virtual de Python
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creando entorno virtual aislado (venv) en $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "[ ] El entorno virtual ya se encuentra inicializado."
fi

# 2. Activar el entorno e instalar dependencias de la aplicación
echo "[+] Activando entorno virtual..."
source "$VENV_DIR/bin/activate"

echo "[+] Actualizando administrador de paquetes pip..."
pip install --upgrade pip

# 3. Instalación de paquetes de Python
if [ -f "$REQ_FILE" ]; then
    echo "[+] Instalando dependencias desde $REQ_FILE..."
    pip install -r "$REQ_FILE"
    echo "[+] Todas las librerías de Python se instalaron con éxito."
else
    echo "[!] Advertencia: No se detectó el archivo de requerimientos en $REQ_FILE."
    echo "[+] Instalando dependencias base estándar para el Dashboard (FastAPI/Uvicorn)..."
    pip install fastapi uvicorn pydantic
fi

# Estas 3 son necesarias para el paso de seed de la BD (punto 4) sin
# importar si ya vinieron o no en requirements.txt.
pip install "sqlalchemy[asyncio]" asyncpg python-dotenv

# 4. Preparar la base de datos: crear tablas y cargar configuracion_modulos
#    (idempotente: se puede correr de nuevo sin duplicar filas ni pisar
#    niveles ya configurados a mano desde el panel).
echo "[+] Preparando base de datos (tablas + configuracion_modulos)..."
python -m db.seed_config

echo "=============================================================================="
echo "[✓] FASE 2 COMPLETADA: Entorno web de M.A.R.A.N.D.U. listo."
echo "Para levantar el Panel de Control con Uvicorn de manera manual, ejecuta:"
echo "    source venv/bin/activate"
echo "    uvicorn web.app:app --host 0.0.0.0 --port 8000"
echo "=============================================================================="