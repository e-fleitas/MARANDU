#!/usr/bin/env bash
# File: /home/marandu/run_detections.sh (o en la raíz de tu proyecto)

# Ir al directorio del proyecto
cd "/home/marandu/detection" || exit 1

# Cargar el entorno virtual de python (si se utiliza uno)
# source ./venv/bin/activate

# Cargar variables de entorno del archivo .env si existe
if [ -f ../.env ]; then
    export $(grep -v '^#' ../.env | xargs)
fi

# Ejecutar de forma segura los monitores que no requieren root
python3 process_monitor.py >> /var/log/hips/process_monitor.log 2>&1
python3 tmp_monitor.py >> /var/log/hips/tmp_monitor.log 2>&1
python3 cron_monitor.py >> /var/log/hips/cron_monitor.log 2>&1
python3 mail_queue_monitor.py >> /var/log/hips/mail_queue_monitor.log 2>&1
python3 sniffer_detect.py >> /var/log/hips/sniffer_detect.log 2>&1