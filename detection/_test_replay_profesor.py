#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module (herramienta de prueba, no forma parte
del sistema en producción)
File: detection/_test_replay_profesor.py

Reproduce los archivos de log de muestra que dio el profesor, línea por
línea, a través de la misma lógica de parseo y evaluación de umbrales de
log_analyzer.py -- sin pasar por LogTail (los archivos son estáticos, no
hace falta seguirlos en vivo). Sirve para calibrar los umbrales contra
ataques reales antes de la entrega.
"""

import sys
import datetime

from db_writer import obtener_conexion
from log_analyzer import (
    parsear_linea_secure_messages,
    parsear_linea_maillog,
    parsear_linea_access_log,
    procesar_linea_secure_messages,
    procesar_linea_maillog,
    procesar_linea,
    VentanaDeslizante,
    VENTANA_FAILED_LOGIN_SEGUNDOS,
    VENTANA_404_SEGUNDOS,
    VENTANA_500_SEGUNDOS,
)


def reproducir_secure_messages(ruta_secure, ruta_messages, conexion_db):
    print(f"\n=== Reproduciendo {ruta_secure} + {ruta_messages} (FAILED_LOGIN_MULTIPLE) ===")
    ventana = VentanaDeslizante(VENTANA_FAILED_LOGIN_SEGUNDOS)
    total_alarmas = 0
    total_lineas_matcheadas = 0

    for ruta, fuente in [(ruta_secure, "secure"), (ruta_messages, "messages")]:
        try:
            with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                for linea in f:
                    linea = linea.rstrip("\n")
                    if not linea:
                        continue
                    evento = parsear_linea_secure_messages(linea)
                    if evento is None:
                        continue
                    total_lineas_matcheadas += 1
                    total_alarmas += procesar_linea_secure_messages(evento, ventana, conexion_db, fuente)
        except FileNotFoundError:
            print(f"[-] No se encontró {ruta}", file=sys.stderr)

    print(f"[+] Líneas matcheadas (Failed password / auth failure): {total_lineas_matcheadas}")
    print(f"[+] Alarmas FAILED_LOGIN_MULTIPLE emitidas: {total_alarmas}")
    return total_alarmas


def reproducir_maillog(ruta_maillog, conexion_db):
    print(f"\n=== Reproduciendo {ruta_maillog} (SMTP_BRUTE_FORCE) ===")
    conteo_mail_por_remitente = {}
    total_alarmas = 0
    total_lineas_matcheadas = 0
    total_ataques_nativos = 0
    total_mails = 0

    try:
        with open(ruta_maillog, "r", encoding="utf-8", errors="replace") as f:
            for linea in f:
                linea = linea.rstrip("\n")
                if not linea:
                    continue
                evento = parsear_linea_maillog(linea)
                if evento is None:
                    continue
                total_lineas_matcheadas += 1
                if evento["tipo_evento"] == "smtp_attack_nativo":
                    total_ataques_nativos += 1
                else:
                    total_mails += 1
                total_alarmas += procesar_linea_maillog(evento, conteo_mail_por_remitente, conexion_db)
    except FileNotFoundError:
        print(f"[-] No se encontró {ruta_maillog}", file=sys.stderr)

    print(f"[+] Líneas matcheadas: {total_lineas_matcheadas} "
          f"(ataques nativos de Sendmail: {total_ataques_nativos}, envíos: {total_mails})")
    print(f"[+] Alarmas SMTP_BRUTE_FORCE emitidas: {total_alarmas}")
    return total_alarmas


def reproducir_access_log(ruta_access_log, conexion_db):
    print(f"\n=== Reproduciendo {ruta_access_log} (WEB_SCAN_404 / WEB_EXPLOIT_500) ===")
    ventana_404 = VentanaDeslizante(VENTANA_404_SEGUNDOS)
    ventana_500 = VentanaDeslizante(VENTANA_500_SEGUNDOS)
    total_alarmas = 0
    total_lineas_matcheadas = 0

    try:
        with open(ruta_access_log, "r", encoding="utf-8", errors="replace") as f:
            for linea in f:
                linea = linea.rstrip("\n")
                if not linea:
                    continue
                evento = parsear_linea_access_log(linea)
                if evento is None:
                    continue
                total_lineas_matcheadas += 1
                total_alarmas += procesar_linea(evento, ventana_404, ventana_500, conexion_db)
    except FileNotFoundError:
        print(f"[-] No se encontró {ruta_access_log}", file=sys.stderr)

    print(f"[+] Líneas matcheadas: {total_lineas_matcheadas}")
    print(f"[+] Alarmas WEB_SCAN_404 / WEB_EXPLOIT_500 emitidas: {total_alarmas}")
    return total_alarmas


if __name__ == "__main__":
    conexion_db = obtener_conexion()
    if conexion_db is None:
        print("[-] No se pudo conectar a la base de datos. Abortando prueba.", file=sys.stderr)
        sys.exit(1)

    inicio = datetime.datetime.now()

    total = 0
    total += reproducir_secure_messages("pruebas_profesor_secure.txt", "pruebas_profesor_message.txt", conexion_db)
    total += reproducir_maillog("pruebas_profesor_maillog.txt", conexion_db)
    total += reproducir_access_log("pruebas_profesor_access_log.txt", conexion_db)

    conexion_db.close()

    duracion = (datetime.datetime.now() - inicio).total_seconds()
    print(f"\n=== TOTAL: {total} alarmas emitidas en {duracion:.2f}s ===")
