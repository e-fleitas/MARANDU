#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/mail_queue_monitor.py

Módulo v: Cola de correo.
Verifica el tamaño de la cola de mails del sistema (comando `mailq`) y
genera una alarma MAIL_QUEUE_ALTA si supera el umbral configurado.

Complementa la detección de envío masivo por remitente que ya vive en
detection/log_analyzer.py (basada en maillog) -- esta pieza mide el
síntoma directo (cola acumulada), independientemente de si el volumen
salió ya o sigue pendiente de entrega.
"""

import os
import sys
import subprocess
from datetime import datetime, timezone
from heartbeat import marcar_heartbeat
NOMBRE_DETECTOR = "mail_queue_monitor"

from db_writer import obtener_conexion, insertar_alarma, insertar_evento_raw

MODULO_NOMBRE = "modulo_v"
TIPO_ALARMA = "MAIL_QUEUE_ALTA"

UMBRAL_COLA = int(os.environ.get("MRND_UMBRAL_COLA_MAIL", "50"))


def obtener_tamano_cola():
    """
    Ejecuta `mailq` y cuenta la cantidad de mensajes pendientes en la cola.
    Devuelve (True, cantidad) en éxito, o (False, mensaje_error) en fallo.
    Nunca lanza excepción hacia el llamador.
    """
    try:
        resultado = subprocess.run(
            ["mailq"],
            shell=False,
            check=True,
            text=True,
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError:
        return False, "Comando 'mailq' no encontrado (¿está instalado el MTA?)"
    except subprocess.TimeoutExpired:
        return False, "Timeout ejecutando 'mailq'"
    except subprocess.CalledProcessError as e:
        return False, f"Error ejecutando 'mailq' ({e.returncode}): {e.stderr.strip() if e.stderr else 'sin detalle'}"
    except Exception as e:
        return False, f"Error inesperado ejecutando 'mailq': {e}"

    salida = resultado.stdout.strip()

    # Sendmail/Postfix imprimen "Mail queue is empty" cuando no hay nada pendiente.
    if "is empty" in salida.lower() or not salida:
        return True, 0

    # Ambos MTAs terminan la salida con una línea resumen tipo:
    # "-- 12 Kbytes in 3 Requests."  (Sendmail)
    # o listan un bloque por mensaje separado por líneas en blanco (Postfix).
    # Buscamos primero el resumen de Sendmail; si no está, contamos bloques.
    for linea in salida.splitlines():
        if "Requests" in linea or "Request" in linea:
            partes = linea.replace("--", "").strip().split()
            for i, palabra in enumerate(partes):
                if palabra.isdigit() and i + 1 < len(partes) and "Request" in partes[i + 1]:
                    return True, int(palabra)

    # Fallback: contar bloques separados por línea en blanco (formato Postfix),
    # descontando la primera línea de encabezado.
    bloques = [b for b in salida.split("\n\n") if b.strip()]
    cantidad = max(len(bloques) - 1, 0)
    return True, cantidad


def verificar_cola():
    """
    Ejecuta una pasada de verificación: obtiene el tamaño de la cola y
    dispara alarma si supera el umbral. Devuelve la cantidad de alarmas
    emitidas (0 o 1).
    """
    conexion_db = obtener_conexion()

    ok, resultado = obtener_tamano_cola()
    if not ok:
        print(f"[-] No se pudo verificar la cola de correo: {resultado}", file=sys.stderr)
        if conexion_db is not None:
            conexion_db.close()
        return 0

    cantidad = resultado
    timestamp = datetime.now(timezone.utc)

    try:
        insertar_evento_raw(
            conexion_db,
            timestamp=timestamp,
            fuente="mailq",
            ip_origen=None,
            usuario=None,
            contenido_raw=f"tamano_cola={cantidad}",
            modulo=MODULO_NOMBRE,
        )
    except Exception as e:
        print(f"[!] Error normalizando evento de mailq a eventos_raw: {e}", file=sys.stderr)

    print(f"[.] Tamaño actual de la cola de correo: {cantidad} mensajes (umbral: {UMBRAL_COLA})")

    alarmas_emitidas = 0
    if cantidad >= UMBRAL_COLA:
        detalle = {
            "tamano_cola": cantidad,
            "umbral": UMBRAL_COLA,
            "origen": "tamano_cola_mailq",
        }
        try:
            insertar_alarma(
                conexion_db,
                timestamp=timestamp,
                tipo_alarma=TIPO_ALARMA,
                ip_origen="N/A",
                modulo=MODULO_NOMBRE,
                detalle=detalle,
            )
            print(f"[ALARMA] {TIPO_ALARMA} (cola alta) :: tamano={cantidad} umbral={UMBRAL_COLA}")
            alarmas_emitidas += 1
        except Exception as e:
            print(f"[-] Error insertando alarma de cola de correo: {e}", file=sys.stderr)

    if conexion_db is not None:
        conexion_db.close()

    return alarmas_emitidas


if __name__ == "__main__":
    try:
        total = verificar_cola()
        print(f"[+] Verificación completada. Alarmas emitidas: {total}")
        marcar_heartbeat(NOMBRE_DETECTOR, alarmas_emitidas=total, ok=True)
    except KeyboardInterrupt:
        print("\n[.] Verificación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error fatal en mail_queue_monitor: {e}", file=sys.stderr)
        marcar_heartbeat(NOMBRE_DETECTOR, alarmas_emitidas=0, ok=False)
        sys.exit(1)
