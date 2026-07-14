#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/sniffer_detect.py

Módulo iii: Sniffers y modo promiscuo.
Detecta dos señales relacionadas:
1. Interfaces de red en modo promiscuo (flag PROMISC en `ip link show`).
2. Procesos de herramientas de captura de paquetes en ejecución
   (tcpdump, wireshark, tshark, dumpcap, ethereal, ettercap).

Cualquiera de las dos dispara SNIFFER_DETECTADO -- el módulo de
prevención de Julián puede usar el `detalle` para decidir si desactivar
el modo promiscuo (`ip link set <iface> promisc off`) o matar el proceso.
"""

import os
import sys
import subprocess
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    print(
        "[-] La librería 'psutil' no está instalada. Instalala con: "
        "pip3 install --user psutil",
        file=sys.stderr,
    )
    psutil = None

from db_writer import obtener_conexion, insertar_alarma, insertar_evento_raw

MODULO_NOMBRE = "modulo_iii"
TIPO_ALARMA = "SNIFFER_DETECTADO"

# Interfaces que legítimamente pueden estar en modo promiscuo por diseño
# (bridges virtuales de Docker/libvirt, loopback) y no deben alarmar.
_DEFAULT_INTERFACES_IGNORADAS = ["lo", "virbr0", "docker0"]

# Nombres de procesos de herramientas de captura conocidas
_DEFAULT_PROCESOS_SNIFFER = ["tcpdump", "wireshark", "tshark", "dumpcap", "ethereal", "ettercap"]


def _cargar_interfaces_ignoradas():
    ifaces = list(_DEFAULT_INTERFACES_IGNORADAS)
    raw_env = os.environ.get("MRND_SNIFFER_IFACES_IGNORADAS", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                ifaces.append(item)
    return ifaces


def _cargar_procesos_sniffer():
    procesos = list(_DEFAULT_PROCESOS_SNIFFER)
    raw_env = os.environ.get("MRND_SNIFFER_PROCESOS", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                procesos.append(item)
    return procesos


INTERFACES_IGNORADAS = _cargar_interfaces_ignoradas()
PROCESOS_SNIFFER_CONOCIDOS = _cargar_procesos_sniffer()


# --------------------------------------------------------------------------
# Señal 1: interfaces en modo promiscuo
# --------------------------------------------------------------------------

def obtener_interfaces_promiscuas():
    """
    Corre `ip link show` y devuelve la lista de interfaces (no ignoradas)
    que tienen el flag PROMISC activo. Nunca lanza excepción: si el
    comando falla, devuelve lista vacía y registra el error.
    """
    try:
        resultado = subprocess.run(
            ["ip", "link", "show"],
            shell=False,
            check=True,
            text=True,
            capture_output=True,
            timeout=5,
        )
    except FileNotFoundError:
        print("[-] Comando 'ip' no encontrado.", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print("[-] Timeout ejecutando 'ip link show'.", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print(f"[-] Error ejecutando 'ip link show': {e.stderr.strip() if e.stderr else e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[-] Error inesperado ejecutando 'ip link show': {e}", file=sys.stderr)
        return []

    interfaces_promiscuas = []
    interfaz_actual = None

    for linea in resultado.stdout.splitlines():
        # Líneas de interfaz nueva empiezan con un número: "2: eth0: <FLAGS> ..."
        if linea and linea[0].isdigit():
            try:
                interfaz_actual = linea.split(":")[1].strip().split("@")[0]
            except (IndexError, ValueError):
                interfaz_actual = None
                continue

            if "PROMISC" in linea and interfaz_actual not in INTERFACES_IGNORADAS:
                interfaces_promiscuas.append(interfaz_actual)

    return interfaces_promiscuas


# --------------------------------------------------------------------------
# Señal 2: procesos de captura de paquetes en ejecución
# --------------------------------------------------------------------------

def obtener_procesos_sniffer_activos():
    """
    Recorre los procesos activos y devuelve los que coincidan con nombres
    de herramientas de captura conocidas. Devuelve lista de dicts
    {pid, nombre, usuario}. Nunca lanza excepción.
    """
    if psutil is None:
        print("[-] No se puede verificar procesos sniffer sin psutil instalado.", file=sys.stderr)
        return []

    procesos_encontrados = []
    try:
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                info = proc.info
                nombre = (info.get("name") or "").lower()
                if nombre in PROCESOS_SNIFFER_CONOCIDOS:
                    procesos_encontrados.append({
                        "pid": info.get("pid"),
                        "nombre": info.get("name"),
                        "usuario": info.get("username") or "desconocido",
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                print(f"[!] Error leyendo proceso individual: {e}", file=sys.stderr)
                continue
    except Exception as e:
        print(f"[-] Error inesperado iterando procesos del sistema: {e}", file=sys.stderr)
        return []

    return procesos_encontrados


# --------------------------------------------------------------------------
# Punto de entrada del módulo
# --------------------------------------------------------------------------

def verificar_sniffers():
    """
    Ejecuta una pasada de verificación de ambas señales (interfaces
    promiscuas y procesos sniffer). Devuelve la cantidad de alarmas
    emitidas.
    """
    conexion_db = obtener_conexion()
    timestamp = datetime.now(timezone.utc)
    alarmas_emitidas = 0

    interfaces_promiscuas = obtener_interfaces_promiscuas()
    procesos_sniffer = obtener_procesos_sniffer_activos()

    try:
        insertar_evento_raw(
            conexion_db,
            timestamp=timestamp,
            fuente="ip_link_show",
            ip_origen=None,
            usuario=None,
            contenido_raw=f"interfaces_promiscuas={interfaces_promiscuas}",
            modulo=MODULO_NOMBRE,
        )
    except Exception as e:
        print(f"[!] Error normalizando estado de interfaces a eventos_raw: {e}", file=sys.stderr)

    for iface in interfaces_promiscuas:
        detalle = {
            "interfaz": iface,
            "origen_deteccion": "modo_promiscuo",
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
            print(f"[ALARMA] {TIPO_ALARMA} :: interfaz={iface} en modo promiscuo")
            alarmas_emitidas += 1
        except Exception as e:
            print(f"[-] Error insertando alarma de interfaz promiscua: {e}", file=sys.stderr)

    for proceso in procesos_sniffer:
        try:
            insertar_evento_raw(
                conexion_db,
                timestamp=timestamp,
                fuente="psutil_procesos",
                ip_origen=None,
                usuario=proceso["usuario"],
                contenido_raw=f"pid={proceso['pid']} nombre={proceso['nombre']}",
                modulo=MODULO_NOMBRE,
            )
        except Exception as e:
            print(f"[!] Error normalizando proceso sniffer a eventos_raw: {e}", file=sys.stderr)

        detalle = {
            "pid": proceso["pid"],
            "nombre_proceso": proceso["nombre"],
            "usuario": proceso["usuario"],
            "origen_deteccion": "proceso_sniffer_activo",
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
            print(f"[ALARMA] {TIPO_ALARMA} :: proceso={proceso['nombre']} pid={proceso['pid']} "
                  f"usuario={proceso['usuario']}")
            alarmas_emitidas += 1
        except Exception as e:
            print(f"[-] Error insertando alarma de proceso sniffer: {e}", file=sys.stderr)

    if not interfaces_promiscuas and not procesos_sniffer:
        print("[.] Sin interfaces en modo promiscuo ni procesos sniffer activos.")

    if conexion_db is not None:
        conexion_db.close()

    return alarmas_emitidas


if __name__ == "__main__":
    try:
        total = verificar_sniffers()
        print(f"[+] Verificación completada. Alarmas emitidas: {total}")
    except KeyboardInterrupt:
        print("\n[.] Verificación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error fatal en sniffer_detect: {e}", file=sys.stderr)
        sys.exit(1)
