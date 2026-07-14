#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/ddos_detector.py

Módulo viii: Ataques DDoS.

A diferencia de los demás módulos de detección, este no lee un archivo de
log -- captura tráfico de red en vivo con `tcpdump` (filtrado a consultas
DNS, puerto 53) y mide la tasa de consultas en una ventana deslizante.

Calibrado contra la muestra de ataque DNS que dio el profesor: ~4000
consultas/segundo tipo ANY al mismo dominio, desde múltiples IPs de origen
en una ráfaga de milisegundos -- un patrón muy por encima de tráfico DNS
legítimo, incluso bajo carga.

Requiere privilegios de root para que tcpdump pueda abrir un socket crudo
(correr con sudo, o vía systemd service con capabilities CAP_NET_RAW).

Incluye un modo de "reproducción" (--replay <archivo>) que corre el mismo
parser y lógica de umbral contra un archivo de captura de texto ya
existente (como el que dio el profesor), sin necesitar tcpdump en vivo --
útil para calibrar y probar sin tráfico de red real.
"""

import os
import re
import sys
import time
import datetime
import subprocess
import collections

from db_writer import obtener_conexion, insertar_evento_raw, insertar_alarma

MODULO_NOMBRE = "modulo_viii"
TIPO_ALARMA = "DDOS_DETECTADO"

# --------------------------------------------------------------------------
# Configuración
# --------------------------------------------------------------------------

INTERFAZ_RED = os.environ.get("MRND_DDOS_INTERFAZ", "any")

# Umbral de consultas DNS por segundo para considerar un ataque. Calibrado
# muy por debajo de los ~4000 q/s de la muestra real, pero por encima de
# tráfico DNS normal incluso con carga alta.
UMBRAL_QPS = int(os.environ.get("MRND_DDOS_UMBRAL_QPS", "100"))
VENTANA_QPS_SEGUNDOS = float(os.environ.get("MRND_DDOS_VENTANA_SEGUNDOS", "1.0"))

# Ventana más larga para evaluar si el ataque sigue vigente (debounce)
VENTANA_DEBOUNCE_SEGUNDOS = int(os.environ.get("MRND_DDOS_VENTANA_DEBOUNCE", "30"))


# --------------------------------------------------------------------------
# Parseo de líneas de tcpdump (formato de salida por defecto, sin -n forzado
# pero con IPs numéricas -- tal como en la muestra real del profesor):
# 11:00:14.627392 IP 121.217.184.207.38254 > 201.217.5.142.53: 1824+ [1au] ANY? doc.gov. (36)
# --------------------------------------------------------------------------

_PATRON_CONSULTA_DNS = re.compile(
    r'^(?P<hora>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<ip_origen>[\d.]+)\.(?P<puerto_origen>\d+)\s+>\s+'
    r'(?P<ip_destino>[\d.]+)\.(?P<puerto_destino>\d+|domain):\s+'
    r'(?P<txid>\d+)\+?\s+(?:\[1au\]\s+)?(?P<tipo_consulta>\S+)\?\s+'
    r'(?P<dominio>\S+)\s+\((?P<tamano>\d+)\)'
)


def parsear_linea_tcpdump(linea, fecha_referencia=None):
    """
    Parsea una línea de salida de tcpdump filtrada a consultas DNS.
    Devuelve un dict normalizado, o None si la línea no es una consulta DNS
    reconocible (tcpdump con este filtro puede igual mostrar líneas de
    control TCP que no nos interesan; se ignoran sin ser un error).
    """
    linea = linea.rstrip("\r\n")
    match = _PATRON_CONSULTA_DNS.match(linea)
    if not match:
        return None

    datos = match.groupdict()

    if fecha_referencia is None:
        fecha_referencia = datetime.datetime.now().date()

    try:
        hora_partes = datos["hora"].split(".")
        hora_base = datetime.datetime.strptime(hora_partes[0], "%H:%M:%S").time()
        microsegundos = int((hora_partes[1] + "000000")[:6]) if len(hora_partes) > 1 else 0
        timestamp = datetime.datetime.combine(fecha_referencia, hora_base).replace(microsecond=microsegundos)
    except (ValueError, IndexError) as e:
        print(f"[!] No se pudo parsear timestamp de tcpdump '{datos['hora']}': {e}", file=sys.stderr)
        return None

    return {
        "timestamp": timestamp,
        "ip_origen": datos["ip_origen"],
        "ip_destino": datos["ip_destino"],
        "tipo_consulta": datos["tipo_consulta"],
        "dominio": datos["dominio"],
        "linea_raw": linea,
    }


# --------------------------------------------------------------------------
# Medición de tasa de consultas (ventana corta para QPS, ventana larga para
# debounce de la alarma)
# --------------------------------------------------------------------------

class MedidorDeTasa:
    """
    Mantiene una lista de timestamps recientes y calcula la tasa de eventos
    por segundo dentro de una ventana corta configurable. Separado del
    debounce (que usa su propia ventana, más larga) para no confundir
    "¿está pasando ahora mismo?" con "¿ya avisé de esto?".
    """

    def __init__(self, ventana_qps_segundos, ventana_debounce_segundos):
        self.ventana_qps_segundos = ventana_qps_segundos
        self.ventana_debounce_segundos = ventana_debounce_segundos
        self._timestamps = collections.deque()
        self._en_alarma = False
        self._ultimo_timestamp_evento = None

    def registrar(self, timestamp):
        """
        Registra un evento y devuelve la tasa actual (eventos/segundo),
        calculada contra el tiempo real transcurrido entre el primer y
        último evento vigente en la ventana -- no contra el tamaño fijo
        de la ventana, que subestimaría ráfagas muy cortas y densas
        (ej: miles de consultas en pocos milisegundos).
        """
        self._timestamps.append(timestamp)
        self._ultimo_timestamp_evento = timestamp

        limite = timestamp - datetime.timedelta(seconds=self.ventana_qps_segundos)
        while self._timestamps and self._timestamps[0] < limite:
            self._timestamps.popleft()

        if len(self._timestamps) < 2:
            return 0.0

        span_segundos = (self._timestamps[-1] - self._timestamps[0]).total_seconds()
        span_segundos = max(span_segundos, 0.001)

        return len(self._timestamps) / span_segundos

    def debe_alarmar(self, tasa_actual, umbral_qps):
        """
        Debounce basado en tiempo: si ya está en alarma, no repite hasta
        que la tasa caiga por debajo del umbral. Una vez que cae, se
        "enfría" y puede volver a alarmar si el ataque se reactiva.
        """
        if tasa_actual < umbral_qps:
            self._en_alarma = False
            return False

        if self._en_alarma:
            return False

        self._en_alarma = True
        return True

    def ips_recientes(self, top_n=5):
        """Devuelve las IPs más frecuentes en la ventana actual (para el detalle de la alarma)."""
        return list(self._timestamps)[-top_n:]


# --------------------------------------------------------------------------
# Procesamiento de eventos
# --------------------------------------------------------------------------

def procesar_consulta_dns(evento, medidor, conteo_ips, conexion_db):
    """
    Procesa una consulta DNS ya parseada: la normaliza a eventos_raw,
    actualiza la tasa medida, y dispara DDOS_DETECTADO si supera el
    umbral configurado. Devuelve la cantidad de alarmas emitidas (0 o 1).
    """
    try:
        insertar_evento_raw(
            conexion_db,
            timestamp=evento["timestamp"],
            fuente="tcpdump_dns",
            ip_origen=evento["ip_origen"],
            usuario=None,
            contenido_raw=evento["linea_raw"],
            modulo=MODULO_NOMBRE,
        )
    except Exception as e:
        print(f"[!] Error normalizando consulta DNS a eventos_raw: {e}", file=sys.stderr)

    conteo_ips[evento["ip_origen"]] += 1

    alarmas_emitidas = 0
    try:
        tasa_actual = medidor.registrar(evento["timestamp"])
        if medidor.debe_alarmar(tasa_actual, UMBRAL_QPS):
            top_ips = sorted(conteo_ips.items(), key=lambda kv: kv[1], reverse=True)[:5]
            detalle = {
                "tasa_qps": round(tasa_actual, 1),
                "umbral_qps": UMBRAL_QPS,
                "dominio_consultado": evento["dominio"],
                "tipo_consulta": evento["tipo_consulta"],
                "ip_destino": evento["ip_destino"],
                "top_ips_origen": [{"ip": ip, "consultas": n} for ip, n in top_ips],
            }
            insertar_alarma(
                conexion_db,
                timestamp=evento["timestamp"],
                tipo_alarma=TIPO_ALARMA,
                ip_origen=top_ips[0][0] if top_ips else evento["ip_origen"],
                modulo=MODULO_NOMBRE,
                detalle=detalle,
            )
            print(f"[ALARMA] {TIPO_ALARMA} :: tasa={tasa_actual:.1f} q/s "
                  f"dominio={evento['dominio']} top_ip={top_ips[0][0] if top_ips else 'N/A'}")
            alarmas_emitidas += 1
    except Exception as e:
        print(f"[-] Error evaluando tasa de consultas DNS: {e}", file=sys.stderr)

    return alarmas_emitidas


# --------------------------------------------------------------------------
# Modo 1: reproducción de un archivo de captura ya existente (calibración,
# sin necesitar tcpdump en vivo)
# --------------------------------------------------------------------------

def reproducir_archivo(ruta_archivo, fecha_referencia=None):
    """
    Reproduce un archivo de texto con salida de tcpdump ya capturada
    (como la muestra que dio el profesor), línea por línea, a través de
    la misma lógica de detección que se usaría en vivo.
    """
    conexion_db = obtener_conexion()
    if conexion_db is None:
        print("[-] No se pudo conectar a la base de datos. Continuando sin persistir.", file=sys.stderr)

    medidor = MedidorDeTasa(VENTANA_QPS_SEGUNDOS, VENTANA_DEBOUNCE_SEGUNDOS)
    conteo_ips = collections.defaultdict(int)
    total_alarmas = 0
    total_lineas_matcheadas = 0

    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="replace") as f:
            for linea in f:
                evento = parsear_linea_tcpdump(linea, fecha_referencia)
                if evento is None:
                    continue
                total_lineas_matcheadas += 1
                total_alarmas += procesar_consulta_dns(evento, medidor, conteo_ips, conexion_db)
    except FileNotFoundError:
        print(f"[-] No se encontró el archivo {ruta_archivo}", file=sys.stderr)
        return 0

    print(f"[+] Líneas de consulta DNS matcheadas: {total_lineas_matcheadas}")
    print(f"[+] IPs de origen distintas vistas: {len(conteo_ips)}")
    print(f"[+] Alarmas {TIPO_ALARMA} emitidas: {total_alarmas}")

    if conexion_db is not None:
        conexion_db.close()

    return total_alarmas


# --------------------------------------------------------------------------
# Modo 2: captura en vivo con tcpdump (producción)
# --------------------------------------------------------------------------

def monitorear_en_vivo(duracion_segundos=None):
    """
    Lanza tcpdump como subproceso, filtrado a tráfico DNS (puerto 53), y
    procesa su salida línea por línea en tiempo real. Requiere privilegios
    para abrir un socket crudo (root, o systemd con CAP_NET_RAW).
    """
    conexion_db = obtener_conexion()
    if conexion_db is None:
        print("[-] No se pudo conectar a la base de datos. Continuando sin persistir.", file=sys.stderr)

    comando = ["tcpdump", "-l", "-n", "-i", INTERFAZ_RED, "udp", "port", "53"]

    try:
        proceso = subprocess.Popen(
            comando,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print("[-] 'tcpdump' no está instalado. Instalalo con: sudo dnf install -y tcpdump", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"[-] Error inesperado lanzando tcpdump: {e}", file=sys.stderr)
        return 0

    medidor = MedidorDeTasa(VENTANA_QPS_SEGUNDOS, VENTANA_DEBOUNCE_SEGUNDOS)
    conteo_ips = collections.defaultdict(int)
    total_alarmas = 0
    inicio = time.time()

    print(f"[+] Capturando tráfico DNS en interfaz '{INTERFAZ_RED}' "
          f"(umbral: {UMBRAL_QPS} consultas/seg)...")

    try:
        for linea in proceso.stdout:
            if duracion_segundos is not None and (time.time() - inicio) >= duracion_segundos:
                break

            evento = parsear_linea_tcpdump(linea)
            if evento is None:
                continue
            total_alarmas += procesar_consulta_dns(evento, medidor, conteo_ips, conexion_db)

    except KeyboardInterrupt:
        print("\n[.] Captura interrumpida por el usuario.")
    finally:
        proceso.terminate()
        try:
            proceso.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proceso.kill()
        if conexion_db is not None:
            conexion_db.close()

    print(f"[+] Fin de la captura. Alarmas emitidas: {total_alarmas}")
    return total_alarmas


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--replay":
        if len(sys.argv) < 3:
            print("Uso: python3 detection/ddos_detector.py --replay <archivo>", file=sys.stderr)
            sys.exit(1)
        reproducir_archivo(sys.argv[2])
    else:
        duracion = int(sys.argv[1]) if len(sys.argv) > 1 else None
        monitorear_en_vivo(duracion_segundos=duracion)
