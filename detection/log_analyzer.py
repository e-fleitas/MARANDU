#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/log_analyzer.py

Módulo iv: Análisis de Logs y Errores Web.

Cubre 4 fuentes:
- access.log (formato "combined"): WEB_SCAN_404, WEB_EXPLOIT_500.
- /var/log/secure y /var/log/messages: FAILED_LOGIN_MULTIPLE (SSH + SASL).
- maillog (Sendmail): SMTP_BRUTE_FORCE (via deteccion nativa de Sendmail).

Decision de diseño: un solo loop que recorre las 4 fuentes en cada ciclo
de polling (en vez de threads separados por fuente) -- simplificacion
consciente dado el volumen de eventos de esta entrega academica.
"""

import os
import re
import sys
import time
import datetime
import collections

from log_tail import LogTail
from db_writer import obtener_conexion, insertar_evento_raw, insertar_alarma
from heartbeat import marcar_heartbeat
NOMBRE_DETECTOR = "log_analyzer"

MODULO_NOMBRE = "modulo_iv"

# --------------------------------------------------------------------------
# Configuración (prefijo MRND_ según convención de variables de entorno)
# --------------------------------------------------------------------------

RUTA_ACCESS_LOG = os.environ.get("MRND_ACCESS_LOG", "/var/log/nginx/marandu_access.log")
RUTA_SECURE_LOG = os.environ.get("MRND_SECURE_LOG", "/var/log/secure")
RUTA_MESSAGES_LOG = os.environ.get("MRND_MESSAGES_LOG", "/var/log/messages")
RUTA_MAILLOG = os.environ.get("MRND_MAILLOG", "/var/log/maillog")

UMBRAL_FAILED_LOGIN = int(os.environ.get("MRND_UMBRAL_FAILED_LOGIN", "5"))
VENTANA_FAILED_LOGIN_SEGUNDOS = int(os.environ.get("MRND_VENTANA_FAILED_LOGIN", "600"))  # 10 minutos

UMBRAL_USUARIOS_DISTINTOS = int(os.environ.get("MRND_UMBRAL_USUARIOS_DISTINTOS", "3"))
VENTANA_CREDENTIAL_STUFFING_SEGUNDOS = int(os.environ.get("MRND_VENTANA_CREDENTIAL_STUFFING", "300"))  # 5 minutos

UMBRAL_SMTP_ATTACK = int(os.environ.get("MRND_UMBRAL_SMTP_ATTACK", "5"))

UMBRAL_MAIL_MASIVO = int(os.environ.get("MRND_UMBRAL_MAIL_MASIVO", "20"))
VENTANA_MAIL_MASIVO_SEGUNDOS = int(os.environ.get("MRND_VENTANA_MAIL_MASIVO", "300"))  # 5 minutos

UMBRAL_404 = int(os.environ.get("MRND_UMBRAL_404", "50"))
VENTANA_404_SEGUNDOS = int(os.environ.get("MRND_VENTANA_404", "300"))  # 5 minutos

UMBRAL_500 = int(os.environ.get("MRND_UMBRAL_500", "10"))
VENTANA_500_SEGUNDOS = int(os.environ.get("MRND_VENTANA_500", "120"))  # 2 minutos

# Rutas consideradas sensibles (peso extra, según el documento de planificación)
_DEFAULT_RUTAS_SENSIBLES = ["/admin", "/.env", "/wp-login", "/phpMyAdmin"]


def _cargar_rutas_sensibles():
    rutas = list(_DEFAULT_RUTAS_SENSIBLES)
    raw_env = os.environ.get("MRND_RUTAS_SENSIBLES", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                rutas.append(item)
    return rutas


RUTAS_SENSIBLES = _cargar_rutas_sensibles()

# User-Agents de crawlers conocidos que no deben contar para el umbral de 404
_DEFAULT_UA_WHITELIST = ["Googlebot", "Bingbot"]


def _cargar_ua_whitelist():
    agentes = list(_DEFAULT_UA_WHITELIST)
    raw_env = os.environ.get("MRND_UA_WHITELIST", "")
    if raw_env:
        for item in raw_env.split(","):
            item = item.strip()
            if item:
                agentes.append(item)
    return agentes


UA_WHITELIST = _cargar_ua_whitelist()


# --------------------------------------------------------------------------
# Parseo de /var/log/secure y /var/log/messages
# Dos patrones distintos conviven en estos archivos:
#   1. SSH: "sshd[1234]: Failed password for invalid user X from IP port N ssh2"
#      (trae IP del atacante)
#   2. SASL/SMTP: "saslauthd[753]: ... auth failure: [user=X] ..." o
#      "pam_unix(smtp:auth): authentication failure; ... user=X" (sin IP)
# --------------------------------------------------------------------------

_PATRON_SSH_FAILED = re.compile(
    r'^(?P<mes_dia>\w+\s+\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'Failed password for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\S+) port \d+'
)

_PATRON_SASL_FAILURE = re.compile(
    r'^(?P<mes_dia>\w+\s+\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+\S+\s+saslauthd\[\d+\]:\s+'
    r'.*auth(?:entication)? failure.*?user=(?P<usuario>\S+?)(?:[\]\s;]|$)'
)

_FORMATO_TIMESTAMP_SYSLOG = "%b %d %H:%M:%S"


def _parsear_timestamp_syslog(mes_dia, hora, anio_referencia):
    """
    Los logs estilo syslog (secure/messages/maillog) no incluyen el año.
    Usamos el año actual como referencia -- suficiente para detección en
    vivo, que es el caso de uso real de este módulo.
    """
    try:
        texto = f"{mes_dia} {hora} {anio_referencia}"
        return datetime.datetime.strptime(texto, f"{_FORMATO_TIMESTAMP_SYSLOG} %Y")
    except ValueError as e:
        print(f"[!] No se pudo parsear timestamp syslog '{texto}': {e}", file=sys.stderr)
        return None


def parsear_linea_secure_messages(linea):
    """
    Intenta matchear una línea de /var/log/secure o /var/log/messages contra
    los dos patrones conocidos (SSH con IP, SASL sin IP). Devuelve un dict
    normalizado o None si no matchea ninguno (líneas de otro tipo son
    normales en estos archivos y no son un error).
    """
    anio_actual = datetime.datetime.now().year

    match_ssh = _PATRON_SSH_FAILED.match(linea)
    if match_ssh:
        datos = match_ssh.groupdict()
        timestamp = _parsear_timestamp_syslog(datos["mes_dia"], datos["hora"], anio_actual)
        if timestamp is None:
            return None
        return {
            "timestamp": timestamp,
            "usuario": datos["usuario"],
            "ip": datos["ip"],
            "tipo_evento": "ssh_failed_password",
            "linea_raw": linea,
        }

    match_sasl = _PATRON_SASL_FAILURE.match(linea)
    if match_sasl:
        datos = match_sasl.groupdict()
        timestamp = _parsear_timestamp_syslog(datos["mes_dia"], datos["hora"], anio_actual)
        if timestamp is None:
            return None
        return {
            "timestamp": timestamp,
            "usuario": datos["usuario"],
            "ip": None,  # SASL no expone IP en esta instalación; se correlaciona via maillog
            "tipo_evento": "sasl_auth_failure",
            "linea_raw": linea,
        }

    return None


# --------------------------------------------------------------------------
# Parseo de maillog (Sendmail)
# Dos patrones de interés:
#   1. Detección nativa de Sendmail de fuerza bruta SMTP, ya trae IP y conteo:
#      "sendmail[1915]: ID: host [IP]: possible SMTP attack: command=AUTH, count=N"
#   2. Envíos salientes exitosos, para detectar volumen masivo por remitente:
#      "sendmail[2548]: ID: from=<user@dominio>, size=N, ..."
# --------------------------------------------------------------------------

_PATRON_SMTP_ATTACK_NATIVO = re.compile(
    r'^(?P<mes_dia>\w+\s+\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+\S+\s+(?:sendmail\[\d+\]|postfix/\w+\[\d+\]):\s+'
    r'\S+:\s+\S+\s+\[(?P<ip>[\d.]+)\](?:\s+\(may be forged\))?:\s+'
    r'possible SMTP attack: command=(?P<comando>\S+), count=(?P<conteo>\d+)'
)

_PATRON_MAIL_FROM = re.compile(
    r'^(?P<mes_dia>\w+\s+\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+\S+\s+(?:sendmail\[\d+\]|postfix/\w+\[\d+\]):\s+'
    r'\S+:\s+from=<(?P<remitente>[^>]+)>'
)


def parsear_linea_maillog(linea):
    """
    Parsea una línea de maillog contra los 2 patrones conocidos. Devuelve
    un dict normalizado con 'tipo_evento' distinguiendo cuál matcheó, o
    None si la línea no es de interés para este módulo (maillog tiene
    muchas líneas de entrega normal que no necesitamos procesar).
    """
    anio_actual = datetime.datetime.now().year

    match_ataque = _PATRON_SMTP_ATTACK_NATIVO.match(linea)
    if match_ataque:
        datos = match_ataque.groupdict()
        timestamp = _parsear_timestamp_syslog(datos["mes_dia"], datos["hora"], anio_actual)
        if timestamp is None:
            return None
        return {
            "timestamp": timestamp,
            "ip": datos["ip"],
            "comando": datos["comando"],
            "conteo_nativo": int(datos["conteo"]),
            "tipo_evento": "smtp_attack_nativo",
            "linea_raw": linea,
        }

    match_from = _PATRON_MAIL_FROM.match(linea)
    if match_from:
        datos = match_from.groupdict()
        timestamp = _parsear_timestamp_syslog(datos["mes_dia"], datos["hora"], anio_actual)
        if timestamp is None:
            return None
        return {
            "timestamp": timestamp,
            "remitente": datos["remitente"],
            "tipo_evento": "mail_enviado",
            "linea_raw": linea,
        }

    return None


# --------------------------------------------------------------------------
# Parseo del formato "combined" real de Nginx en esta instalación:
# 127.0.0.1 - - [13/Jul/2026:18:07:44 -0400] "HEAD / HTTP/1.1" 404 0 "-" "curl/8.12.1"
# --------------------------------------------------------------------------

_PATRON_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<metodo>\S+)\s+(?P<ruta>\S+)\s+(?P<protocolo>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

_FORMATO_TIMESTAMP_NGINX = "%d/%b/%Y:%H:%M:%S %z"


def parsear_linea_access_log(linea):
    """
    Parsea una línea de access.log en formato "combined". Devuelve un dict
    con los campos extraídos, o None si la línea no matchea el patrón
    esperado (se registra para diagnóstico, pero no interrumpe el resto).
    """
    match = _PATRON_COMBINED.match(linea)
    if not match:
        print(f"[!] Línea de access.log no reconocida, se omite: {linea}", file=sys.stderr)
        return None

    datos = match.groupdict()

    try:
        timestamp = datetime.datetime.strptime(datos["timestamp"], _FORMATO_TIMESTAMP_NGINX)
    except ValueError as e:
        print(f"[!] Timestamp inválido en línea de access.log ({e}): {linea}", file=sys.stderr)
        return None

    try:
        status = int(datos["status"])
    except ValueError:
        print(f"[!] Código de estado HTTP inválido en línea: {linea}", file=sys.stderr)
        return None

    return {
        "ip": datos["ip"],
        "timestamp": timestamp,
        "metodo": datos["metodo"],
        "ruta": datos["ruta"],
        "status": status,
        "user_agent": datos["user_agent"],
        "linea_raw": linea,
    }


def _es_user_agent_whitelisted(user_agent):
    for agente in UA_WHITELIST:
        if agente.lower() in user_agent.lower():
            return True
    return False


def _es_ruta_sensible(ruta):
    return any(ruta.startswith(sensible) for sensible in RUTAS_SENSIBLES)


# --------------------------------------------------------------------------
# Ventanas deslizantes (por IP para 404/500, por usuario para failed login)
# --------------------------------------------------------------------------

class VentanaDeslizante:
    """
    Lleva, por clave (IP o usuario), una lista de timestamps de eventos
    dentro de una ventana de tiempo configurable, con debounce para no
    repetir alarma mientras la clave siga excedida.
    """

    def __init__(self, ventana_segundos):
        self.ventana_segundos = ventana_segundos
        self._eventos_por_ip = collections.defaultdict(list)
        self._ips_en_alarma = set()

    def registrar_y_contar(self, ip, timestamp):
        """
        Registra un evento para la clave dada y devuelve la cantidad de
        eventos vigentes en la ventana (incluyendo el que acaba de agregar).
        """
        limite = timestamp - datetime.timedelta(seconds=self.ventana_segundos)

        eventos = self._eventos_por_ip[ip]
        eventos.append(timestamp)

        eventos_vigentes = [t for t in eventos if t >= limite]
        self._eventos_por_ip[ip] = eventos_vigentes

        return len(eventos_vigentes)

    def debe_alarmar(self, ip, conteo, umbral):
        """
        Debounce: si la clave ya está marcada "en alarma", no vuelve a
        alarmar hasta que el conteo baje del umbral (se enfríe).
        """
        if conteo < umbral:
            self._ips_en_alarma.discard(ip)
            return False

        if ip in self._ips_en_alarma:
            return False

        self._ips_en_alarma.add(ip)
        return True


class VentanaUsuariosPorIP:
    """
    Lleva, por IP, la lista de (timestamp, usuario) de intentos de login
    fallidos dentro de una ventana de tiempo. A diferencia de
    VentanaDeslizante (que cuenta eventos), esta cuenta USUARIOS DISTINTOS
    intentados desde la misma IP -- la señal específica de credential
    stuffing (módulo x): un atacante probando múltiples cuentas desde un
    mismo origen, en vez de fuerza bruta contra una sola cuenta.
    """

    def __init__(self, ventana_segundos):
        self.ventana_segundos = ventana_segundos
        self._eventos_por_ip = collections.defaultdict(list)
        self._ips_en_alarma = set()

    def registrar_y_contar_usuarios(self, ip, usuario, timestamp):
        limite = timestamp - datetime.timedelta(seconds=self.ventana_segundos)

        eventos = self._eventos_por_ip[ip]
        eventos.append((timestamp, usuario))

        eventos_vigentes = [(t, u) for (t, u) in eventos if t >= limite]
        self._eventos_por_ip[ip] = eventos_vigentes

        usuarios_distintos = {u for _, u in eventos_vigentes}
        return len(usuarios_distintos), usuarios_distintos

    def debe_alarmar(self, ip, conteo, umbral):
        if conteo < umbral:
            self._ips_en_alarma.discard(ip)
            return False
        if ip in self._ips_en_alarma:
            return False
        self._ips_en_alarma.add(ip)
        return True


# --------------------------------------------------------------------------
# Procesamiento de access.log
# --------------------------------------------------------------------------

def procesar_linea(evento, ventana_404, ventana_500, conexion_db):
    """
    Procesa un evento ya parseado de access.log: lo normaliza a eventos_raw,
    y evalúa si dispara alguna alarma (WEB_SCAN_404 / WEB_EXPLOIT_500).
    Devuelve la cantidad de alarmas emitidas (0 o 1) para este evento.
    """
    alarmas_emitidas = 0

    try:
        insertar_evento_raw(
            conexion_db,
            timestamp=evento["timestamp"],
            fuente="access.log",
            ip_origen=evento["ip"],
            usuario=None,
            contenido_raw=evento["linea_raw"],
            modulo=MODULO_NOMBRE,
        )
    except Exception as e:
        print(f"[!] Error normalizando evento a eventos_raw: {e}", file=sys.stderr)

    try:
        if evento["status"] in (404, 403):
            if _es_user_agent_whitelisted(evento["user_agent"]):
                return 0

            conteo = ventana_404.registrar_y_contar(evento["ip"], evento["timestamp"])
            if ventana_404.debe_alarmar(evento["ip"], conteo, UMBRAL_404):
                detalle = {
                    "ip_origen": evento["ip"],
                    "conteo_ventana": conteo,
                    "umbral": UMBRAL_404,
                    "ventana_segundos": VENTANA_404_SEGUNDOS,
                    "ultima_ruta": evento["ruta"],
                    "ruta_sensible": _es_ruta_sensible(evento["ruta"]),
                    "user_agent": evento["user_agent"],
                }
                insertar_alarma(
                    conexion_db,
                    timestamp=evento["timestamp"],
                    tipo_alarma="WEB_SCAN_404",
                    ip_origen=evento["ip"],
                    modulo=MODULO_NOMBRE,
                    detalle=detalle,
                )
                print(f"[ALARMA] WEB_SCAN_404 :: ip={evento['ip']} conteo={conteo} ruta={evento['ruta']}")
                alarmas_emitidas += 1

        elif evento["status"] >= 500:
            conteo = ventana_500.registrar_y_contar(evento["ip"], evento["timestamp"])
            if ventana_500.debe_alarmar(evento["ip"], conteo, UMBRAL_500):
                detalle = {
                    "ip_origen": evento["ip"],
                    "conteo_ventana": conteo,
                    "umbral": UMBRAL_500,
                    "ventana_segundos": VENTANA_500_SEGUNDOS,
                    "ultima_ruta": evento["ruta"],
                    "user_agent": evento["user_agent"],
                }
                insertar_alarma(
                    conexion_db,
                    timestamp=evento["timestamp"],
                    tipo_alarma="WEB_EXPLOIT_500",
                    ip_origen=evento["ip"],
                    modulo=MODULO_NOMBRE,
                    detalle=detalle,
                )
                print(f"[ALARMA] WEB_EXPLOIT_500 :: ip={evento['ip']} conteo={conteo} ruta={evento['ruta']}")
                alarmas_emitidas += 1

    except Exception as e:
        print(f"[-] Error evaluando umbrales para evento {evento}: {e}", file=sys.stderr)

    return alarmas_emitidas


# --------------------------------------------------------------------------
# Procesamiento de secure/messages y maillog
# --------------------------------------------------------------------------

def procesar_linea_secure_messages(evento, ventana_failed_login, ventana_credential_stuffing, conexion_db, fuente):
    """
    Procesa un evento de Failed password (SSH) o auth failure (SASL).
    Dos alarmas posibles:
    1. FAILED_LOGIN_MULTIPLE: umbral de intentos fallidos por usuario.
    2. CREDENTIAL_STUFFING (modulo x): usuarios distintos desde la misma IP
       (solo SSH, que trae IP real -- SASL no expone IP).
    """
    try:
        insertar_evento_raw(
            conexion_db,
            timestamp=evento["timestamp"],
            fuente=fuente,
            ip_origen=evento["ip"],
            usuario=evento["usuario"],
            contenido_raw=evento["linea_raw"],
            modulo=MODULO_NOMBRE,
        )
    except Exception as e:
        print(f"[!] Error normalizando evento de {fuente} a eventos_raw: {e}", file=sys.stderr)

    alarmas_emitidas = 0

    try:
        conteo = ventana_failed_login.registrar_y_contar(evento["usuario"], evento["timestamp"])
        if ventana_failed_login.debe_alarmar(evento["usuario"], conteo, UMBRAL_FAILED_LOGIN):
            detalle = {
                "usuario": evento["usuario"],
                "ip_origen": evento["ip"],
                "conteo_ventana": conteo,
                "umbral": UMBRAL_FAILED_LOGIN,
                "ventana_segundos": VENTANA_FAILED_LOGIN_SEGUNDOS,
                "tipo_evento": evento["tipo_evento"],
                "fuente": fuente,
            }
            insertar_alarma(
                conexion_db,
                timestamp=evento["timestamp"],
                tipo_alarma="FAILED_LOGIN_MULTIPLE",
                ip_origen=evento["ip"] or "N/A",
                modulo=MODULO_NOMBRE,
                detalle=detalle,
            )
            print(f"[ALARMA] FAILED_LOGIN_MULTIPLE :: usuario={evento['usuario']} "
                  f"ip={evento['ip'] or 'N/A'} conteo={conteo} fuente={fuente}")
            alarmas_emitidas += 1
    except Exception as e:
        print(f"[-] Error evaluando umbral de failed login para {evento}: {e}", file=sys.stderr)

    if evento["ip"] is not None:
        try:
            conteo_usuarios, usuarios_distintos = ventana_credential_stuffing.registrar_y_contar_usuarios(
                evento["ip"], evento["usuario"], evento["timestamp"]
            )
            if ventana_credential_stuffing.debe_alarmar(evento["ip"], conteo_usuarios, UMBRAL_USUARIOS_DISTINTOS):
                detalle = {
                    "ip_origen": evento["ip"],
                    "usuarios_distintos": sorted(usuarios_distintos),
                    "conteo_usuarios_distintos": conteo_usuarios,
                    "umbral": UMBRAL_USUARIOS_DISTINTOS,
                    "ventana_segundos": VENTANA_CREDENTIAL_STUFFING_SEGUNDOS,
                    "fuente": fuente,
                }
                insertar_alarma(
                    conexion_db,
                    timestamp=evento["timestamp"],
                    tipo_alarma="CREDENTIAL_STUFFING",
                    ip_origen=evento["ip"],
                    modulo="modulo_x",
                    detalle=detalle,
                )
                print(f"[ALARMA] CREDENTIAL_STUFFING :: ip={evento['ip']} "
                      f"usuarios={sorted(usuarios_distintos)} conteo={conteo_usuarios}")
                alarmas_emitidas += 1
        except Exception as e:
            print(f"[-] Error evaluando credential stuffing para {evento}: {e}", file=sys.stderr)

    return alarmas_emitidas


def procesar_linea_maillog(evento, ventana_mail_masivo, conexion_db):
    """
    Procesa un evento de maillog. Dos casos:
    1. smtp_attack_nativo: Sendmail ya detectó y contó el ataque -- si su
       conteo supera nuestro umbral, generamos la alarma directamente
       (no hace falta ventana deslizante propia, Sendmail ya la hizo).
    2. mail_enviado: ventana deslizante por remitente -- dispara
       MAIL_QUEUE_ALTA (variante "envío masivo") si supera el umbral
       configurado (módulo v).
    """
    try:
        insertar_evento_raw(
            conexion_db,
            timestamp=evento["timestamp"],
            fuente="maillog",
            ip_origen=evento.get("ip"),
            usuario=evento.get("remitente"),
            contenido_raw=evento["linea_raw"],
            modulo=MODULO_NOMBRE,
        )
    except Exception as e:
        print(f"[!] Error normalizando evento de maillog a eventos_raw: {e}", file=sys.stderr)

    if evento["tipo_evento"] == "smtp_attack_nativo":
        try:
            if evento["conteo_nativo"] >= UMBRAL_SMTP_ATTACK:
                detalle = {
                    "ip_origen": evento["ip"],
                    "comando": evento["comando"],
                    "conteo_nativo_sendmail": evento["conteo_nativo"],
                    "umbral": UMBRAL_SMTP_ATTACK,
                }
                insertar_alarma(
                    conexion_db,
                    timestamp=evento["timestamp"],
                    tipo_alarma="SMTP_BRUTE_FORCE",
                    ip_origen=evento["ip"],
                    modulo=MODULO_NOMBRE,
                    detalle=detalle,
                )
                print(f"[ALARMA] SMTP_BRUTE_FORCE :: ip={evento['ip']} "
                      f"comando={evento['comando']} conteo={evento['conteo_nativo']}")
                return 1
        except Exception as e:
            print(f"[-] Error evaluando ataque SMTP nativo para {evento}: {e}", file=sys.stderr)

    elif evento["tipo_evento"] == "mail_enviado":
        try:
            remitente = evento["remitente"]
            conteo = ventana_mail_masivo.registrar_y_contar(remitente, evento["timestamp"])
            if ventana_mail_masivo.debe_alarmar(remitente, conteo, UMBRAL_MAIL_MASIVO):
                detalle = {
                    "remitente": remitente,
                    "conteo_ventana": conteo,
                    "umbral": UMBRAL_MAIL_MASIVO,
                    "ventana_segundos": VENTANA_MAIL_MASIVO_SEGUNDOS,
                    "origen": "envio_masivo_remitente",
                }
                insertar_alarma(
                    conexion_db,
                    timestamp=evento["timestamp"],
                    tipo_alarma="MAIL_QUEUE_ALTA",
                    ip_origen="N/A",
                    modulo=MODULO_NOMBRE,
                    detalle=detalle,
                )
                print(f"[ALARMA] MAIL_QUEUE_ALTA (envío masivo) :: remitente={remitente} conteo={conteo}")
                return 1
        except Exception as e:
            print(f"[-] Error evaluando envío masivo para {evento}: {e}", file=sys.stderr)

    return 0


# --------------------------------------------------------------------------
# Punto de entrada del módulo
# --------------------------------------------------------------------------

def monitorear_todas_las_fuentes(duracion_segundos=None):
    """
    Loop principal unificado: recorre access.log, secure, messages y
    maillog en cada ciclo de polling. Simplificación consciente respecto
    al diseño multi-thread original del documento de planificación --
    suficiente para el volumen de eventos de esta entrega, documentado
    como decisión de diseño.
    """
    conexion_db = obtener_conexion()
    if conexion_db is None:
        print(
            "[-] No se pudo conectar a la base de datos. "
            "El módulo va a seguir corriendo pero sin persistir nada.",
            file=sys.stderr,
        )

    tail_access = LogTail(RUTA_ACCESS_LOG, desde_el_final=True, poll_interval=1.0)
    tail_secure = LogTail(RUTA_SECURE_LOG, desde_el_final=True, poll_interval=1.0)
    tail_messages = LogTail(RUTA_MESSAGES_LOG, desde_el_final=True, poll_interval=1.0)
    tail_maillog = LogTail(RUTA_MAILLOG, desde_el_final=True, poll_interval=1.0)

    ventana_404 = VentanaDeslizante(VENTANA_404_SEGUNDOS)
    ventana_500 = VentanaDeslizante(VENTANA_500_SEGUNDOS)
    ventana_failed_login = VentanaDeslizante(VENTANA_FAILED_LOGIN_SEGUNDOS)
    ventana_credential_stuffing = VentanaUsuariosPorIP(VENTANA_CREDENTIAL_STUFFING_SEGUNDOS)
    ventana_mail_masivo = VentanaDeslizante(VENTANA_MAIL_MASIVO_SEGUNDOS)

    print(f"[+] Monitoreando access.log ({RUTA_ACCESS_LOG}), secure ({RUTA_SECURE_LOG}), "
          f"messages ({RUTA_MESSAGES_LOG}) y maillog ({RUTA_MAILLOG})...")

    inicio = time.time()
    total_alarmas = 0

    try:
        while duracion_segundos is None or (time.time() - inicio) < duracion_segundos:
            for linea in tail_access.leer_lineas():
                evento = parsear_linea_access_log(linea)
                if evento is not None:
                    total_alarmas += procesar_linea(evento, ventana_404, ventana_500, conexion_db)

            for linea in tail_secure.leer_lineas():
                evento = parsear_linea_secure_messages(linea)
                if evento is not None:
                    total_alarmas += procesar_linea_secure_messages(
                        evento, ventana_failed_login, ventana_credential_stuffing, conexion_db, "secure"
                    )

            for linea in tail_messages.leer_lineas():
                evento = parsear_linea_secure_messages(linea)
                if evento is not None:
                    total_alarmas += procesar_linea_secure_messages(
                        evento, ventana_failed_login, ventana_credential_stuffing, conexion_db, "messages"
                    )

            for linea in tail_maillog.leer_lineas():
                evento = parsear_linea_maillog(linea)
                if evento is not None:
                    total_alarmas += procesar_linea_maillog(evento, ventana_mail_masivo, conexion_db)

            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n[.] Monitoreo interrumpido por el usuario.")
    finally:
        tail_access.cerrar()
        tail_secure.cerrar()
        tail_messages.cerrar()
        tail_maillog.cerrar()
        if conexion_db is not None:
            conexion_db.close()

    print(f"[+] Fin del monitoreo. Alarmas emitidas: {total_alarmas}")
    return total_alarmas


if __name__ == "__main__":
    marcar_heartbeat(NOMBRE_DETECTOR, alarmas_emitidas=1, ok=True)
    duracion = int(sys.argv[1]) if len(sys.argv) > 1 else None
    monitorear_todas_las_fuentes(duracion_segundos=duracion)
