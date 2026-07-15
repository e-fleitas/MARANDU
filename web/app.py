import datetime
import os
import subprocess
from dotenv import load_dotenv
from pathlib import Path
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import psycopg2

# ==============================================================================
# 1. CONFIGURACIÓN DE RUTAS Y ENTORNO
# ==============================================================================
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

# Intérprete de Python del venv del proyecto. Los scripts de prevention/ se
# ejecutan con este binario (no con "python3" a secas) porque las reglas
# NOPASSWD de /etc/sudoers.d/marandu exigen la ruta absoluta exacta del venv
# -- sudo compara el comando resuelto contra el patrón de la regla, y
# "python3" resuelto vía $PATH normalmente apunta a /usr/bin/python3, que no
# matchea, causando que sudo caiga a modo interactivo (sin -n, esto puede
# colgar el proceso hasta el timeout en vez de fallar rápido).
VENV_PYTHON = str(BASE_DIR / "venv" / "bin" / "python3")

# Rutas físicas hacia los scripts de remediación
DB_AUTH_SCRIPT = str(BASE_DIR / "prevention" / "db_auth.py")

# ⚡ MAPEO DE TODOS LOS SCRIPTS DE HARDENING DE OS (Carpeta prevention/)
STRATEGY_SCRIPTS = {
    "ssh_hardening": str(BASE_DIR / "prevention" / "ssh_hardening.py"),
    "rsyslog_centralized": str(BASE_DIR / "prevention" / "rsyslog_centralization.py"),
    "banner_login": str(BASE_DIR / "prevention" / "banner.py"),
    "selinux_enforcing": str(BASE_DIR / "prevention" / "selinux.py"),
    "firewall_restrictive": str(BASE_DIR / "prevention" / "firewall.py"),
    "pam_faillock": str(BASE_DIR / "prevention" / "pam_faillock.py"),
    "sysctl_network": str(BASE_DIR / "prevention" / "sysctl.py"),
    "auditd_rules": str(BASE_DIR / "prevention" / "auditd.py"),
    "pam_pwquality": str(BASE_DIR / "prevention" / "password_hardening.py"),
    "tmp_mount": str(BASE_DIR / "prevention" / "secure_tmp_mount.py"),
}

# ⚡ Whitelist de usuarios del SO habilitados para ejecutar el hardening de DB
# vía sudo. Nunca se debe aceptar un usuario arbitrario proveniente del cliente:
# eso permitiría a cualquier sesión autenticada correr comandos como root
# (o como cualquier otro usuario con privilegios sudo) simplemente cambiando
# el campo "db_user" del request.
ALLOWED_DB_OS_USERS = {"postgres"}

# ==============================================================================
# 2. INICIALIZACIÓN DE LA APLICACIÓN Y MIDDLEWARES
# ==============================================================================
app = FastAPI(title="MARANDU HIPS")

SECRET_KEY = os.environ.get("MARANDU_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "Falta la variable de entorno MARANDU_SECRET_KEY.\n"
        "Generá una con `python -c \"import secrets; print(secrets.token_urlsafe(32))\"` "
        "y definila en tu archivo .env antes de levantar la app. "
        "No se permite un valor por defecto: una clave predecible permite forjar "
        "cookies de sesión válidas."
    )

# Por defecto exigimos HTTPS para la cookie de sesión. Solo se debe desactivar
# explícitamente en desarrollo local (MARANDU_COOKIE_SECURE=false).
COOKIE_SECURE = os.environ.get("MARANDU_COOKIE_SECURE", "true").lower() == "true"

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="marandu_session",
    https_only=COOKIE_SECURE,
    same_site="lax",
)

templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))

# ==============================================================================
# 3. IMPORTACIONES Y MAPEOS DEL PROYECTO
# ==============================================================================
from tests.db_hardening_check import get_db_hardening_status_dict
from tests.hardening_check import get_hardening_status as get_os_hardening_status

# Sesión de DB (para consultar usuarios_web en el login y alarmas/acciones en el dashboard)
from db.session import get_db
from db.models import Alarma, AccionPrevencion

# Nivel de respuesta automática por grupo de alarma (minimo/moderado/agresivo,
# con piso de seguridad que no se puede bajar desde acá; ver prevention/strategia.py)
from prevention.strategia import (
    NIVELES as NIVELES_ESTRATEGIA,
    PISO_NIVEL,
    piso_de,
    obtener_estrategia_activa,
    activar_estrategia,
)

# Etiquetas legibles para mostrar en el panel (las claves deben coincidir
# con las de PISO_NIVEL / ALARM_GRUPO en prevention/strategia.py).
GRUPO_ESTRATEGIA_LABELS = {
    "usuario_sospechoso": "Usuario sospechoso",
    "proceso_alto_consumo": "Proceso de alto consumo",
    "archivo_tmp_sospechoso": "Archivo sospechoso en /tmp",
    "web_scan_404": "Escaneo web (404 repetidos)",
    "web_exploit_500": "Posible exploit web (500)",
    "failed_login_multiple": "Múltiples logins fallidos",
    "smtp_brute_force": "Fuerza bruta SMTP",
    "mail_queue_alta": "Cola de correo alta",
    "ddos_detectado": "DDoS detectado",
}

# Mapeo tipo_alarma (tabla `alarmas`) -> grupo de estrategia, para poder
# contar alarmas pendientes por grupo en /api/estrategias.
#
# ⚠️ Esto es un espejo intencional de ALARM_GRUPO en
# prevention/mitigation_actions.py, NO un import de ese módulo: importarlo
# acá haría que el proceso web (corriendo como 'marandu', sin privilegios)
# ejecute el `logging.FileHandler("/var/log/hips/prevencion.log")` que ese
# módulo abre al cargarse — pensado para correr como root/scheduler, no
# desde el panel web. Si agregás un grupo de alarma nuevo, actualizá los
# dos lados (acá y en mitigation_actions.py).
ALARM_TIPO_TO_GRUPO = {
    "USUARIO_SOSPECHOSO": "usuario_sospechoso",
    "PROCESO_ALTO_CONSUMO": "proceso_alto_consumo",
    "ARCHIVO_TMP_SOSPECHOSO": "archivo_tmp_sospechoso",
    "WEB_SCAN_404": "web_scan_404",
    "WEB_EXPLOIT_500": "web_exploit_500",
    "FAILED_LOGIN_MULTIPLE": "failed_login_multiple",
    "SMTP_BRUTE_FORCE": "smtp_brute_force",
    "MAIL_QUEUE_ALTA": "mail_queue_alta",
    "DDOS_DETECTADO": "ddos_detectado",
}
GRUPO_A_TIPO_ALARMA = {grupo: tipo for tipo, grupo in ALARM_TIPO_TO_GRUPO.items()}

# Mapeo grupo de estrategia -> nombre_detector (id usado en el heartbeat,
# ver detection/heartbeat.py). El nombre debe ser exactamente el que cada
# script pasa a marcar_heartbeat(...) al terminar su pasada.
GRUPO_A_DETECTOR = {
    "usuario_sospechoso": "users_monitor",
    "proceso_alto_consumo": "process_monitor",
    "archivo_tmp_sospechoso": "tmp_monitor",
    "web_scan_404": "log_analyzer",
    "web_exploit_500": "log_analyzer",
    "failed_login_multiple": "log_analyzer",
    "smtp_brute_force": "log_analyzer",
    "mail_queue_alta": "mail_queue_monitor",
    "ddos_detectado": "ddos_detector",
}

# Los detectores corren por cron cada 2 minutos (120s). Si no hubo
# heartbeat en este umbral, lo mostramos como inactivo -- el margen extra
# sobre 120s absorbe jitter normal de cron sin tardar en avisar.
UMBRAL_DETECTOR_ACTIVO_SEGUNDOS = 150

from detection.heartbeat import leer_heartbeats


def _detector_activo(nombre_detector: str, heartbeats: dict) -> tuple[bool, str | None]:
    """Devuelve (activo, ultima_ejecucion_iso) para un detector dado el
    dict ya leído de leer_heartbeats(). 'activo' exige heartbeat reciente
    Y que la última pasada haya terminado sin excepción (ok=True)."""
    registro = heartbeats.get(nombre_detector)
    if not registro:
        return False, None

    ultima_ejecucion_iso = registro.get("ultima_ejecucion")
    if not ultima_ejecucion_iso:
        return False, None

    try:
        ultima_ejecucion = datetime.datetime.fromisoformat(ultima_ejecucion_iso)
    except ValueError:
        return False, None

    ahora = datetime.datetime.now(datetime.timezone.utc)
    antiguedad = (ahora - ultima_ejecucion).total_seconds()
    activo = antiguedad <= UMBRAL_DETECTOR_ACTIVO_SEGUNDOS and registro.get("ok", True)
    return activo, ultima_ejecucion_iso

# ⚡ Autenticación centralizada real (rate limiting, CSRF por sesión,
# comparación en tiempo constante, usuarios en DB). Ya no se reimplementa
# nada de esto acá.
from web.auth import (
    NotAuthenticated,
    verify_credentials,
    touch_last_login,
    is_locked_out,
    register_failed_attempt,
    clear_attempts,
    login_required as auth_login_required,
    get_csrf_token,
    verify_csrf,
)

MAPPING_KEYS = {
    "SSH Hardening completo (root + puerto + clave)": "ssh_hardening",
    "rsyslog centralizado": "rsyslog_centralized",
    "Banner de login": "banner_login",
    "SELinux en modo Enforcing": "selinux_enforcing",
    "firewalld zona restrictiva": "firewall_restrictive",
    "pam_faillock bloqueo por intentos fallidos": "pam_faillock",
    "parámetros sysctl de red seguros": "sysctl_network",
    "auditd reglas de auditoría": "auditd_rules",
    "Política de contraseñas (PAM pwquality)": "pam_pwquality",
    "Montaje /tmp con noexec y nosuid": "tmp_mount",
}

DB_MAPPING_KEYS = {
    "Cifrado TLS/SSL Activo (ssl=on)": "db_ssl",
    "Rol 'marandu_app' sin Superusuario": "db_role",
    "Registro de Auditoría (connections/disconnections)": "db_logging",
    "Control Restrictivo de Hosts (pg_hba.conf sin md5)": "db_hba",
    "Algoritmo de Hashing Seguro (scram-sha-256)": "db_auth",
    "Restricción de Privilegios Públicos en Schema Public": "db_public",
    "Extensión pgaudit Instalada y Configurada": "db_pgaudit",
}

# ==============================================================================
# 4. DEPENDENCIA DE CONTROL DE ACCESO
# ==============================================================================
def login_required(request: Request) -> str:
    try:
        return auth_login_required(request)
    except NotAuthenticated:
        raise HTTPException(status_code=401, detail="Sesión inválida o no autorizada.")


# ==============================================================================
# 5. ENDPOINTS DE AUTENTICACIÓN CENTRALIZADA
# ==============================================================================
@app.get("/login", response_class=HTMLResponse)
async def get_login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"csrf_token": get_csrf_token(request)},
    )


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    if not verify_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente.")

    if is_locked_out(request):
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos fallidos. Probá de nuevo en unos minutos.",
        )

    user = await verify_credentials(db, username, password)
    if user is not None:
        clear_attempts(request)
        request.session["user"] = user.username
        await touch_last_login(db, user)
        return RedirectResponse(url="/dashboard", status_code=303)

    register_failed_attempt(request)
    raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos.")


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


# ==============================================================================
# 6. ENDPOINTS DEL DASHBOARD Y REMEDIACIONES EN CALIENTE
# ==============================================================================
def _render_dashboard(
    request: Request,
    user: str,
    db_user: str = None,
    db_name: str = None,
    db_password: str = None,
):
    """Arma el contexto del dashboard. Compartido entre GET (sin credenciales)
    y POST (con credenciales de DB), para que la contraseña de Postgres nunca
    viaje como query string."""
    raw_status = get_os_hardening_status()
    controls = []
    for description, active in raw_status.items():
        slug = MAPPING_KEYS.get(description, "unknown")
        controls.append(
            {
                "id": slug,
                "description": description,
                "status": "COMPLIANT" if active else "VULNERABLE",
                "active": active,
            }
        )

    db_controls = []
    error_db = None
    necesita_credenciales = True

    if db_user and db_name and db_password:
        necesita_credenciales = False
        db_host = os.environ.get("MARANDU_DB_HOST", "127.0.0.1")
        db_port = os.environ.get("MARANDU_DB_PORT", "5432")

        try:
            conn = psycopg2.connect(
                host=db_host, port=db_port, user=db_user, dbname=db_name, password=db_password
            )
            conn.close()

            raw_db_status = get_db_hardening_status_dict(
                host=db_host, port=db_port, user=db_user, dbname=db_name, password=db_password
            )

            if not raw_db_status:
                raise Exception("La auditoría no retornó resultados. Verifica permisos de pgaudit.")

            for description, active in raw_db_status.items():
                slug = DB_MAPPING_KEYS.get(description, "unknown")
                db_controls.append(
                    {
                        "id": slug,
                        "description": description,
                        "status": "COMPLIANT" if active else "VULNERABLE",
                        "active": active,
                    }
                )

        except psycopg2.OperationalError:
            necesita_credenciales = True
            error_db = "Error de autenticación o conexión: Usuario o contraseña inválidos."
        except Exception as e:
            necesita_credenciales = True
            error_db = f"Fallo inesperado: {str(e)}"

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "controls": controls,
            "db_controls": db_controls,
            "db_user": db_user or "postgres",
            "db_name": db_name or "postgres",
            "necesita_credenciales": necesita_credenciales,
            "error_db": error_db,
            "csrf_token": get_csrf_token(request),
            "user": user,
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard(request: Request, user: str = Depends(login_required)):
    # El GET nunca lleva credenciales de DB: sólo renderiza el panel de OS
    # y el formulario para conectar a Postgres (que se envía por POST).
    return _render_dashboard(request, user)


@app.post("/dashboard", response_class=HTMLResponse)
async def read_dashboard_with_db(
    request: Request,
    db_user: str = Form(...),
    db_name: str = Form(...),
    db_password: str = Form(...),
    csrf_token: str = Form(...),
    user: str = Depends(login_required),
):
    if not verify_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente.")
    return _render_dashboard(request, user, db_user, db_name, db_password)


# ==============================================================================
# 6.5 ENDPOINT DE ALARMAS Y ACCIONES DE MITIGACIÓN (solo lectura)
# ==============================================================================
def _serializar_alarma(alarma: Alarma, incluir_acciones: bool = False) -> dict:
    data = {
        "id": alarma.id,
        "timestamp": alarma.timestamp.isoformat() if alarma.timestamp else None,
        "tipo_alarma": alarma.tipo_alarma,
        "ip_origen": alarma.ip_origen,
        "modulo": alarma.modulo,
        "detalle": alarma.detalle,
    }
    if incluir_acciones:
        acciones_ordenadas = sorted(
            alarma.acciones, key=lambda a: a.timestamp or datetime.datetime.min
        )
        data["acciones"] = [
            {
                "accion": accion.accion,
                "resultado": accion.resultado,
                "timestamp": accion.timestamp.isoformat() if accion.timestamp else None,
            }
            for accion in acciones_ordenadas
        ]
    return data


@app.get("/api/alarmas")
async def api_alarmas(
    request: Request,
    user: str = Depends(login_required),
    db: AsyncSession = Depends(get_db),
    limite_resueltas: int = 50,
    tipo_alarma: str | None = None,
):
    """
    Endpoint de solo lectura (GET, sin CSRF porque no cambia estado) que
    alimenta la sección de "Alarmas y Mitigaciones" del dashboard:
      - pendientes: alarmas con resuelta=False (ordenadas más reciente primero).
      - resueltas: últimas N alarmas con resuelta=True, cada una con sus
        acciones de prevención asociadas (tabla acciones_prevencion), para
        mostrar qué se hizo y con qué resultado.

    Si se pasa `tipo_alarma`, filtra ambas listas a ese tipo únicamente
    (usado por el botón "Ver detalle" de la tabla de niveles de reacción).
    """
    stmt_pendientes = select(Alarma).where(Alarma.resuelta.is_(False))
    if tipo_alarma:
        stmt_pendientes = stmt_pendientes.where(Alarma.tipo_alarma == tipo_alarma)
    stmt_pendientes = stmt_pendientes.order_by(Alarma.timestamp.desc())
    pendientes = (await db.execute(stmt_pendientes)).scalars().all()

    stmt_resueltas = select(Alarma).where(Alarma.resuelta.is_(True))
    if tipo_alarma:
        stmt_resueltas = stmt_resueltas.where(Alarma.tipo_alarma == tipo_alarma)
    stmt_resueltas = (
        stmt_resueltas
        .options(selectinload(Alarma.acciones))
        .order_by(Alarma.timestamp.desc())
        .limit(max(1, min(limite_resueltas, 200)))
    )
    resueltas = (await db.execute(stmt_resueltas)).scalars().all()

    return {
        "pendientes": [_serializar_alarma(a) for a in pendientes],
        "resueltas": [_serializar_alarma(a, incluir_acciones=True) for a in resueltas],
    }


@app.get("/api/estrategias")
async def api_estrategias(
    request: Request,
    user: str = Depends(login_required),
    db: AsyncSession = Depends(get_db),
):
    """Estado actual (nivel configurado + piso de seguridad) de cada grupo
    de alarma, más la cantidad de alarmas pendientes de ese grupo, para
    poblar la tabla unificada de "Alarmas y Respuesta" del panel."""
    stmt_conteo = (
        select(Alarma.tipo_alarma, func.count(Alarma.id))
        .where(Alarma.resuelta.is_(False))
        .group_by(Alarma.tipo_alarma)
    )
    conteo_por_grupo: dict[str, int] = {}
    for tipo_alarma, cantidad in (await db.execute(stmt_conteo)).all():
        grupo_de_tipo = ALARM_TIPO_TO_GRUPO.get(tipo_alarma)
        if grupo_de_tipo:
            conteo_por_grupo[grupo_de_tipo] = conteo_por_grupo.get(grupo_de_tipo, 0) + cantidad

    heartbeats = leer_heartbeats()

    resultado = []
    for grupo, piso in PISO_NIVEL.items():
        nivel_actual = await obtener_estrategia_activa(db, grupo)
        nombre_detector = GRUPO_A_DETECTOR.get(grupo)
        detector_activo, detector_ultima_ejecucion = (
            _detector_activo(nombre_detector, heartbeats) if nombre_detector else (False, None)
        )
        resultado.append({
            "grupo": grupo,
            "etiqueta": GRUPO_ESTRATEGIA_LABELS.get(grupo, grupo),
            "tipo_alarma": GRUPO_A_TIPO_ALARMA.get(grupo),
            "nivel_actual": nivel_actual,
            "piso": piso,
            "niveles": list(NIVELES_ESTRATEGIA),
            "alarmas_pendientes": conteo_por_grupo.get(grupo, 0),
            "detector": nombre_detector,
            "detector_activo": detector_activo,
            "detector_ultima_ejecucion": detector_ultima_ejecucion,
        })
    return {"estrategias": resultado}


@app.post("/api/estrategias/{grupo}")
async def api_cambiar_estrategia(
    grupo: str,
    request: Request,
    user: str = Depends(login_required),
    db: AsyncSession = Depends(get_db),
):
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not verify_csrf(request, csrf_header):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente.")

    if grupo not in PISO_NIVEL:
        raise HTTPException(status_code=404, detail="Grupo de estrategia desconocido.")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Body inválido: se espera JSON con {'nivel': ...}.")

    nivel = body.get("nivel")
    if nivel not in NIVELES_ESTRATEGIA:
        raise HTTPException(status_code=400, detail=f"Nivel inválido: {nivel!r}.")

    # Chequeamos el piso ACÁ, antes de llamar a activar_estrategia, para
    # poder distinguir el motivo real de un rechazo: activar_estrategia
    # devuelve False tanto si el nivel pedido está por debajo del piso
    # como si simplemente no existe la fila (modulo, parametro) en la
    # tabla (ej. porque nunca se corrió el seed para ese grupo). Sin este
    # chequeo previo, ambos casos se ven idénticos desde afuera.
    piso = piso_de(grupo)
    if NIVELES_ESTRATEGIA.index(nivel) < NIVELES_ESTRATEGIA.index(piso):
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{nivel}' está por debajo del piso de seguridad de este grupo "
                f"('{piso}'). No se puede bajar de ahí."
            ),
        )

    exito = await activar_estrategia(db, grupo, nivel)
    if not exito:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No se pudo activar '{nivel}' para '{grupo}'. Esto normalmente significa "
                f"que falta la fila correspondiente en 'configuracion_modulos' (la tabla no "
                f"se sembró para este grupo/nivel). Corré 'python -m db.seed_config' desde "
                f"el venv y volvé a intentar."
            ),
        )

    return {"status": "success", "grupo": grupo, "nivel": nivel}


@app.post("/prevention/apply/{control_id}")
async def apply_hardening(control_id: str, request: Request, user: str = Depends(login_required)):
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not verify_csrf(request, csrf_header):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente.")

    req_db_user = "postgres"
    req_db_name = "postgres"

    if request.headers.get("content-type") == "application/json":
        try:
            body = await request.json()
            req_db_user = body.get("db_user", "postgres")
            req_db_name = body.get("db_name", "postgres")
        except Exception:
            pass

    # A. INTERCEPCIÓN PARA MEDIDAS POSTGRESQL
    if control_id in DB_MAPPING_KEYS.values():
        # ⚡ Nunca confiar en el usuario del SO que manda el cliente: sólo se
        # permite ejecutar el hardening con el usuario esperado. Aceptar un
        # valor arbitrario acá permitiría escalar privilegios vía
        # `sudo -i -u <lo-que-mande-el-cliente>`.
        if req_db_user not in ALLOWED_DB_OS_USERS:
            raise HTTPException(
                status_code=400,
                detail=f"Usuario de sistema '{req_db_user}' no permitido para esta operación.",
            )

        app_db_password = os.environ.get("MARANDU_DB_APP_PASSWORD")
        if not app_db_password:
            raise HTTPException(
                status_code=500,
                detail="Falta configurar MARANDU_DB_APP_PASSWORD en el archivo .env web.",
            )

        # El orden de los flags debe coincidir literalmente con la regla de
        # sudoers ("... db_auth.py -p * -d * -u *"): sudo hace matching de
        # string sobre la línea de comando completa, no parseo de argumentos,
        # así que "-p -u -d" no matchea aunque sea semánticamente equivalente.
        cmd = ["sudo", "-n", VENV_PYTHON, DB_AUTH_SCRIPT, "-p", app_db_password, "-d", req_db_name, "-u", req_db_user]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
            return {
                "status": "success",
                "message": f"Hardening general aplicado exitosamente en DB '{req_db_name}' con usuario admin '{req_db_user}'.",
                "output": result.stdout,
            }
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Error al aplicar hardening en DB: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="El script de hardening de DB superó el tiempo límite.")

    # B. FLUJO PARA MEDIDAS DEL SISTEMA OPERATIVO
    if control_id not in STRATEGY_SCRIPTS:
        raise HTTPException(status_code=400, detail="Estrategia de hardening inválida.")

    script_path = STRATEGY_SCRIPTS[control_id]
    try:
        result = subprocess.run(
            ["sudo", "-n", VENV_PYTHON, script_path],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        return {"status": "success", "message": f"Control {control_id} aplicado.", "output": result.stdout}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al aplicar hardening: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail=f"El script para '{control_id}' superó el tiempo límite.")