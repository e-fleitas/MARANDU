import os
import subprocess
from dotenv import load_dotenv
from pathlib import Path
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import psycopg2

# ==============================================================================
# 1. CONFIGURACIÓN DE RUTAS Y ENTORNO
# ==============================================================================
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

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

# ⚡ Autenticación centralizada real (rate limiting, CSRF por sesión,
# comparación en tiempo constante). Ya no se reimplementa nada de esto acá.
from web.auth import (
    NotAuthenticated,
    verify_credentials,
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
):
    if not verify_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente.")

    if is_locked_out(request):
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos fallidos. Probá de nuevo en unos minutos.",
        )

    if verify_credentials(username, password):
        clear_attempts(request)
        request.session["user"] = username
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

        cmd = ["sudo", "python3", DB_AUTH_SCRIPT, "-p", app_db_password, "-u", req_db_user, "-d", req_db_name]
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
            ["sudo", "python3", script_path],
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