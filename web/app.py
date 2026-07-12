import os
import sys
import secrets
import subprocess
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

# --------------------------------------------------------------------------
# Rutas basadas en __file__: funcionan sin importar desde qué carpeta
# ejecutes `uvicorn` (project root, dentro de web/, systemd, etc).
#
#   proyecto/
#   ├── web/          <- WEB_DIR (este archivo vive acá)
#   ├── prevention/
#   └── tests/
#   BASE_DIR = proyecto/
# --------------------------------------------------------------------------
WEB_DIR = Path(__file__).resolve().parent
BASE_DIR = WEB_DIR.parent

# Cargamos el .env que vive junto a este app.py.
load_dotenv(WEB_DIR / ".env")

# Para poder hacer `from tests.hardening_check import ...` sin importar
# desde dónde se invoque uvicorn.
sys.path.insert(0, str(BASE_DIR))

from tests.hardening_check import get_hardening_status  # noqa: E402
from auth import (  # noqa: E402
    NotAuthenticated,
    login_required,
    verify_credentials,
    get_csrf_token,
    verify_csrf,
    is_locked_out,
    register_failed_attempt,
    clear_attempts,
)

# --------------------------------------------------------------------------
# Configuración de seguridad de sesión
# --------------------------------------------------------------------------
SECRET_KEY = os.environ.get("MARANDU_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "Definí MARANDU_SECRET_KEY como variable de entorno "
        '(generala con: python -c "import secrets; print(secrets.token_hex(32))")'
    )

# En desarrollo local sin HTTPS podés poner MARANDU_COOKIE_SECURE=false.
# En producción DEBE quedar en true (requiere servir la app detrás de TLS).
COOKIE_SECURE = os.environ.get("MARANDU_COOKIE_SECURE", "true").lower() == "true"

app = FastAPI(title="M.A.R.A.N.D.U. Dashboard")

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="marandu_session",
    max_age=8 * 60 * 60,   # sesión expira a las 8 horas
    same_site="lax",
    https_only=COOKIE_SECURE,
)

templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))


@app.exception_handler(NotAuthenticated)
async def not_authenticated_handler(request: Request, exc: NotAuthenticated):
    return RedirectResponse(url="/login", status_code=303)


# --------------------------------------------------------------------------
# Headers de seguridad en todas las respuestas
# --------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'"
    )
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# Mapeo de controles hacia sus respectivos scripts de aplicación.
# Rutas absolutas: además de ser robustas ante el cwd, es lo que necesitás
# para restringir `sudo` a comandos exactos en /etc/sudoers.d (ver README).
PREVENTION_DIR = BASE_DIR / "prevention"
STRATEGY_SCRIPTS = {
    "ssh": str(PREVENTION_DIR / "ssh_hardening.py"),
    "rsyslog": str(PREVENTION_DIR / "rsyslog_centralization.py"),
    "banner": str(PREVENTION_DIR / "banner.py"),
    "selinux": str(PREVENTION_DIR / "selinux.py"),
    "firewall": str(PREVENTION_DIR / "firewall.py"),
    "pam_faillock": str(PREVENTION_DIR / "pam_faillock.py"),
    "sysctl": str(PREVENTION_DIR / "sysctl.py"),
    "auditd": str(PREVENTION_DIR / "auditd.py"),
    "pwquality": str(PREVENTION_DIR / "password_hardening.py"),
    "tmp": str(PREVENTION_DIR / "secure_tmp_mount.py"),
}

MAPPING_KEYS = {
    "SSH Hardening completo (root + puerto + clave)": "ssh",
    "rsyslog centralizado": "rsyslog",
    "Banner de login": "banner",
    "SELinux en modo Enforcing": "selinux",
    "firewalld zona restrictiva": "firewall",
    "pam_faillock bloqueo por intentos fallidos": "pam_faillock",
    "parámetros sysctl de red seguros": "sysctl",
    "auditd reglas de auditoría": "auditd",
    "Política de contraseñas (PAM pwquality)": "pwquality",
    "Montaje /tmp con noexec y nosuid": "tmp"
}


# --------------------------------------------------------------------------
# Login / logout
# --------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None, "csrf_token": get_csrf_token(request)},
    )


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        raise HTTPException(status_code=400, detail="Token CSRF inválido. Recargá la página.")

    if is_locked_out(request):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            status_code=429,
            context={
                "error": "Demasiados intentos fallidos. Esperá unos minutos antes de reintentar.",
                "csrf_token": get_csrf_token(request),
            },
        )

    if verify_credentials(username, password):
        clear_attempts(request)
        request.session.clear()
        request.session["user"] = username
        request.session["csrf_token"] = secrets.token_urlsafe(32)
        return RedirectResponse(url="/dashboard", status_code=303)

    register_failed_attempt(request)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        status_code=401,
        context={
            "error": "Usuario o contraseña incorrectos.",
            "csrf_token": get_csrf_token(request),
        },
    )


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


# --------------------------------------------------------------------------
# Dashboard (protegido)
# --------------------------------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard(request: Request, user: str = Depends(login_required)):
    raw_status = get_hardening_status()

    controls = []
    for description, active in raw_status.items():
        slug = MAPPING_KEYS.get(description, "unknown")
        controls.append({
            "id": slug,
            "description": description,
            "status": "COMPLIANT" if active else "VULNERABLE",
            "active": active
        })

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "controls": controls,
            "csrf_token": get_csrf_token(request),
            "user": user,
        }
    )


# --------------------------------------------------------------------------
# Aplicar hardening (protegido + CSRF)
# --------------------------------------------------------------------------
@app.post("/prevention/apply/{control_id}")
async def apply_hardening(control_id: str, request: Request, user: str = Depends(login_required)):
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not verify_csrf(request, csrf_header):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente.")

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