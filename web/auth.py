"""
Módulo de autenticación para M.A.R.A.N.D.U. Dashboard.

Maneja:
- Verificación de credenciales contra la tabla usuarios_web (bcrypt,
  comparación en tiempo constante).
- Sesiones basadas en cookie firmada (via Starlette SessionMiddleware).
- Tokens CSRF (patrón "synchronizer token" atado a la sesión).
- Rate limiting simple en memoria contra fuerza bruta en /login.

Requiere la variable de entorno:
- MARANDU_SECRET_KEY

Los usuarios ya NO se leen de variables de entorno: se guardan en la
tabla `usuarios_web` (ver db/models.py). Para dar de alta o resetear
la contraseña del primer admin, correr `python web/scripts/generar_hash.py`.
"""

import time
import secrets
import datetime
from typing import Dict, List, Optional

import bcrypt
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import UsuarioWeb

# bcrypt solo usa los primeros 72 bytes de la contraseña; versiones nuevas
# de la librería directamente lanzan ValueError si te pasás, en vez de
# truncar en silencio. Truncamos nosotros mismos de forma explícita.
_BCRYPT_MAX_BYTES = 72


def _prep(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prep(password), bcrypt.gensalt()).decode("utf-8")


def check_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prep(password), hashed.encode("utf-8"))
    except ValueError:
        # Hash con formato inválido/corrupto en la fila de la DB.
        return False


# Un hash "dummy" para gastar el mismo tiempo de cómputo aunque el usuario no
# exista en la tabla, y evitar que un atacante detecte usuarios válidos
# midiendo tiempos de respuesta.
_DUMMY_HASH = hash_password("marandu-dummy-password-para-timing-safety")


class NotAuthenticated(Exception):
    """Se lanza cuando una ruta protegida no tiene sesión válida."""
    pass


# --------------------------------------------------------------------------
# Rate limiting simple en memoria (por IP). Para producción multi-instancia
# conviene reemplazar esto por Redis, pero para un único proceso alcanza.
# --------------------------------------------------------------------------
_failed_attempts: Dict[str, List[float]] = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300      # ventana de conteo: 5 minutos
LOCKOUT_SECONDS = 900     # bloqueo: 15 minutos


def _client_ip(request: Request) -> str:
    # Si corrés detrás de un reverse proxy (Nginx/Caddy), configurá
    # ProxyHeadersMiddleware o similar para que request.client.host sea la IP real.
    return request.client.host if request.client else "unknown"


def is_locked_out(request: Request) -> bool:
    ip = _client_ip(request)
    now = time.time()
    attempts = [t for t in _failed_attempts.get(ip, []) if now - t < LOCKOUT_SECONDS]
    _failed_attempts[ip] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def register_failed_attempt(request: Request) -> None:
    ip = _client_ip(request)
    now = time.time()
    attempts = [t for t in _failed_attempts.get(ip, []) if now - t < WINDOW_SECONDS]
    attempts.append(now)
    _failed_attempts[ip] = attempts


def clear_attempts(request: Request) -> None:
    _failed_attempts.pop(_client_ip(request), None)


# --------------------------------------------------------------------------
# Credenciales (ahora contra la DB)
# --------------------------------------------------------------------------
async def verify_credentials(db: AsyncSession, username: str, password: str) -> Optional[UsuarioWeb]:
    """Verifica usuario/contraseña contra la tabla usuarios_web, en tiempo
    constante respecto a si el usuario existe. Devuelve la fila de
    UsuarioWeb si las credenciales son válidas, o None en caso contrario."""
    result = await db.execute(
        select(UsuarioWeb).where(UsuarioWeb.username == username)
    )
    user = result.scalar_one_or_none()

    if user is None:
        # Igual corremos el check contra un hash dummy para que el tiempo
        # de respuesta no filtre si el usuario existe.
        check_password(password, _DUMMY_HASH)
        return None

    if check_password(password, user.password_hash):
        return user

    return None


async def touch_last_login(db: AsyncSession, user: UsuarioWeb) -> None:
    """Actualiza ultimo_login y persiste. Se llama después de un login exitoso."""
    user.ultimo_login = datetime.datetime.utcnow()
    await db.commit()


# --------------------------------------------------------------------------
# Sesión / dependencia de autenticación
# --------------------------------------------------------------------------
def login_required(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise NotAuthenticated()
    return user


# --------------------------------------------------------------------------
# CSRF (synchronizer token pattern)
# --------------------------------------------------------------------------
def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, token: str) -> bool:
    real = request.session.get("csrf_token")
    return bool(real) and bool(token) and secrets.compare_digest(real, token)