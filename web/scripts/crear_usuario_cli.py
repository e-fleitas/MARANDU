"""
Crea un usuario en la tabla usuarios_web. Requiere:

1. Correr el script como root (no alcanza con un usuario cualquiera con sudo
   a otro comando: se exige euid == 0 explícitamente).
2. Conocer la frase secreta maestra, verificada contra el hash guardado en
   /etc/marandu/create_user.secret (ver web/scripts/setup_secreto_maestro.py).

Ningún dato sensible (usuario, contraseña, secreto) se acepta como argumento
de línea de comandos: todo se pide de forma interactiva con input oculto,
para no dejar rastro en `ps aux` ni en el historial de bash.

Uso:
    sudo python3 web/scripts/crear_usuario_cli.py
"""
import datetime
import getpass
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# sudo no hereda el entorno del usuario que invoca (ni el .env que la app
# carga normalmente), así que hay que cargarlo explícitamente acá. Sin
# esto, db/session.py cae al DATABASE_URL por defecto con el placeholder
# de contraseña y falla la autenticación contra Postgres.
from dotenv import load_dotenv
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
load_dotenv(dotenv_path=os.path.join(_BASE_DIR, ".env"))

import asyncio
from sqlalchemy import select

from db.session import async_session
from db.models import UsuarioWeb
from web.auth import hash_password, check_password

SECRET_FILE = "/etc/marandu/create_user.secret"
AUDIT_LOG = "/var/log/marandu/creacion_usuarios.log"

_BCRYPT_MAX_BYTES = 72
MAX_INTENTOS_SECRETO = 3


def _log_auditoria(mensaje: str) -> None:
    """Registra la acción en un log de auditoría. No falla el script si el
    log no se puede escribir (ej. directorio no creado); solo avisa."""
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), mode=0o750, exist_ok=True)
        quien = os.environ.get("SUDO_USER", "desconocido")
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(AUDIT_LOG, "a") as f:
            f.write(f"[{timestamp}] (invocado por sudo_user={quien}) {mensaje}\n")
    except Exception as e:
        print(f"⚠️  No se pudo escribir en el log de auditoría: {e}")


def _verificar_root() -> None:
    if os.geteuid() != 0:
        print("❌ Este script debe correrse como root: sudo python3 web/scripts/crear_usuario_cli.py")
        sys.exit(1)


def _leer_hash_secreto() -> str:
    if not os.path.exists(SECRET_FILE):
        print(f"❌ No existe {SECRET_FILE}.")
        print("   Corré primero: sudo python3 web/scripts/setup_secreto_maestro.py")
        sys.exit(1)

    st = os.stat(SECRET_FILE)
    if st.st_uid != 0 or (st.st_mode & 0o077):
        print(f"❌ {SECRET_FILE} tiene permisos inseguros (debe ser 600, dueño root).")
        print(f"   Corregí con: sudo chown root:root {SECRET_FILE} && sudo chmod 600 {SECRET_FILE}")
        sys.exit(1)

    with open(SECRET_FILE, "r") as f:
        return f.read().strip()


def _verificar_secreto(hash_guardado: str) -> bool:
    for intento in range(1, MAX_INTENTOS_SECRETO + 1):
        secreto = getpass.getpass("Frase secreta maestra: ")
        if check_password(secreto, hash_guardado):
            return True
        restantes = MAX_INTENTOS_SECRETO - intento
        if restantes > 0:
            print(f"❌ Frase incorrecta. Intentos restantes: {restantes}")
            time.sleep(2)  # pequeña demora para dificultar fuerza bruta interactiva
    return False


async def _upsert_usuario(username: str, password_hash: str, rol: str) -> bool:
    async with async_session() as session:
        result = await session.execute(
            select(UsuarioWeb).where(UsuarioWeb.username == username)
        )
        user = result.scalar_one_or_none()

        if user is None:
            user = UsuarioWeb(username=username, password_hash=password_hash, rol=rol)
            session.add(user)
            await session.commit()
            return True
        else:
            user.password_hash = password_hash
            user.rol = rol
            await session.commit()
            return False


async def main():
    _verificar_root()
    hash_guardado = _leer_hash_secreto()

    if not _verificar_secreto(hash_guardado):
        print("❌ Demasiados intentos fallidos. Abortando.")
        _log_auditoria("INTENTO FALLIDO: frase secreta incorrecta (máximo de intentos alcanzado).")
        sys.exit(1)

    print("✅ Frase secreta verificada.\n")

    username = input("Nombre de usuario a crear/actualizar: ").strip()
    if not username:
        print("❌ El nombre de usuario no puede estar vacío.")
        return

    password = getpass.getpass("Contraseña: ")
    confirm = getpass.getpass("Confirmá la contraseña: ")

    if password != confirm:
        print("❌ Las contraseñas no coinciden.")
        _log_auditoria(f"INTENTO FALLIDO: contraseñas no coincidentes para username='{username}'.")
        return

    if len(password) < 12:
        print("⚠️  Advertencia: se recomienda una contraseña de al menos 12 caracteres.")

    if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
        print(f"⚠️  Advertencia: bcrypt solo usa los primeros {_BCRYPT_MAX_BYTES} bytes; el resto se ignora.")

    rol = input("Rol (default: admin): ").strip() or "admin"

    hashed = hash_password(password)

    try:
        creado = await _upsert_usuario(username, hashed, rol)
    except Exception as e:
        print(f"❌ Error al escribir en la base de datos: {e}")
        _log_auditoria(f"ERROR DE DB al crear/actualizar username='{username}': {e}")
        return

    accion = "creado" if creado else "actualizado"
    print(f"\n✅ Usuario '{username}' {accion} con rol '{rol}'.")
    _log_auditoria(f"OK: usuario '{username}' {accion} con rol '{rol}'.")


if __name__ == "__main__":
    asyncio.run(main())