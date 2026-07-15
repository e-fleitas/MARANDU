"""
Crea o actualiza un usuario en la tabla usuarios_web.

Uso:
    python web/scripts/generar_hash.py

Pide username, contraseña y rol por consola. Si el username ya existe,
actualiza el hash de contraseña; si no existe, crea la fila.

Requiere que la variable de entorno DATABASE_URL (o el default de
db/session.py) apunte a una base con la migración de Alembic ya aplicada
(tabla usuarios_web creada).
"""
import asyncio
import getpass
import sys
from pathlib import Path

# Permite importar los módulos del proyecto aunque el script se corra como
# `python web/scripts/generar_hash.py` desde la raíz del repo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from sqlalchemy import select

from db.session import async_session
from db.models import UsuarioWeb
from web.auth import hash_password

_BCRYPT_MAX_BYTES = 72


async def _upsert_usuario(username: str, password_hash: str, rol: str) -> bool:
    """Devuelve True si se creó un usuario nuevo, False si se actualizó uno existente."""
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
    username = input("Nombre de usuario: ").strip()
    if not username:
        print("❌ El nombre de usuario no puede estar vacío.")
        return

    password = getpass.getpass("Contraseña: ")
    confirm = getpass.getpass("Confirmá la contraseña: ")

    if password != confirm:
        print("❌ Las contraseñas no coinciden.")
        return

    if len(password) < 12:
        print("⚠️  Advertencia: se recomienda una contraseña de al menos 12 caracteres.")

    password_bytes = password.encode("utf-8")
    if len(password_bytes) > _BCRYPT_MAX_BYTES:
        print(f"⚠️  Advertencia: bcrypt solo usa los primeros {_BCRYPT_MAX_BYTES} bytes; el resto se ignora.")

    rol = input("Rol (default: admin): ").strip() or "admin"

    hashed = hash_password(password)

    try:
        creado = await _upsert_usuario(username, hashed, rol)
    except Exception as e:
        print(f"❌ Error al escribir en la base de datos: {e}")
        print("   Verificá que DATABASE_URL apunte a la DB correcta y que la ")
        print("   migración de Alembic (tabla usuarios_web) ya esté aplicada.")
        return

    if creado:
        print(f"\n✅ Usuario '{username}' creado con rol '{rol}'.")
    else:
        print(f"\n✅ Usuario '{username}' actualizado (nueva contraseña, rol '{rol}').")


if __name__ == "__main__":
    asyncio.run(main())