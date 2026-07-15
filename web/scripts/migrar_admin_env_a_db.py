"""
Migración de UNA SOLA VEZ: toma el admin actual (MARANDU_ADMIN_USER +
MARANDU_ADMIN_PASSWORD_HASH del .env) y lo inserta en la tabla usuarios_web,
para no perder el acceso durante el corte de env -> DB.

Uso:
    python web/scripts/migrar_admin_env_a_db.py

Después de correr esto y confirmar que el login funciona contra la DB,
borrá MARANDU_ADMIN_USER y MARANDU_ADMIN_PASSWORD_HASH del .env.
"""
import asyncio
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
load_dotenv(dotenv_path=BASE_DIR / ".env")

from sqlalchemy import select

from db.session import async_session
from db.models import UsuarioWeb


async def main():
    username = os.environ.get("MARANDU_ADMIN_USER")
    password_hash = os.environ.get("MARANDU_ADMIN_PASSWORD_HASH")

    if not username or not password_hash:
        print("❌ No se encontraron MARANDU_ADMIN_USER / MARANDU_ADMIN_PASSWORD_HASH en el .env.")
        print("   No hay nada que migrar (o ya fueron borradas).")
        return

    async with async_session() as session:
        result = await session.execute(
            select(UsuarioWeb).where(UsuarioWeb.username == username)
        )
        existing = result.scalar_one_or_none()

        if existing is not None:
            print(f"⚠️  El usuario '{username}' ya existe en usuarios_web. No se modifica nada.")
            return

        user = UsuarioWeb(username=username, password_hash=password_hash, rol="admin")
        session.add(user)
        await session.commit()

    print(f"✅ Usuario '{username}' migrado a la tabla usuarios_web con rol 'admin'.")
    print("   Ahora podés borrar MARANDU_ADMIN_USER y MARANDU_ADMIN_PASSWORD_HASH del .env.")


if __name__ == "__main__":
    asyncio.run(main())