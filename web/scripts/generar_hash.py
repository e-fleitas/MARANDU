"""
Genera el hash bcrypt para usar como MARANDU_ADMIN_PASSWORD_HASH.

Uso:
    python scripts/generar_hash.py
"""
import getpass
import sys
from pathlib import Path

# Permite importar auth.py aunque el script se corra como `python scripts/generar_hash.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bcrypt

_BCRYPT_MAX_BYTES = 72


def main():
    password = getpass.getpass("Contraseña para el usuario admin: ")
    confirm = getpass.getpass("Confirmá la contraseña: ")

    if password != confirm:
        print("❌ Las contraseñas no coinciden.")
        return

    if len(password) < 12:
        print("⚠️  Advertencia: se recomienda una contraseña de al menos 12 caracteres.")

    password_bytes = password.encode("utf-8")
    if len(password_bytes) > _BCRYPT_MAX_BYTES:
        print(f"⚠️  Advertencia: bcrypt solo usa los primeros {_BCRYPT_MAX_BYTES} bytes; el resto se ignora.")
        password_bytes = password_bytes[:_BCRYPT_MAX_BYTES]

    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")
    print("\nAgregá esta línea a tu archivo .env:\n")
    print(f"MARANDU_ADMIN_PASSWORD_HASH={hashed}")


if __name__ == "__main__":
    main()