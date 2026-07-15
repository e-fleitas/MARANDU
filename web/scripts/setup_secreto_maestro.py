"""
Uso ÚNICO (setup inicial): genera el archivo /etc/marandu/create_user.secret
con el hash bcrypt de la frase secreta que va a proteger la creación de
usuarios vía CLI.

Correr UNA sola vez, como root:
    sudo python3 web/scripts/setup_secreto_maestro.py

Después de correrlo, guardá la frase secreta en un lugar seguro (gestor de
contraseñas). No queda guardada en texto plano en ningún lado del sistema.
"""
import getpass
import os
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from web.auth import hash_password

SECRET_DIR = "/etc/marandu"
SECRET_FILE = os.path.join(SECRET_DIR, "create_user.secret")


def main():
    if os.geteuid() != 0:
        print("❌ Este script debe correrse como root (sudo).")
        sys.exit(1)

    if os.path.exists(SECRET_FILE):
        confirm = input(
            f"⚠️  Ya existe {SECRET_FILE}. ¿Sobreescribir la frase secreta? (escribí 'si' para confirmar): "
        )
        if confirm.strip().lower() != "si":
            print("Cancelado.")
            return

    secret = getpass.getpass("Frase secreta maestra (no se va a mostrar en pantalla): ")
    confirm = getpass.getpass("Confirmá la frase secreta: ")

    if secret != confirm:
        print("❌ Las frases no coinciden.")
        return

    if len(secret) < 20:
        print("⚠️  Advertencia: se recomienda una frase de al menos 20 caracteres (ej. varias palabras al azar).")

    hashed = hash_password(secret)

    os.makedirs(SECRET_DIR, mode=0o700, exist_ok=True)
    # Escribimos con permisos restrictivos desde el vamos, para no dejar
    # una ventana donde el archivo sea legible por otros usuarios.
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(hashed + "\n")

    os.chmod(SECRET_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600, solo root
    print(f"\n✅ Secreto maestro configurado en {SECRET_FILE} (permisos 600, solo root).")
    print("   Guardá la frase secreta en un gestor de contraseñas: no queda guardada en texto plano en ningún lado.")


if __name__ == "__main__":
    main()