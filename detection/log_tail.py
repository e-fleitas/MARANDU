#!/usr/bin/env python3
"""
M.A.R.A.N.D.U. - Detection Module
File: detection/log_tail.py

Utilidad de bajo nivel para el módulo iv (log_analyzer.py): sigue un archivo
de log en vivo, línea por línea, detectando y sobreviviendo a la rotación de
logs (truncado in-place o renombrado + recreación por logrotate).

Esta pieza se prueba de forma aislada, sin lógica de detección todavía.
El resto de log_analyzer.py se construye sobre esta base en los próximos pasos.
"""

import os
import sys
import time
from heartbeat import marcar_heartbeat
NOMBRE_DETECTOR = "mail_queue_monitor"


class LogTail:
    """
    Sigue un archivo de log de forma robusta ante rotación.

    Dos escenarios de rotación que maneja:
    1. Truncado in-place (ej: `> archivo.log` o `logrotate` con copytruncate):
       el inode no cambia, pero el tamaño baja abruptamente. Detectado
       comparando el tamaño actual contra la última posición leída.
    2. Renombrado + recreación (logrotate estándar sin copytruncate):
       el inode cambia. Detectado comparando el inode actual contra el
       que teníamos abierto.
    """

    def __init__(self, ruta, desde_el_final=True, poll_interval=1.0):
        self.ruta = ruta
        self.poll_interval = poll_interval
        self._archivo = None
        self._inode = None
        self._posicion = 0
        self._desde_el_final = desde_el_final

    def _abrir(self):
        """
        Abre (o reabre) el archivo. Nunca lanza excepción hacia el llamador:
        si el archivo no existe todavía (ej: el servicio que lo genera no
        arrancó), reintenta en la próxima llamada a leer_lineas().
        """
        try:
            nuevo_archivo = open(self.ruta, "r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            print(f"[!] Archivo no encontrado (todavía): {self.ruta}", file=sys.stderr)
            return False
        except PermissionError:
            print(f"[-] Sin permisos para leer: {self.ruta}", file=sys.stderr)
            return False
        except OSError as e:
            print(f"[-] Error de sistema abriendo {self.ruta}: {e}", file=sys.stderr)
            return False

        try:
            stat = os.fstat(nuevo_archivo.fileno())
            self._inode = stat.st_ino
        except OSError as e:
            print(f"[!] No se pudo obtener inode de {self.ruta}: {e}", file=sys.stderr)
            self._inode = None

        if self._archivo is not None:
            try:
                self._archivo.close()
            except Exception:
                pass

        self._archivo = nuevo_archivo

        if self._desde_el_final:
            try:
                self._archivo.seek(0, os.SEEK_END)
                self._posicion = self._archivo.tell()
            except OSError as e:
                print(f"[!] No se pudo posicionar al final de {self.ruta}: {e}", file=sys.stderr)
                self._posicion = 0
        else:
            self._posicion = 0

        return True

    def _detectar_rotacion(self):
        """
        Chequea si el archivo rotó (por inode distinto o por truncado).
        Devuelve True si detectó rotación y ya reabrió el archivo.
        """
        try:
            stat_disco = os.stat(self.ruta)
        except FileNotFoundError:
            # El archivo desapareció (logrotate en el medio de renombrar):
            # no es un error fatal, reintentamos en la próxima pasada.
            return False
        except OSError as e:
            print(f"[!] Error verificando estado de {self.ruta}: {e}", file=sys.stderr)
            return False

        rotado_por_inode = (self._inode is not None and stat_disco.st_ino != self._inode)
        rotado_por_truncado = (stat_disco.st_size < self._posicion)

        if rotado_por_inode or rotado_por_truncado:
            motivo = "inode cambió" if rotado_por_inode else "archivo truncado"
            print(f"[i] Rotación detectada en {self.ruta} ({motivo}), reabriendo...", file=sys.stderr)
            self._desde_el_final = False  # leer desde el inicio del archivo nuevo
            return self._abrir()

        return False

    def leer_lineas(self):
        """
        Devuelve una lista de líneas nuevas disponibles desde la última
        lectura. Lista vacía si no hay líneas nuevas. Nunca lanza excepción:
        cualquier error de lectura se registra y devuelve lista vacía,
        para que el módulo que llama pueda seguir el loop sin morir.
        """
        if self._archivo is None:
            if not self._abrir():
                return []

        try:
            self._detectar_rotacion()
        except Exception as e:
            print(f"[!] Error inesperado detectando rotación en {self.ruta}: {e}", file=sys.stderr)

        lineas = []
        try:
            while True:
                linea = self._archivo.readline()
                if not linea:
                    break
                if linea.endswith("\n"):
                    lineas.append(linea.rstrip("\n"))
                    self._posicion = self._archivo.tell()
                else:
                    # Línea incompleta (el escritor todavía no terminó de
                    # escribirla): la descartamos de este ciclo y la
                    # releemos completa en el próximo poll.
                    self._archivo.seek(self._posicion)
                    break
        except (IOError, OSError) as e:
            print(f"[-] Error leyendo {self.ruta}: {e}", file=sys.stderr)
            return []
        except Exception as e:
            print(f"[-] Error inesperado leyendo {self.ruta}: {e}", file=sys.stderr)
            return []

        return lineas

    def cerrar(self):
        if self._archivo is not None:
            try:
                self._archivo.close()
            except Exception:
                pass
            self._archivo = None


def demo_seguir_archivo(ruta, duracion_segundos=30):
    """
    Función de prueba manual: sigue un archivo e imprime las líneas nuevas
    que aparezcan, durante `duracion_segundos`. Sirve para validar el
    comportamiento de LogTail antes de integrarlo al resto del módulo.
    """
    print(f"[+] Siguiendo {ruta} durante {duracion_segundos}s (Ctrl+C para cortar antes)...")
    tail = LogTail(ruta, desde_el_final=True, poll_interval=0.5)
    inicio = time.time()
    try:
        while time.time() - inicio < duracion_segundos:
            for linea in tail.leer_lineas():
                print(f"[LINEA NUEVA] {linea}")
            time.sleep(tail.poll_interval)
    except KeyboardInterrupt:
        print("\n[.] Interrumpido por el usuario.")
    finally:
        tail.cerrar()
    print("[+] Fin de la prueba.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 detection/log_tail.py <ruta_al_archivo> [duracion_segundos]", file=sys.stderr)
        sys.exit(1)

    ruta_arg = sys.argv[1]
    duracion_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    marcar_heartbeat(NOMBRE_DETECTOR, alarmas_emitidas=total, ok=True)
    demo_seguir_archivo(ruta_arg, duracion_arg)

