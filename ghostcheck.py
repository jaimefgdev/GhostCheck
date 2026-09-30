#!/usr/bin/env python3
"""
==============================================================================
  GhostCheck — Auditoría de Seguridad para Servidores Linux / RHEL
  Modo: DRY-RUN (solo auditoría, sin cambios destructivos)
  Autor   : jaimefg1888
  Tool    : GhostCheck
  GitHub  : https://github.com/jaimefg1888

  Módulos de auditoría implementados:
    [1] Control de privilegios root
    [2] SELinux — modo y política activa
    [3] Firewall — firewalld / ufw, puertos expuestos
    [4] Usuarios — UID 0 duplicados, contraseñas vacías
    [5] SSH — directivas de riesgo en sshd_config
    [6] Actualizaciones de seguridad — dnf check-update
    [7] Generación de reportes TXT + HTML
==============================================================================
"""

import argparse
import html
import os
import sys
import re
import glob
import shutil
import subprocess
import itertools
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES GLOBALES
# ─────────────────────────────────────────────────────────────────────────────

# Puertos considerados esenciales (SSH, HTTP, HTTPS)
PUERTOS_ESENCIALES: set[str] = {"22", "80", "443"}

# Rutas clave del sistema
RUTA_PASSWD:    str = "/etc/passwd"
RUTA_SHADOW:    str = "/etc/shadow"
RUTA_SSHD_CFG: str = "/etc/ssh/sshd_config"

# Directivas de sshd_config consideradas de alto riesgo.
# Formato: { "directiva": "valor_peligroso" }
# Solo se marcan cuando están activas (sin comentar) y con el valor peligroso.
SSHD_DIRECTIVAS_RIESGO: dict[str, str] = {
    "PermitRootLogin":        "yes",
    "PasswordAuthentication": "yes",   # riesgo si se prefiere solo clave pública
    "PermitEmptyPasswords":   "yes",   # riesgo crítico
    "X11Forwarding":          "yes",   # superficie de ataque innecesaria
    "Protocol":               "1",     # SSHv1 obsoleto y vulnerable
}

# Lista blanca de comandos de SOLO LECTURA que GhostCheck puede ejecutar.
# Cada entrada es una plantilla: una tupla de expresiones regulares que deben
# casar completas, posición a posición, con cada argumento del comando.
# Cualquier comando que no case con alguna plantilla se bloquea sin ejecutarse,
# lo que garantiza el modo DRY-RUN aunque un futuro cambio introduzca un error.
COMANDOS_PERMITIDOS: tuple[tuple[str, ...], ...] = (
    ("getenforce",),
    ("sestatus",),
    ("systemctl", "is-active", "firewalld"),
    ("firewall-cmd", "--list-ports",    r"--zone=[\w.-]+"),
    ("firewall-cmd", "--list-services", r"--zone=[\w.-]+"),
    ("ufw", "status", "verbose"),
    ("dnf", "check-update", "--security"),
    ("hostname", "-f"),
)

# Marca de tiempo para los nombres de fichero de reporte
HOY: str = datetime.now().strftime("%Y%m%d_%H%M%S")
NOMBRE_REPORTE_TXT:  str = f"auditoria_servidor_{HOY}.txt"
NOMBRE_REPORTE_HTML: str = f"auditoria_servidor_{HOY}.html"


# ─────────────────────────────────────────────────────────────────────────────
# SPINNER — Para que la terminal no se congele mientras dnf hace su vida
# ─────────────────────────────────────────────────────────────────────────────

class Spinner:
    """
    Animación de carga en consola. Útil cuando un comando tarda la vida
    y no quieres que el operario piense que el script se ha colgado.

    Uso:
        with Spinner("Consultando repositorios..."):
            resultado = operacion_lenta()
    """

    _FRAMES: tuple[str, ...] = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    _DELAY:  float           = 0.1

    def __init__(self, mensaje: str = "Trabajando...") -> None:
        self._mensaje  = mensaje
        self._activo   = False
        self._hilo: Optional[threading.Thread] = None

    def _girar(self) -> None:
        # Ciclo infinito de frames hasta que _activo sea False
        for frame in itertools.cycle(self._FRAMES):
            if not self._activo:
                break
            # \r vuelve al inicio de línea — así sobreescribimos sin basura visual
            sys.stdout.write(f"\r  {frame}  {self._mensaje}")
            sys.stdout.flush()
            time.sleep(self._DELAY)
        # Limpiar la línea del spinner al terminar
        sys.stdout.write(f"\r{' ' * (len(self._mensaje) + 8)}\r")
        sys.stdout.flush()

    def __enter__(self) -> "Spinner":
        self._activo = True
        self._hilo   = threading.Thread(target=self._girar, daemon=True)
        self._hilo.start()
        return self

    def __exit__(self, *_) -> None:
        self._activo = False
        if self._hilo:
            self._hilo.join()


# ─────────────────────────────────────────────────────────────────────────────
# [1] CONTROL DE EJECUCIÓN — Verificar privilegios root
# ─────────────────────────────────────────────────────────────────────────────

def verificar_root() -> None:
    """
    Comprueba que el script se ejecuta con UID 0 (root).
    Termina la ejecución con código de error 1 si no es así.
    """
    if os.getuid() != 0:
        print("\n[✘ ERROR CRÍTICO] Este script debe ejecutarse como root (UID 0).")
        print("  Utiliza: sudo python3 ghostcheck.py\n")
        sys.exit(1)
    print("[✔] Ejecutando como root. Privilegios verificados.\n")


# ─────────────────────────────────────────────────────────────────────────────
# UTILIDAD — Ejecutar comandos del sistema de forma segura
# ─────────────────────────────────────────────────────────────────────────────

def comando_permitido(comando: list[str]) -> bool:
    """
    Indica si ``comando`` casa exactamente con alguna plantilla de
    COMANDOS_PERMITIDOS (mismo número de argumentos y cada uno casando
    completo con su expresión regular).
    """
    for plantilla in COMANDOS_PERMITIDOS:
        if len(plantilla) == len(comando) and all(
            re.fullmatch(patron, arg) for patron, arg in zip(plantilla, comando)
        ):
            return True
    return False


def ejecutar_comando(
    comando: list[str],
    timeout: int = 10
) -> tuple[int, str, str]:
    """
    Ejecuta un comando del sistema operativo de forma segura mediante subprocess.
    Solo se ejecutan comandos de la lista blanca COMANDOS_PERMITIDOS.

    Args:
        comando: Lista de strings con el comando y sus argumentos.
        timeout: Tiempo máximo de espera en segundos (por defecto 10).

    Returns:
        Tupla (código_retorno, stdout, stderr).
        Códigos negativos propios:
          -1  → comando no encontrado en PATH
          -2  → timeout superado
          -3  → excepción inesperada
          -4  → comando bloqueado por no estar en la lista blanca (DRY-RUN)
    """
    if not comando_permitido(comando):
        return -4, "", f"Comando bloqueado por DRY-RUN (no está en la lista blanca): {' '.join(comando)}"

    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout
        )
        return resultado.returncode, resultado.stdout.strip(), resultado.stderr.strip()

    except FileNotFoundError:
        return -1, "", f"Comando no encontrado: {comando[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"Tiempo de espera agotado ejecutando: {' '.join(comando)}"
    except Exception as exc:
        return -3, "", f"Error inesperado: {str(exc)}"


# ─────────────────────────────────────────────────────────────────────────────
# [2] AUDITORÍA DE SELINUX
# ─────────────────────────────────────────────────────────────────────────────

def auditar_selinux() -> dict:
    """
    Comprueba el estado actual de SELinux usando `getenforce` y `sestatus`.

    Returns:
        Diccionario con estado, modo, política activa y lista de advertencias.
    """
    print("=" * 64)
    print("  [2] AUDITORÍA DE SELINUX")
    print("=" * 64)

    resultado: dict = {
        "herramienta": "SELinux",
        "estado":      "DESCONOCIDO",
        "modo":        None,
        "politica":    None,
        "advertencias": [],
        "ok":          False,
    }

    codigo, stdout, stderr = ejecutar_comando(["getenforce"])

    if codigo == -1:
        adv = "SELinux no está instalado o no está disponible en este sistema."
        resultado["advertencias"].append(adv)
        resultado["estado"] = "NO_DISPONIBLE"
        print(f"  [⚠] {adv}")
        print()
        return resultado

    if codigo != 0:
        adv = f"Error al ejecutar getenforce: {stderr}"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")
        print()
        return resultado

    modo = stdout.strip()
    resultado["modo"] = modo

    # Obtener política cargada con sestatus
    codigo_s, stdout_s, _ = ejecutar_comando(["sestatus"])
    if codigo_s == 0:
        for linea in stdout_s.splitlines():
            if "Loaded policy name" in linea:
                resultado["politica"] = linea.split(":")[1].strip()

    if modo == "Enforcing":
        resultado["estado"] = "OK"
        resultado["ok"]     = True
        print(f"  [✔] SELinux está en modo: Enforcing")
        print(f"  [i] Política cargada: {resultado.get('politica', 'N/A')}")

    elif modo == "Permissive":
        adv = "SELinux en modo PERMISSIVE: las políticas se registran pero NO se aplican."
        resultado["estado"] = "ADVERTENCIA"
        resultado["advertencias"].append(adv)
        print(f"  [⚠] {adv}")
        print( "      Recomendación: Cambiar a Enforcing en /etc/selinux/config")

    elif modo == "Disabled":
        adv = "SELinux DESHABILITADO: el sistema carece de control de acceso obligatorio (MAC)."
        resultado["estado"] = "CRÍTICO"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")
        print( "      Recomendación: Habilitar SELinux y reiniciar el sistema.")

    else:
        adv = f"Estado de SELinux desconocido: '{modo}'"
        resultado["estado"] = "DESCONOCIDO"
        resultado["advertencias"].append(adv)
        print(f"  [?] {adv}")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [3] GESTIÓN DE FIREWALL
# ─────────────────────────────────────────────────────────────────────────────

def _auditar_firewalld() -> dict:
    """Audita el firewall mediante firewalld (RHEL / CentOS / Fedora / Rocky)."""
    resultado: dict = {
        "herramienta":       "firewalld",
        "activo":            False,
        "puertos_abiertos":  [],
        "puertos_a_revisar": [],
        "advertencias":      [],
        "ok":                False,
    }

    codigo, stdout, _ = ejecutar_comando(["systemctl", "is-active", "firewalld"])
    if codigo != 0 or stdout != "active":
        resultado["advertencias"].append("firewalld no está activo. El sistema puede estar expuesto.")
        print("  [✘] firewalld NO está activo.")
        return resultado

    resultado["activo"] = True
    print("  [✔] firewalld está activo.")

    codigo_p, stdout_p, _ = ejecutar_comando(["firewall-cmd", "--list-ports",    "--zone=public"])
    codigo_s, stdout_s, _ = ejecutar_comando(["firewall-cmd", "--list-services", "--zone=public"])

    puertos_raw:   list[str] = stdout_p.split() if stdout_p else []
    servicios_raw: list[str] = stdout_s.split() if stdout_s else []

    mapa_servicios: dict[str, str] = {
        "ssh": "22", "http": "80", "https": "443",
        "ftp": "21", "smtp": "25", "dns": "53",
        "mysql": "3306", "postgresql": "5432",
    }
    puertos_desde_servicios = [mapa_servicios[s] for s in servicios_raw if s in mapa_servicios]

    # Normalizar a solo el número (quitar "/tcp", "/udp")
    todos_puertos: list[str] = list(
        {p.split("/")[0] for p in puertos_raw} | set(puertos_desde_servicios)
    )
    resultado["puertos_abiertos"] = todos_puertos

    no_esenciales = [p for p in todos_puertos if p not in PUERTOS_ESENCIALES]
    resultado["puertos_a_revisar"] = no_esenciales

    print(f"  [i] Puertos/Servicios abiertos: {', '.join(todos_puertos) or 'ninguno'}")
    if servicios_raw:
        print(f"  [i] Servicios habilitados:      {', '.join(servicios_raw)}")

    if no_esenciales:
        msg = f"Puertos no esenciales detectados: {', '.join(no_esenciales)}"
        resultado["advertencias"].append(msg)
        print(f"  [⚠] {msg}")
        print( "      Recomendación (DRY-RUN): evaluar y bloquear con:")
        for p in no_esenciales:
            print(f"        firewall-cmd --permanent --remove-port={p}/tcp")
    else:
        resultado["ok"] = True
        print("  [✔] Solo están abiertos los puertos esenciales.")

    return resultado


def _auditar_ufw() -> dict:
    """
    Audita el firewall mediante UFW (Debian / Ubuntu).

    Mejoras sobre la versión original:
      - Parsea perfiles de aplicación (App Profiles) de 'ufw status verbose'
        y los resuelve a sus puertos correspondientes.
      - Los puertos numéricos directos se siguen detectando como antes.

    Tabla de mapeo de perfiles de aplicación:
      OpenSSH / SSH        → 22
      Nginx HTTP / Apache  → 80
      Nginx HTTPS / Apache Secure → 443
      Nginx Full / Apache Full    → 80, 443
    """
    # Mapa de perfiles de aplicación UFW → lista de puertos equivalentes.
    # Las claves son fragmentos de texto en minúsculas presentes en el nombre
    # del perfil; se evalúan en orden para que 'full' (80+443) tenga prioridad
    # sobre 'http' y 'https' por separado.
    PERFILES_APP: list[tuple[str, list[str]]] = [
        ("nginx full",      ["80", "443"]),
        ("apache full",     ["80", "443"]),
        ("nginx http",      ["80"]),
        ("nginx https",     ["443"]),
        ("apache secure",   ["443"]),
        ("apache",          ["80"]),
        ("openssh",         ["22"]),
        ("ssh",             ["22"]),
    ]

    resultado: dict = {
        "herramienta":       "ufw",
        "activo":            False,
        "puertos_abiertos":  [],
        "puertos_a_revisar": [],
        "advertencias":      [],
        "ok":                False,
    }

    codigo, stdout, _ = ejecutar_comando(["ufw", "status", "verbose"])
    if codigo != 0:
        resultado["advertencias"].append("No se pudo obtener el estado de UFW.")
        return resultado

    if "inactive" in stdout.lower():
        resultado["advertencias"].append("UFW está INACTIVO. El sistema puede estar expuesto.")
        print("  [✘] UFW NO está activo.")
        return resultado

    resultado["activo"] = True
    print("  [✔] UFW está activo.")

    puertos_detectados: set[str] = set()
    perfiles_resueltos: list[str] = []   # para informar qué perfiles se mapearon

    for linea in stdout.splitlines():
        linea_upper = linea.upper()
        if "ALLOW" not in linea_upper:
            continue

        linea_lower = linea.lower()

        # ── Intentar resolver como perfil de aplicación primero ───────────────
        perfil_encontrado = False
        for fragmento, puertos in PERFILES_APP:
            if fragmento in linea_lower:
                puertos_detectados.update(puertos)
                perfiles_resueltos.append(
                    f"{linea.split()[0]} → puerto(s) {', '.join(puertos)}"
                )
                perfil_encontrado = True
                break   # cada línea solo se procesa una vez

        # ── Si no hay perfil, buscar puerto numérico directo ──────────────────
        if not perfil_encontrado:
            match = re.search(r"(\d+)(?:/(?:tcp|udp))?", linea)
            if match:
                puertos_detectados.add(match.group(1))

    resultado["puertos_abiertos"] = sorted(puertos_detectados, key=lambda p: int(p))
    no_esenciales = [p for p in resultado["puertos_abiertos"] if p not in PUERTOS_ESENCIALES]
    resultado["puertos_a_revisar"] = no_esenciales

    if perfiles_resueltos:
        print("  [i] Perfiles de aplicación resueltos:")
        for pr in perfiles_resueltos:
            print(f"      • {pr}")

    print(f"  [i] Puertos permitidos: {', '.join(resultado['puertos_abiertos']) or 'ninguno'}")

    if no_esenciales:
        msg = f"Puertos no esenciales detectados: {', '.join(no_esenciales)}"
        resultado["advertencias"].append(msg)
        print(f"  [⚠] {msg}")
        print( "      Recomendación (DRY-RUN): ufw deny <puerto>")
    else:
        resultado["ok"] = True
        print("  [✔] Solo están abiertos los puertos esenciales.")

    return resultado


def auditar_firewall() -> dict:
    """
    Detecta automáticamente si el sistema usa firewalld o ufw
    y delega en la función de auditoría correspondiente.

    Returns:
        Diccionario con los resultados del firewall.
    """
    print("=" * 64)
    print("  [3] GESTIÓN DE FIREWALL")
    print("=" * 64)

    if shutil.which("firewall-cmd"):
        print("  [i] Gestor detectado: firewalld (RHEL/CentOS/Rocky/Fedora)\n")
        resultado = _auditar_firewalld()
    elif shutil.which("ufw"):
        print("  [i] Gestor detectado: UFW (Debian/Ubuntu)\n")
        resultado = _auditar_ufw()
    else:
        resultado = {
            "herramienta":       "ninguno",
            "activo":            False,
            "puertos_abiertos":  [],
            "puertos_a_revisar": [],
            "advertencias":      [
                "No se encontró firewalld ni ufw. El sistema NO tiene firewall gestionado."
            ],
            "ok": False,
        }
        print("  [✘] No se encontró ningún gestor de firewall (firewalld / ufw).")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [4] AUDITORÍA DE USUARIOS (ACLs / PERMISOS)
# ─────────────────────────────────────────────────────────────────────────────

def auditar_usuarios() -> dict:
    """
    Audita /etc/passwd y /etc/shadow en busca de:
      - Usuarios con UID 0 distintos de root (escalada de privilegios).
      - Cuentas con contraseñas vacías en /etc/shadow.

    Returns:
        Diccionario con los hallazgos de la auditoría de usuarios.
    """
    print("=" * 64)
    print("  [4] AUDITORÍA DE USUARIOS (ACLs / PERMISOS)")
    print("=" * 64)

    resultado: dict = {
        "usuarios_uid0_no_root":  [],
        "cuentas_sin_contrasena": [],
        "total_usuarios":         0,
        "total_usuarios_sistema": 0,
        "advertencias":           [],
        "ok":                     True,
    }

    # ── /etc/passwd ──────────────────────────────────────────────────────────
    print(f"\n  [i] Analizando {RUTA_PASSWD}...")
    try:
        with open(RUTA_PASSWD, "r", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                partes = linea.split(":")
                if len(partes) < 4:
                    continue

                usuario = partes[0]
                uid     = partes[2]
                shell   = partes[6] if len(partes) > 6 else ""

                resultado["total_usuarios"] += 1

                if shell in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"):
                    resultado["total_usuarios_sistema"] += 1

                if uid == "0" and usuario != "root":
                    adv = f"Usuario '{usuario}' tiene UID 0 — privilegios equivalentes a root."
                    resultado["usuarios_uid0_no_root"].append(usuario)
                    resultado["advertencias"].append(adv)
                    resultado["ok"] = False
                    print(f"  [✘] CRÍTICO: {adv}")

        if not resultado["usuarios_uid0_no_root"]:
            print("  [✔] Ningún usuario con UID 0 fuera de root.")
        print(
            f"  [i] Total entradas en passwd: {resultado['total_usuarios']} "
            f"({resultado['total_usuarios_sistema']} cuentas de sistema)"
        )

    except FileNotFoundError:
        adv = f"No se encontró el archivo {RUTA_PASSWD}"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")
    except PermissionError:
        adv = f"Sin permisos para leer {RUTA_PASSWD}"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")
    except OSError as exc:
        adv = f"Error leyendo {RUTA_PASSWD}: {exc}"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")

    # ── /etc/shadow ───────────────────────────────────────────────────────────
    print(f"\n  [i] Analizando {RUTA_SHADOW}...")
    try:
        with open(RUTA_SHADOW, "r", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                partes = linea.split(":")
                if len(partes) < 2:
                    continue

                usuario   = partes[0]
                hash_pass = partes[1]

                # Campo vacío "" → contraseña en blanco real (riesgo crítico)
                # "!" o "*" → cuenta bloqueada/sin login → no es un riesgo directo
                if hash_pass == "":
                    adv = f"Cuenta '{usuario}' tiene contraseña VACÍA en /etc/shadow."
                    resultado["cuentas_sin_contrasena"].append(usuario)
                    resultado["advertencias"].append(adv)
                    resultado["ok"] = False
                    print(f"  [✘] CRÍTICO: {adv}")

        if not resultado["cuentas_sin_contrasena"]:
            print("  [✔] Ninguna cuenta con contraseña vacía detectada.")

    except FileNotFoundError:
        adv = f"No se encontró el archivo {RUTA_SHADOW}"
        resultado["advertencias"].append(adv)
        print(f"  [⚠] {adv}")
    except PermissionError:
        adv = f"Sin permisos para leer {RUTA_SHADOW} (¿ejecutas como root?)"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")
    except OSError as exc:
        adv = f"Error leyendo {RUTA_SHADOW}: {exc}"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [5] AUDITORÍA DE SSH
# ─────────────────────────────────────────────────────────────────────────────

def _resolver_includes(ruta_cfg: str) -> list[tuple[str, int, str]]:
    """
    Lee un archivo de configuración SSH y resuelve cualquier directiva
    ``Include`` encontrada, devolviendo todas las líneas (de todos los archivos)
    como una lista de tuplas ``(ruta_origen, número_de_línea, texto_de_línea)``.

    La resolución sigue el comportamiento de sshd_config:
      - Si la ruta del Include es relativa, se interpreta como relativa a
        ``/etc/ssh/``.
      - Se admiten comodines estándar (``*``, ``?``, ``[…]``) usando
        ``glob.glob``.
      - Los archivos resultantes se ordenan alfabéticamente, igual que sshd.
      - Las directivas Include anidadas NO se resuelven (sshd tampoco lo hace).

    Args:
        ruta_cfg: Ruta absoluta del archivo de configuración principal.

    Returns:
        Lista de tuplas (ruta_archivo, num_linea, texto_linea) con el contenido
        combinado del archivo principal y todos los archivos incluidos.
    """
    SSH_DIR = "/etc/ssh"
    lineas_combinadas: list[tuple[str, int, str]] = []

    try:
        with open(ruta_cfg, "r", encoding="utf-8", errors="replace") as fh:
            lineas_principales = fh.readlines()
    except OSError:
        return lineas_combinadas  # El llamador manejará el error

    for num, linea in enumerate(lineas_principales, start=1):
        linea_limpia = linea.strip()

        # Detectar directiva Include (case-insensitive)
        if re.match(r"(?i)^include\s+", linea_limpia) and not linea_limpia.startswith("#"):
            partes = linea_limpia.split(None, 1)
            if len(partes) < 2:
                continue

            patron = partes[1].strip()

            # Si la ruta no es absoluta, resolverla relativa a /etc/ssh/
            if not os.path.isabs(patron):
                patron = os.path.join(SSH_DIR, patron)

            # Expandir comodines y ordenar alfabéticamente (comportamiento sshd)
            archivos_incluidos = sorted(glob.glob(patron))

            for ruta_inc in archivos_incluidos:
                try:
                    with open(ruta_inc, "r", encoding="utf-8", errors="replace") as fh_inc:
                        for num_inc, linea_inc in enumerate(fh_inc.readlines(), start=1):
                            lineas_combinadas.append((ruta_inc, num_inc, linea_inc))
                except OSError as exc:
                    # Registrar el problema pero continuar con los demás archivos
                    lineas_combinadas.append(
                        (ruta_inc, 0, f"# [GhostCheck ERROR] No se pudo leer {ruta_inc}: {exc}\n")
                    )
        else:
            lineas_combinadas.append((ruta_cfg, num, linea))

    return lineas_combinadas


def auditar_ssh() -> dict:
    """
    Analiza /etc/ssh/sshd_config (y los archivos que incluya vía ``Include``)
    en busca de directivas de riesgo alto.

    Mejoras sobre la versión original:
      - Resuelve automáticamente las directivas ``Include`` del archivo
        principal usando ``glob``, evaluando también los fragmentos en
        ``/etc/ssh/sshd_config.d/*.conf`` u otras rutas incluidas.
      - El reporte indica en qué archivo y línea exacta se encontró cada
        directiva peligrosa.

    Lógica de parsing:
      - Ignora líneas vacías y comentadas (comienzan con '#').
      - Es insensible a mayúsculas/minúsculas en el nombre de la directiva.
      - Detecta directivas activas con valores peligrosos definidos en
        SSHD_DIRECTIVAS_RIESGO.

    Returns:
        Diccionario con directivas peligrosas encontradas, resumen de la
        configuración y lista de advertencias.
    """
    print("=" * 64)
    print("  [5] AUDITORÍA DE SSH (sshd_config + Include)")
    print("=" * 64)

    resultado: dict = {
        "ruta_config":        RUTA_SSHD_CFG,
        "archivos_analizados": [],   # list[str] — todos los archivos leídos
        "directivas_riesgo":  [],    # list[dict]
        "directivas_seguras": [],
        "puerto_ssh":         "22",
        "advertencias":       [],
        "ok":                 True,
    }

    print(f"\n  [i] Leyendo {RUTA_SSHD_CFG} (resolviendo Include si existe)...")

    # Verificar existencia y permisos antes de llamar al resolvedor
    if not os.path.exists(RUTA_SSHD_CFG):
        adv = f"No se encontró {RUTA_SSHD_CFG}. ¿Está instalado el servidor SSH?"
        resultado["advertencias"].append(adv)
        print(f"  [⚠] {adv}")
        print()
        return resultado

    if not os.access(RUTA_SSHD_CFG, os.R_OK):
        adv = f"Sin permisos para leer {RUTA_SSHD_CFG}"
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")
        print()
        return resultado

    # Obtener todas las líneas del archivo principal + los archivos incluidos
    lineas_totales = _resolver_includes(RUTA_SSHD_CFG)

    # Registrar qué archivos únicos se procesaron (para el reporte)
    archivos_vistos: list[str] = []
    for ruta_arc, _, _ in lineas_totales:
        if ruta_arc not in archivos_vistos:
            archivos_vistos.append(ruta_arc)
    resultado["archivos_analizados"] = archivos_vistos

    if len(archivos_vistos) > 1:
        print(f"  [i] Archivos analizados ({len(archivos_vistos)}):")
        for arc in archivos_vistos:
            print(f"      • {arc}")
    else:
        print(f"  [i] Archivo analizado: {RUTA_SSHD_CFG}")

    # Descripciones legibles de cada directiva de riesgo
    descripciones: dict[str, str] = {
        "PermitRootLogin":        "Permite login directo como root vía SSH — vector de ataque primario.",
        "PasswordAuthentication": "Permite autenticación por contraseña — vulnerable a fuerza bruta.",
        "PermitEmptyPasswords":   "Permite login SSH sin contraseña — riesgo CRÍTICO.",
        "X11Forwarding":          "Reenvío X11 activo — aumenta la superficie de ataque.",
        "Protocol":               "SSHv1 habilitado — protocolo obsoleto con vulnerabilidades conocidas.",
    }

    for ruta_arc, num, linea in lineas_totales:
        linea_limpia = linea.strip()

        # Saltar comentarios y líneas vacías
        if not linea_limpia or linea_limpia.startswith("#"):
            continue

        partes = linea_limpia.split(None, 1)
        if len(partes) < 2:
            continue

        directiva = partes[0].strip()
        valor     = partes[1].strip().lower()

        # Detectar el puerto SSH
        if directiva.lower() == "port":
            resultado["puerto_ssh"] = partes[1].strip()

        # Comprobar contra el mapa de directivas peligrosas
        for dir_riesgo, val_peligroso in SSHD_DIRECTIVAS_RIESGO.items():
            if directiva.lower() == dir_riesgo.lower() and valor == val_peligroso.lower():
                origen = (
                    f"{os.path.basename(ruta_arc)}:{num}"
                    if ruta_arc != RUTA_SSHD_CFG
                    else f"línea {num}"
                )
                hallazgo = {
                    "directiva":   directiva,
                    "valor":       partes[1].strip(),
                    "linea_num":   num,
                    "archivo":     ruta_arc,
                    "descripcion": descripciones.get(dir_riesgo, "Directiva de riesgo detectada."),
                }
                resultado["directivas_riesgo"].append(hallazgo)
                resultado["advertencias"].append(
                    f"{origen}: '{directiva} {partes[1].strip()}' — "
                    f"{descripciones.get(dir_riesgo, '')}"
                )
                resultado["ok"] = False
                print(f"  [✘] RIESGO ALTO  — {origen}: {directiva} {partes[1].strip()}")
                print(f"      {descripciones.get(dir_riesgo, '')}")

            elif directiva.lower() == dir_riesgo.lower():
                resultado["directivas_seguras"].append(f"{directiva} {partes[1].strip()}")

    if resultado["ok"]:
        print("  [✔] No se detectaron directivas SSH de alto riesgo.")

    print(f"  [i] Puerto SSH en uso          : {resultado['puerto_ssh']}")
    print(f"  [i] Directivas de riesgo       : {len(resultado['directivas_riesgo'])}")
    print(f"  [i] Directivas seguras halladas: {len(resultado['directivas_seguras'])}")

    if resultado["directivas_riesgo"]:
        print()
        print("  Recomendaciones (DRY-RUN) para /etc/ssh/sshd_config:")
        if any(h["directiva"].lower() == "permitrootlogin" for h in resultado["directivas_riesgo"]):
            print("    PermitRootLogin no           # Deshabilitar login directo como root")
        if any(h["directiva"].lower() == "passwordauthentication" for h in resultado["directivas_riesgo"]):
            print("    PasswordAuthentication no    # Usar solo autenticación por clave pública")
        if any(h["directiva"].lower() == "permitemptypasswords" for h in resultado["directivas_riesgo"]):
            print("    PermitEmptyPasswords no      # NUNCA permitir contraseñas vacías")
        print("    Tras editar: systemctl restart sshd")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [6] AUDITORÍA DE ACTUALIZACIONES DE SEGURIDAD (RHEL/Rocky)
# ─────────────────────────────────────────────────────────────────────────────

def auditar_actualizaciones() -> dict:
    """
    Comprueba si existen actualizaciones de seguridad pendientes en sistemas
    basados en RPM/DNF (RHEL, Rocky Linux, AlmaLinux, CentOS Stream, Fedora).

    Códigos de salida documentados de `dnf check-update`:
      0   → El sistema está completamente actualizado.
      100 → Hay paquetes con actualizaciones disponibles.
      1   → Error durante la ejecución del comando.

    La flag `--security` restringe la búsqueda solo a actualizaciones de
    seguridad publicadas en los repositorios activos (errata de tipo 'security').

    Returns:
        Diccionario con el estado de actualización, lista de paquetes
        pendientes y las advertencias generadas.
    """
    print("=" * 64)
    print("  [6] AUDITORÍA DE ACTUALIZACIONES DE SEGURIDAD")
    print("=" * 64)

    resultado: dict = {
        "gestor":              "dnf",
        "estado":              "DESCONOCIDO",
        "paquetes_pendientes": [],  # list[str] — "nombre versión repositorio"
        "total_pendientes":    0,
        "advertencias":        [],
        "ok":                  False,
    }

    # Verificar que dnf está disponible antes de molestar a los repositorios
    if not shutil.which("dnf"):
        adv = "dnf no está disponible. Este módulo es específico de RHEL/Rocky/Fedora."
        resultado["advertencias"].append(adv)
        resultado["estado"] = "NO_DISPONIBLE"
        print(f"  [⚠] {adv}")
        print()
        return resultado

    # dnf puede tardar la vida consultando metadatos remotos — el spinner evita
    # que el operario piense que el proceso se ha colgado y lo mate con Ctrl+C
    with Spinner("Consultando repositorios con dnf check-update --security..."):
        codigo, stdout, stderr = ejecutar_comando(
            ["dnf", "check-update", "--security"],
            timeout=120   # timeout extendido: necesita contactar repos remotos
        )

    # ── Interpretar el código de salida ──────────────────────────────────────

    if codigo == 0:
        # El sistema está al día — no hay que hacer nada, cortar por lo sano
        resultado["estado"] = "ACTUALIZADO"
        resultado["ok"]     = True
        print("  [✔] No hay actualizaciones de seguridad pendientes. Sistema al día.")

    elif codigo == 100:
        # Código 100: hay parches de seguridad esperando en los repos
        resultado["estado"] = "ACTUALIZACIONES_PENDIENTES"
        resultado["ok"]     = False

        # Parsear la salida: cada línea válida tiene formato
        # "nombre_paquete  nueva_version  repositorio"
        paquetes: list[str] = []
        for linea in stdout.splitlines():
            linea = linea.strip()
            # Saltar cabeceras, líneas vacías y mensajes de metadatos de dnf
            if (not linea
                    or linea.startswith("Last metadata")
                    or linea.startswith("Obsoleting")
                    or linea.startswith("Security:")):
                continue
            # Una línea de paquete tiene al menos 2 columnas
            if len(linea.split()) >= 2:
                paquetes.append(linea)

        resultado["paquetes_pendientes"] = paquetes
        resultado["total_pendientes"]    = len(paquetes)

        adv = f"{len(paquetes)} actualización(es) de seguridad pendiente(s) detectada(s)."
        resultado["advertencias"].append(adv)
        print(f"  [✘] {adv}")

        # Mostrar solo los primeros 10 — más que eso es basura visual en consola
        limite = min(10, len(paquetes))
        print(f"\n  Primeros {limite} paquetes pendientes:")
        for pkg in paquetes[:limite]:
            print(f"    • {pkg}")
        if len(paquetes) > 10:
            print(f"    ... y {len(paquetes) - 10} más (ver reporte completo).")

        print()
        print("  Recomendación (DRY-RUN): aplicar actualizaciones con:")
        print("    sudo dnf update --security -y")

    elif codigo == -1:
        # dnf no encontrado en PATH — no debería llegar aquí, pero por si acaso
        adv = f"dnf no encontrado en PATH: {stderr}"
        resultado["advertencias"].append(adv)
        resultado["estado"] = "ERROR"
        print(f"  [✘] {adv}")

    elif codigo == -2:
        # Los repos tardaron demasiado — problema de red o de mirror muerto
        adv = (
            "Timeout esperando respuesta de dnf. "
            "Revisa la conectividad con los repositorios — puede que algún mirror esté caído."
        )
        resultado["advertencias"].append(adv)
        resultado["estado"] = "ERROR_TIMEOUT"
        print(f"  [✘] {adv}")

    else:
        # Código 1 u otro: dnf encontró algo que no le gustó — ver stderr
        adv = f"dnf check-update terminó con error (código {codigo}): {stderr or stdout}"
        resultado["advertencias"].append(adv)
        resultado["estado"] = "ERROR"
        print(f"  [✘] {adv}")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [7] GENERACIÓN DE REPORTES
# ─────────────────────────────────────────────────────────────────────────────

def escribir_reporte_seguro(ruta: str, contenido: str) -> None:
    """
    Escribe un reporte creando SIEMPRE un fichero nuevo con permisos 0600.

      - O_EXCL: falla si el fichero ya existe (no sobrescribe nada).
      - O_NOFOLLOW: falla si la ruta es un enlace simbólico, evitando que
        un atacante redirija la escritura de root a un fichero arbitrario.
      - 0600: el reporte contiene información sensible (cuentas sin
        contraseña, puertos abiertos...) y solo debe leerlo su propietario.

    Raises:
        OSError: si el fichero ya existe, es un symlink o no se puede crear.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(ruta, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(contenido)


def _calcular_nivel_riesgo(resultados: dict) -> str:
    """
    Determina el nivel de riesgo global de la auditoría basándose en los
    hallazgos de todos los módulos.

    Criterios (en orden de precedencia descendente):
      CRÍTICO → usuarios con UID 0 distintos de root, cuentas sin contraseña,
                directiva PermitRootLogin yes o PermitEmptyPasswords yes activas.
      ALTO    → actualizaciones de seguridad pendientes, otras directivas SSH
                de riesgo, o más de 3 advertencias en total.
      MEDIO   → alguna advertencia puntual (SELinux Permissive, puertos extra,
                firewall inactivo, etc.).
      BAJO    → ninguna advertencia en ningún módulo.

    Args:
        resultados: Diccionario con las salidas de todos los módulos.

    Returns:
        String con el nivel: "BAJO", "MEDIO", "ALTO" o "CRÍTICO".
    """
    u  = resultados.get("usuarios", {})
    s  = resultados.get("ssh", {})
    ac = resultados.get("actualizaciones", {})

    # ── Condiciones CRÍTICAS ──────────────────────────────────────────────────
    uid0_extra     = len(u.get("usuarios_uid0_no_root", []))
    sin_contrasena = len(u.get("cuentas_sin_contrasena", []))

    # PermitRootLogin yes o PermitEmptyPasswords yes son condiciones críticas
    ssh_critico = any(
        h["directiva"].lower() in ("permitrootlogin", "permitemptypasswords")
        for h in s.get("directivas_riesgo", [])
    )

    if uid0_extra > 0 or sin_contrasena > 0 or ssh_critico:
        return "CRÍTICO"

    # ── Condiciones ALTAS ─────────────────────────────────────────────────────
    hay_actualizaciones = ac.get("estado") == "ACTUALIZACIONES_PENDIENTES"
    ssh_riesgo_alto     = len(s.get("directivas_riesgo", [])) > 0

    total_advertencias = sum(
        len(resultados.get(mod, {}).get("advertencias", []))
        for mod in ("selinux", "firewall", "usuarios", "ssh", "actualizaciones")
    )

    if hay_actualizaciones or ssh_riesgo_alto or total_advertencias > 3:
        return "ALTO"

    # ── Condiciones MEDIAS ────────────────────────────────────────────────────
    if total_advertencias > 0:
        return "MEDIO"

    return "BAJO"


def generar_reporte_txt(resultados: dict, ruta_salida: Optional[str] = None) -> str:
    """
    Genera un reporte en texto plano (.txt) con los resultados de la auditoría.

    Args:
        resultados:  Diccionario con los resultados de todos los módulos.
        ruta_salida: Ruta de destino. Si es None, usa el directorio de trabajo.

    Returns:
        Ruta absoluta del fichero generado.
    """
    ruta         = ruta_salida or NOMBRE_REPORTE_TXT
    nivel_riesgo = _calcular_nivel_riesgo(resultados)
    ts           = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _, hostname, _ = ejecutar_comando(["hostname", "-f"])
    hostname       = hostname or "desconocido"

    s  = resultados.get("ssh", {})
    ac = resultados.get("actualizaciones", {})

    def _sep(titulo: str = "") -> str:
        return f"{'─' * 64}\n{titulo}" if titulo else "─" * 64

    lineas: list[str] = [
        "=" * 64,
        "  REPORTE DE AUDITORÍA DE SEGURIDAD DEL SERVIDOR",
        "  jaimefg1888 — GhostCheck",
        "=" * 64,
        f"  Fecha y hora    : {ts}",
        f"  Hostname        : {hostname}",
        f"  Modo            : DRY-RUN (solo auditoría, sin cambios)",
        f"  Nivel de riesgo : {nivel_riesgo}",
        "=" * 64,
        "",
        _sep("[1] PRIVILEGIOS DE EJECUCIÓN"),
        _sep(),
        "  Script ejecutado correctamente como root (UID 0).",
        "",
        _sep("[2] AUDITORÍA DE SELINUX"),
        _sep(),
        f"  Estado   : {resultados.get('selinux', {}).get('estado', 'N/A')}",
        f"  Modo     : {resultados.get('selinux', {}).get('modo', 'N/A')}",
        f"  Política : {resultados.get('selinux', {}).get('politica', 'N/A')}",
    ]
    for adv in resultados.get("selinux", {}).get("advertencias", []):
        lineas.append(f"  [⚠] {adv}")

    fw = resultados.get("firewall", {})
    lineas += [
        "",
        _sep("[3] GESTIÓN DE FIREWALL"),
        _sep(),
        f"  Herramienta     : {fw.get('herramienta', 'N/A')}",
        f"  Activo          : {'Sí' if fw.get('activo') else 'No'}",
        f"  Puertos abiertos: {', '.join(fw.get('puertos_abiertos', [])) or 'ninguno'}",
        f"  A revisar       : {', '.join(fw.get('puertos_a_revisar', [])) or 'ninguno'}",
    ]
    for adv in fw.get("advertencias", []):
        lineas.append(f"  [⚠] {adv}")

    u = resultados.get("usuarios", {})
    lineas += [
        "",
        _sep("[4] AUDITORÍA DE USUARIOS"),
        _sep(),
        f"  Total entradas /etc/passwd : {u.get('total_usuarios', 0)}",
        f"  Usuarios con UID 0 (≠root) : {', '.join(u.get('usuarios_uid0_no_root', [])) or 'ninguno'}",
        f"  Cuentas sin contraseña     : {', '.join(u.get('cuentas_sin_contrasena', [])) or 'ninguna'}",
    ]
    for adv in u.get("advertencias", []):
        lineas.append(f"  [⚠] {adv}")

    # ── Sección SSH ───────────────────────────────────────────────────────────
    lineas += [
        "",
        _sep("[5] AUDITORÍA DE SSH"),
        _sep(),
        f"  Archivo analizado  : {s.get('ruta_config', RUTA_SSHD_CFG)}",
        f"  Puerto SSH activo  : {s.get('puerto_ssh', '22')}",
        f"  Directivas de riesgo: {len(s.get('directivas_riesgo', []))}",
    ]
    if s.get("directivas_riesgo"):
        lineas.append("  Detalle de hallazgos:")
        for h in s["directivas_riesgo"]:
            lineas.append(f"    [✘] Línea {h['linea_num']:>4}: {h['directiva']} {h['valor']}")
            lineas.append(f"         → {h['descripcion']}")
    else:
        lineas.append("  [✔] No se detectaron directivas SSH de alto riesgo.")
    for adv in s.get("advertencias", []):
        lineas.append(f"  [⚠] {adv}")

    # ── Sección Actualizaciones ───────────────────────────────────────────────
    lineas += [
        "",
        _sep("[6] ACTUALIZACIONES DE SEGURIDAD"),
        _sep(),
        f"  Gestor de paquetes  : {ac.get('gestor', 'N/A')}",
        f"  Estado              : {ac.get('estado', 'N/A')}",
        f"  Paquetes pendientes : {ac.get('total_pendientes', 0)}",
    ]
    if ac.get("paquetes_pendientes"):
        lineas.append("  Listado (primeros 20):")
        for pkg in ac["paquetes_pendientes"][:20]:
            lineas.append(f"    • {pkg}")
        restantes = ac.get("total_pendientes", 0) - 20
        if restantes > 0:
            lineas.append(f"    ... y {restantes} paquete(s) más.")
    for adv in ac.get("advertencias", []):
        lineas.append(f"  [⚠] {adv}")

    total_adv = sum(
        len(resultados.get(m, {}).get("advertencias", []))
        for m in ("selinux", "firewall", "usuarios", "ssh", "actualizaciones")
    )
    lineas += [
        "",
        "=" * 64,
        "RESUMEN EJECUTIVO",
        "=" * 64,
        f"  Nivel de riesgo global : {nivel_riesgo}",
        f"  Total de advertencias  : {total_adv}",
        "",
        "  RECOMENDACIONES GENERALES (DRY-RUN):",
        "  1. Configurar SELinux en modo Enforcing si no lo está.",
        "  2. Mantener firewalld/ufw activo, exponer solo puertos 22, 80 y 443.",
        "  3. Eliminar o bloquear usuarios con UID 0 que no sean root.",
        "  4. Forzar contraseñas en todas las cuentas del sistema.",
        "  5. Establecer 'PermitRootLogin no' y 'PasswordAuthentication no' en sshd_config.",
        "  6. Aplicar actualizaciones de seguridad pendientes: dnf update --security -y",
        "  7. Revisar periódicamente con este script y con Lynis / OpenSCAP.",
        "",
        f"  Reporte generado en: {ruta}",
        "=" * 64,
    ]

    contenido = "\n".join(lineas)
    try:
        escribir_reporte_seguro(ruta, contenido)
        print(f"[✔] Reporte TXT  generado: {Path(ruta).resolve()}")
    except OSError as exc:
        print(f"[✘] Error al guardar el reporte TXT: {exc}")

    return str(Path(ruta).resolve())


def generar_reporte_html(resultados: dict, ruta_salida: Optional[str] = None) -> str:
    """
    Genera un reporte en HTML limpio y legible con los resultados de la auditoría.

    Args:
        resultados:  Diccionario con los resultados de todos los módulos.
        ruta_salida: Ruta de destino. Si es None, usa el directorio de trabajo.

    Returns:
        Ruta absoluta del fichero generado.
    """
    ruta         = ruta_salida or NOMBRE_REPORTE_HTML
    nivel_riesgo = _calcular_nivel_riesgo(resultados)
    ts           = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _, hostname, _ = ejecutar_comando(["hostname", "-f"])
    hostname       = hostname or "desconocido"

    colores_riesgo: dict[str, str] = {
        "BAJO":    "#28a745",
        "MEDIO":   "#ffc107",
        "ALTO":    "#fd7e14",
        "CRÍTICO": "#dc3545",
    }
    color_riesgo = colores_riesgo.get(nivel_riesgo, "#6c757d")

    # ── Helpers HTML ──────────────────────────────────────────────────────────

    # Todo dato procedente del sistema (usuarios, config, salida de comandos)
    # pasa por esc() antes de insertarse en el HTML: evita inyección de HTML/JS.
    def esc(valor: object) -> str:
        return html.escape("N/A" if valor is None else str(valor))

    def badge(ok: bool, lbl_ok: str = "OK", lbl_fail: str = "ALERTA") -> str:
        color = "#28a745" if ok else "#dc3545"
        return (
            f'<span style="background:{color};color:#fff;padding:3px 10px;'
            f'border-radius:4px;font-size:.82em;font-weight:700">'
            f'{"✔ " + esc(lbl_ok) if ok else "✘ " + esc(lbl_fail)}</span>'
        )

    def badge_texto(texto: str, color: str = "#6c757d") -> str:
        return (
            f'<span style="background:{color};color:#fff;padding:3px 10px;'
            f'border-radius:4px;font-size:.82em;font-weight:700">{esc(texto)}</span>'
        )

    def lista_adv(advs: list[str]) -> str:
        if not advs:
            return '<p style="color:#28a745;margin:4px 0">✔ Sin advertencias.</p>'
        items = "".join(
            f'<li style="color:#c0392b;margin-bottom:3px">⚠ {esc(a)}</li>' for a in advs
        )
        return f'<ul style="margin:6px 0 0 18px;padding:0">{items}</ul>'

    def fila(label: str, value: str) -> str:
        # ``value`` es HTML ya construido: los datos dinámicos se escapan antes.
        return (
            f'<tr><td style="font-weight:600;color:#555;padding:5px 12px 5px 0;'
            f'white-space:nowrap;vertical-align:top">{label}</td>'
            f'<td style="padding:5px 0;vertical-align:top">{value}</td></tr>'
        )

    # ── Preparar datos de módulos ──────────────────────────────────────────────
    sl = resultados.get("selinux", {})
    fw = resultados.get("firewall", {})
    u  = resultados.get("usuarios", {})
    s  = resultados.get("ssh", {})
    ac = resultados.get("actualizaciones", {})

    total_adv = sum(
        len(resultados.get(m, {}).get("advertencias", []))
        for m in ("selinux", "firewall", "usuarios", "ssh", "actualizaciones")
    )

    # ── HTML tabla de directivas SSH peligrosas ───────────────────────────────
    if s.get("directivas_riesgo"):
        rows_ssh = "".join(
            f'<tr style="background:#fff5f5">'
            f'<td style="padding:5px 10px;color:#c0392b;font-weight:700">Línea {esc(h["linea_num"])}</td>'
            f'<td style="padding:5px 10px;font-family:monospace">{esc(h["directiva"])} {esc(h["valor"])}</td>'
            f'<td style="padding:5px 10px;color:#7f0000">{esc(h["descripcion"])}</td>'
            f'</tr>'
            for h in s["directivas_riesgo"]
        )
        ssh_directivas_html = f"""
        <table style="width:100%;border-collapse:collapse;margin-top:8px;font-size:.88em">
          <thead>
            <tr style="background:#f8d7da">
              <th style="padding:6px 10px;text-align:left">Línea</th>
              <th style="padding:6px 10px;text-align:left">Directiva activa</th>
              <th style="padding:6px 10px;text-align:left">Descripción del riesgo</th>
            </tr>
          </thead>
          <tbody>{rows_ssh}</tbody>
        </table>"""
    else:
        ssh_directivas_html = (
            '<p style="color:#28a745;margin:6px 0">'
            '✔ No se detectaron directivas SSH de alto riesgo.</p>'
        )

    # ── HTML lista de paquetes pendientes ─────────────────────────────────────
    color_estado_ac = "#28a745" if ac.get("ok") else "#dc3545"
    if ac.get("paquetes_pendientes"):
        items_pkg = "".join(
            f'<li style="font-family:monospace;font-size:.85em;margin-bottom:2px">{esc(pkg)}</li>'
            for pkg in ac["paquetes_pendientes"][:25]
        )
        restantes = ac.get("total_pendientes", 0) - 25
        extra = (
            f'<li style="color:#888;font-style:italic">... y {restantes} paquete(s) más.</li>'
            if restantes > 0 else ""
        )
        paquetes_html = f'<ul style="margin:8px 0 0 18px;padding:0">{items_pkg}{extra}</ul>'
    else:
        paquetes_html = ""

    documento = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Auditoría de Seguridad — {esc(hostname)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', system-ui, Arial, sans-serif;
      background: #eef1f5; color: #2c3e50;
      margin: 0; padding: 24px; font-size: 14px; line-height: 1.55;
    }}
    .wrap {{
      max-width: 980px; margin: 0 auto; background: #fff;
      border-radius: 10px; box-shadow: 0 3px 18px rgba(0,0,0,.12); overflow: hidden;
    }}
    .hdr {{
      background: linear-gradient(135deg, #1a252f 0%, #2c3e50 100%);
      color: #fff; padding: 30px 36px;
    }}
    .hdr h1 {{ margin: 0 0 6px; font-size: 1.55em; letter-spacing: -.3px; }}
    .hdr p  {{ margin: 0; font-size: .88em; opacity: .7; }}
    .meta {{
      display: flex; flex-wrap: wrap; gap: 14px 28px;
      padding: 13px 36px; background: #f8f9fa;
      border-bottom: 1px solid #dee2e6; font-size: .86em;
    }}
    .meta b {{ color: #1a252f; }}
    .sec {{ padding: 22px 36px; border-bottom: 1px solid #e9ecef; }}
    .sec h2 {{
      margin: 0 0 14px; font-size: 1em; color: #1a252f;
      border-left: 4px solid #3498db; padding-left: 11px;
    }}
    table.props {{ border-collapse: collapse; width: 100%; }}
    .risk {{
      margin: 22px 36px 30px; padding: 20px 26px;
      border-radius: 8px; background: #f8f9fa;
      border: 2px solid {color_riesgo};
    }}
    .risk h2 {{ margin: 0 0 12px; color: {color_riesgo}; font-size: 1.15em; }}
    .risk ul {{ margin: 0 0 0 18px; padding: 0; font-size: .9em; color: #444; }}
    .risk li {{ margin-bottom: 6px; }}
    .risk li b {{ color: #1a252f; }}
    .risk code {{ background:#eee; padding:1px 5px; border-radius:3px; font-size:.9em; }}
    .ftr {{
      text-align: center; padding: 13px; font-size: .76em; color: #aaa;
      background: #f8f9fa; border-top: 1px solid #dee2e6;
    }}
    @media (max-width: 600px) {{
      .hdr, .sec, .meta, .risk {{ padding-left: 16px; padding-right: 16px; }}
    }}
  </style>
</head>
<body>
<div class="wrap">

  <div class="hdr">
    <h1>🔐 Reporte de Auditoría de Seguridad</h1>
    <p>jaimefg1888 · GhostCheck · Modo DRY-RUN — solo lectura, sin cambios en el sistema</p>
  </div>

  <div class="meta">
    <span><b>Fecha:</b> {ts}</span>
    <span><b>Hostname:</b> {esc(hostname)}</span>
    <span><b>Módulos ejecutados:</b> 6</span>
    <span><b>Total advertencias:</b> {total_adv}</span>
    <span><b>Nivel de riesgo:</b>
      <span style="color:{color_riesgo};font-weight:700">{nivel_riesgo}</span>
    </span>
  </div>

  <!-- [2] SELinux -->
  <div class="sec">
    <h2>[2] Auditoría de SELinux</h2>
    <table class="props">
      {fila("Estado:", badge(sl.get('ok', False), sl.get('estado','N/A'), sl.get('estado','N/A')))}
      {fila("Modo:", esc(sl.get('modo')))}
      {fila("Política cargada:", esc(sl.get('politica')))}
      {fila("Advertencias:", lista_adv(sl.get('advertencias', [])))}
    </table>
  </div>

  <!-- [3] Firewall -->
  <div class="sec">
    <h2>[3] Gestión de Firewall</h2>
    <table class="props">
      {fila("Herramienta:", esc(fw.get('herramienta')))}
      {fila("Estado:", badge(fw.get('activo', False), 'Activo', 'Inactivo'))}
      {fila("Puertos abiertos:", esc(', '.join(fw.get('puertos_abiertos', [])) or '—'))}
      {fila("Puertos a revisar:",
        f'<span style="color:#e74c3c;font-weight:700">'
        f'{esc(", ".join(fw.get("puertos_a_revisar", [])) or "—")}</span>')}
      {fila("Advertencias:", lista_adv(fw.get('advertencias', [])))}
    </table>
  </div>

  <!-- [4] Usuarios -->
  <div class="sec">
    <h2>[4] Auditoría de Usuarios</h2>
    <table class="props">
      {fila("Entradas en /etc/passwd:", str(u.get('total_usuarios', 0)))}
      {fila("UID 0 (≠ root):",
        f'<span style="color:#e74c3c;font-weight:700">'
        f'{esc(", ".join(u.get("usuarios_uid0_no_root", [])) or "✔ Ninguno")}</span>')}
      {fila("Sin contraseña:",
        f'<span style="color:#e74c3c;font-weight:700">'
        f'{esc(", ".join(u.get("cuentas_sin_contrasena", [])) or "✔ Ninguna")}</span>')}
      {fila("Advertencias:", lista_adv(u.get('advertencias', [])))}
    </table>
  </div>

  <!-- [5] SSH -->
  <div class="sec">
    <h2>[5] Auditoría de SSH
      <span style="font-size:.75em;color:#888;font-weight:400">(sshd_config)</span>
    </h2>
    <table class="props">
      {fila("Archivo analizado:", f'<code style="background:#eee;padding:1px 5px;border-radius:3px">{esc(s.get("ruta_config", RUTA_SSHD_CFG))}</code>')}
      {fila("Puerto SSH activo:", esc(s.get('puerto_ssh','22')))}
      {fila("Estado:", badge(
        s.get('ok', False),
        'Sin riesgos detectados',
        f'{len(s.get("directivas_riesgo", []))} directiva(s) de riesgo'
      ))}
      {fila("Directivas peligrosas:", ssh_directivas_html)}
      {fila("Advertencias:", lista_adv(s.get('advertencias', [])))}
    </table>
  </div>

  <!-- [6] Actualizaciones -->
  <div class="sec">
    <h2>[6] Actualizaciones de Seguridad
      <span style="font-size:.75em;color:#888;font-weight:400">(dnf check-update --security)</span>
    </h2>
    <table class="props">
      {fila("Gestor de paquetes:", esc(ac.get('gestor')))}
      {fila("Estado:", badge_texto(ac.get('estado','N/A'), color_estado_ac))}
      {fila("Paquetes pendientes:",
        f'<span style="color:{color_estado_ac};font-weight:700">{esc(ac.get("total_pendientes", 0))}</span>')}
      {fila("Listado:", paquetes_html) if paquetes_html else ""}
      {fila("Advertencias:", lista_adv(ac.get('advertencias', [])))}
    </table>
  </div>

  <!-- Resumen ejecutivo -->
  <div class="risk">
    <h2>📋 Resumen Ejecutivo — Nivel de riesgo: {nivel_riesgo}</h2>
    <ul>
      <li>Configurar SELinux en modo <b>Enforcing</b>
          (<code>/etc/selinux/config</code> → <code>SELINUX=enforcing</code>).</li>
      <li>Verificar que <b>firewalld / ufw</b> esté activo
          y solo exponga los puertos 22, 80 y 443.</li>
      <li>Eliminar o bloquear cualquier usuario con <b>UID 0</b> distinto de root.</li>
      <li>Forzar contraseñas en todas las cuentas del sistema
          (<code>passwd &lt;usuario&gt;</code>).</li>
      <li>Establecer <b>PermitRootLogin no</b> y <b>PasswordAuthentication no</b>
          en <code>/etc/ssh/sshd_config</code> y reiniciar con
          <code>systemctl restart sshd</code>.</li>
      <li>Aplicar todas las actualizaciones de seguridad pendientes:
          <code>sudo dnf update --security -y</code>.</li>
      <li>Programar ejecuciones periódicas de este script y complementar con
          <b>Lynis</b> u <b>OpenSCAP / SCAP Security Guide</b>.</li>
    </ul>
  </div>

  <div class="ftr">
    Generado por <b>GhostCheck</b> · jaimefg1888 ·
    DRY-RUN — No se realizó ningún cambio en el sistema
  </div>

</div>
</body>
</html>"""

    try:
        escribir_reporte_seguro(ruta, documento)
        print(f"[✔] Reporte HTML generado: {Path(ruta).resolve()}")
    except OSError as exc:
        print(f"[✘] Error al guardar el reporte HTML: {exc}")

    return str(Path(ruta).resolve())


# ─────────────────────────────────────────────────────────────────────────────
# FUNCIÓN PRINCIPAL — Orquestador del pipeline de auditoría
# ─────────────────────────────────────────────────────────────────────────────

def parsear_argumentos(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Define y procesa los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        prog="ghostcheck",
        description="Auditoría de seguridad para servidores Linux / RHEL (modo DRY-RUN).",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directorio donde se guardan los reportes (por defecto: el actual).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    """
    Punto de entrada principal. Orquesta las 6 fases de auditoría
    y genera los reportes finales en TXT y HTML.

    Pipeline de ejecución:
      [1] Verificación de privilegios root
      [2] Auditoría de SELinux
      [3] Auditoría de Firewall
      [4] Auditoría de Usuarios
      [5] Auditoría de SSH
      [6] Auditoría de Actualizaciones
      [7] Generación de reportes TXT + HTML
    """
    args = parsear_argumentos(argv)
    if not os.path.isdir(args.output_dir):
        print(f"[✘ ERROR] El directorio de salida no existe: {args.output_dir}")
        sys.exit(2)

    print("\n" + "=" * 64)
    print("  GHOSTCHECK  —  jaimefg1888")
    print("  Modo: DRY-RUN — Sin cambios destructivos en el sistema")
    print("=" * 64 + "\n")

    # ── [1] Control de privilegios (termina si no es root) ────────────────────
    verificar_root()

    # ── Contenedor de resultados de todos los módulos ─────────────────────────
    resultados: dict = {}

    # ── [2] Auditoría SELinux ─────────────────────────────────────────────────
    resultados["selinux"] = auditar_selinux()

    # ── [3] Gestión de Firewall ───────────────────────────────────────────────
    resultados["firewall"] = auditar_firewall()

    # ── [4] Auditoría de Usuarios ─────────────────────────────────────────────
    resultados["usuarios"] = auditar_usuarios()

    # ── [5] Auditoría de SSH ──────────────────────────────────────────────────
    resultados["ssh"] = auditar_ssh()

    # ── [6] Auditoría de Actualizaciones de Seguridad ─────────────────────────
    resultados["actualizaciones"] = auditar_actualizaciones()

    # ── [7] Generación de reportes ────────────────────────────────────────────
    print("=" * 64)
    print("  [7] GENERACIÓN DE REPORTES")
    print("=" * 64)
    ruta_txt  = generar_reporte_txt(resultados, os.path.join(args.output_dir, NOMBRE_REPORTE_TXT))
    ruta_html = generar_reporte_html(resultados, os.path.join(args.output_dir, NOMBRE_REPORTE_HTML))

    # Nivel de riesgo con color ANSI en terminal
    nivel = _calcular_nivel_riesgo(resultados)
    color_map: dict[str, str] = {
        "BAJO":    "\033[32m",   # verde
        "MEDIO":   "\033[33m",   # amarillo
        "ALTO":    "\033[91m",   # naranja/rojo claro
        "CRÍTICO": "\033[31m",   # rojo
    }
    reset = "\033[0m"
    color = color_map.get(nivel, "")

    print(f"\n{'=' * 64}")
    print(f"  Auditoría completada — Nivel de riesgo: {color}{nivel}{reset}")
    print(f"  TXT  → {ruta_txt}")
    print(f"  HTML → {ruta_html}")
    print(f"{'=' * 64}\n")


if __name__ == "__main__":
    main()
