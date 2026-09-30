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

# Puertos considerados esenciales (SSH, HTTP, HTTPS). Solo cuentan en TCP.
# Los puertos en los que escucha sshd se añaden a esta lista en tiempo de ejecución.
PUERTOS_ESENCIALES: set[str] = {"22", "80", "443"}

# Rutas clave del sistema
RUTA_PASSWD:    str = "/etc/passwd"
RUTA_SHADOW:    str = "/etc/shadow"
RUTA_SSHD_CFG: str = "/etc/ssh/sshd_config"
RUTA_SELINUX_CFG: str = "/etc/selinux/config"

# ─────────────────────────────────────────────────────────────────────────────
# NIVELES DE RIESGO — Tabla explícita hallazgo → severidad
# ─────────────────────────────────────────────────────────────────────────────
# El nivel de riesgo global es la severidad MÁXIMA de los hallazgos.
# Las comprobaciones que no se pudieron realizar (errores) NO suben el nivel:
# marcan la auditoría como INCOMPLETA.

NIVELES_RIESGO: tuple[str, ...] = ("BAJO", "MEDIO", "ALTO", "CRÍTICO")

SEVERIDADES: dict[str, str] = {
    # CRÍTICO — exposición directa a nivel root: actuar de inmediato
    "usuario_uid0_no_root":        "CRÍTICO",
    "cuenta_sin_contrasena":       "CRÍTICO",
    "ssh_permit_root_login":       "CRÍTICO",
    "ssh_permit_empty_passwords":  "CRÍTICO",
    # ALTO — una capa de defensa principal falla
    "selinux_deshabilitado":       "ALTO",
    "firewall_ausente":            "ALTO",
    "firewall_inactivo":           "ALTO",
    "actualizaciones_seguridad":   "ALTO",
    "ssh_password_authentication": "ALTO",
    "ssh_protocol_1":              "ALTO",
    # MEDIO — debilidades que conviene revisar
    "selinux_permissive":          "MEDIO",
    "selinux_no_persistente":      "MEDIO",
    "selinux_no_disponible":       "MEDIO",
    "puertos_no_esenciales":       "MEDIO",
    "firewall_reglas_a_revisar":   "MEDIO",
    "ssh_x11_forwarding":          "MEDIO",
    "ssh_riesgo_condicional":      "MEDIO",
}

# Módulos cuyos resultados se agregan en el resumen y el nivel de riesgo
MODULOS: tuple[str, ...] = ("selinux", "firewall", "usuarios", "ssh", "actualizaciones")

# Directivas de sshd_config consideradas de riesgo.
# Formato: { "directiva_en_minúsculas": (nombre, valor_peligroso, código_hallazgo) }
SSHD_DIRECTIVAS_RIESGO: dict[str, tuple[str, str, str]] = {
    "permitrootlogin":        ("PermitRootLogin",        "yes", "ssh_permit_root_login"),
    "passwordauthentication": ("PasswordAuthentication", "yes", "ssh_password_authentication"),
    "permitemptypasswords":   ("PermitEmptyPasswords",   "yes", "ssh_permit_empty_passwords"),
    "x11forwarding":          ("X11Forwarding",          "yes", "ssh_x11_forwarding"),
    "protocol":               ("Protocol",               "1",   "ssh_protocol_1"),
}

SSHD_DESCRIPCIONES: dict[str, str] = {
    "permitrootlogin":        "Permite login directo como root vía SSH — vector de ataque primario.",
    "passwordauthentication": "Permite autenticación por contraseña — vulnerable a fuerza bruta.",
    "permitemptypasswords":   "Permite login SSH sin contraseña — riesgo CRÍTICO.",
    "x11forwarding":          "Reenvío X11 activo — aumenta la superficie de ataque.",
    "protocol":               "SSHv1 habilitado — protocolo obsoleto con vulnerabilidades conocidas.",
}

# Valores por defecto de OpenSSH cuando la directiva no aparece en la
# configuración (solo se usan si `sshd -T` no está disponible).
SSHD_VALORES_DEFECTO: dict[str, str] = {
    "permitrootlogin":        "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords":   "no",
    "x11forwarding":          "no",
}

# Profundidad máxima de Include anidados (la misma que usa sshd)
SSHD_MAX_PROFUNDIDAD_INCLUDE: int = 16

# Lista blanca de comandos de SOLO LECTURA que GhostCheck puede ejecutar.
# Cada entrada es una plantilla: una tupla de expresiones regulares que deben
# casar completas, posición a posición, con cada argumento del comando.
# Cualquier comando que no case con alguna plantilla se bloquea sin ejecutarse,
# lo que garantiza el modo DRY-RUN aunque un futuro cambio introduzca un error.
COMANDOS_PERMITIDOS: tuple[tuple[str, ...], ...] = (
    ("getenforce",),
    ("sestatus",),
    ("systemctl", "is-active", "firewalld"),
    ("firewall-cmd", "--get-default-zone"),
    ("firewall-cmd", "--get-active-zones"),
    ("firewall-cmd", r"--list-(?:ports|services|rich-rules|forward-ports)", r"--zone=[\w.-]+"),
    ("firewall-cmd", r"--info-service=[\w.-]+"),
    ("ufw", "status", "verbose"),
    ("ufw", "app", "info", r"[\w .+-]+"),
    ("sshd", "-T", "-f", r"/[\w./-]+"),
    ("dnf", "-q", "updateinfo", "list", "--security"),
    ("dnf", "-q", "-C", "updateinfo", "list", "--security"),
    ("hostname", "-f"),
)

# Entorno de los comandos: locale C para que la salida no dependa del idioma
ENTORNO_COMANDOS: dict[str, str] = {**os.environ, "LC_ALL": "C", "LANG": "C"}

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
            env=ENTORNO_COMANDOS,
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
# UTILIDAD — Registro de hallazgos y de comprobaciones no realizadas
# ─────────────────────────────────────────────────────────────────────────────

def _nuevo_resultado(**campos) -> dict:
    """Crea el diccionario base de resultados de un módulo."""
    return {**campos, "hallazgos": [], "advertencias": [], "errores": [], "ok": True}


def _registrar_hallazgo(resultado: dict, codigo: str, mensaje: str) -> None:
    """
    Registra un hallazgo de seguridad. Su severidad sale de la tabla
    SEVERIDADES, que es la única fuente del nivel de riesgo global.
    """
    resultado["hallazgos"].append(
        {"codigo": codigo, "severidad": SEVERIDADES[codigo], "mensaje": mensaje}
    )
    resultado["advertencias"].append(mensaje)
    resultado["ok"] = False


def _registrar_error(resultado: dict, mensaje: str) -> None:
    """
    Registra una comprobación que NO se pudo realizar. No sube el nivel de
    riesgo, pero marca la auditoría como INCOMPLETA.
    """
    resultado["errores"].append(mensaje)
    resultado["ok"] = False


# ─────────────────────────────────────────────────────────────────────────────
# [2] AUDITORÍA DE SELINUX
# ─────────────────────────────────────────────────────────────────────────────

def _leer_modo_selinux_persistente() -> Optional[str]:
    """
    Devuelve el modo configurado en /etc/selinux/config (el que se aplicará
    tras reiniciar), en minúsculas, o None si no se puede determinar.
    """
    try:
        with open(RUTA_SELINUX_CFG, "r", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                coincidencia = re.match(r"\s*SELINUX\s*=\s*(\w+)", linea)
                if coincidencia:
                    return coincidencia.group(1).lower()
    except OSError:
        return None
    return None


def auditar_selinux() -> dict:
    """
    Comprueba el estado de SELinux: modo en ejecución (`getenforce`),
    política cargada (`sestatus`) y modo persistente (/etc/selinux/config).

    Returns:
        Diccionario con estado, modo, política, hallazgos y errores.
    """
    print("=" * 64)
    print("  [2] AUDITORÍA DE SELINUX")
    print("=" * 64)

    resultado = _nuevo_resultado(
        herramienta="SELinux",
        estado="DESCONOCIDO",
        modo=None,
        modo_persistente=None,
        politica=None,
    )

    codigo, stdout, stderr = ejecutar_comando(["getenforce"])

    if codigo == -1:
        adv = "SELinux no está instalado o no está disponible en este sistema."
        _registrar_hallazgo(resultado, "selinux_no_disponible", adv)
        resultado["estado"] = "NO_DISPONIBLE"
        print(f"  [⚠] {adv}")
        print()
        return resultado

    if codigo != 0:
        err = f"Error al ejecutar getenforce: {stderr or stdout}"
        _registrar_error(resultado, err)
        resultado["estado"] = "ERROR"
        print(f"  [?] {err}")
        print()
        return resultado

    modo = stdout.strip()
    resultado["modo"] = modo

    # Obtener política cargada con sestatus
    codigo_s, stdout_s, _ = ejecutar_comando(["sestatus"])
    if codigo_s == 0:
        for linea in stdout_s.splitlines():
            if "Loaded policy name" in linea:
                resultado["politica"] = linea.split(":", 1)[1].strip()

    persistente = _leer_modo_selinux_persistente()
    resultado["modo_persistente"] = persistente

    if modo == "Enforcing":
        resultado["estado"] = "OK"
        print("  [✔] SELinux está en modo: Enforcing")
        print(f"  [i] Política cargada: {resultado['politica'] or 'N/A'}")
        if persistente and persistente != "enforcing":
            adv = (
                f"SELinux está en Enforcing pero {RUTA_SELINUX_CFG} indica "
                f"SELINUX={persistente}: el cambio NO sobrevivirá a un reinicio."
            )
            _registrar_hallazgo(resultado, "selinux_no_persistente", adv)
            print(f"  [⚠] {adv}")

    elif modo == "Permissive":
        adv = "SELinux en modo PERMISSIVE: las políticas se registran pero NO se aplican."
        resultado["estado"] = "ADVERTENCIA"
        _registrar_hallazgo(resultado, "selinux_permissive", adv)
        print(f"  [⚠] {adv}")
        print(f"      Recomendación: Cambiar a Enforcing en {RUTA_SELINUX_CFG}")

    elif modo == "Disabled":
        adv = "SELinux DESHABILITADO: el sistema carece de control de acceso obligatorio (MAC)."
        resultado["estado"] = "DESHABILITADO"
        _registrar_hallazgo(resultado, "selinux_deshabilitado", adv)
        print(f"  [✘] {adv}")
        print("      Recomendación: Habilitar SELinux y reiniciar el sistema.")

    else:
        err = f"Estado de SELinux desconocido: '{modo}'"
        resultado["estado"] = "DESCONOCIDO"
        _registrar_error(resultado, err)
        print(f"  [?] {err}")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [3] GESTIÓN DE FIREWALL
# ─────────────────────────────────────────────────────────────────────────────

# Respaldo si `firewall-cmd --info-service` no responde
MAPA_SERVICIOS_FIREWALLD: dict[str, list[str]] = {
    "ssh": ["22/tcp"], "http": ["80/tcp"], "https": ["443/tcp"],
    "ftp": ["21/tcp"], "smtp": ["25/tcp"], "dns": ["53/tcp", "53/udp"],
    "mysql": ["3306/tcp"], "postgresql": ["5432/tcp"], "cockpit": ["9090/tcp"],
    "dhcpv6-client": ["546/udp"],
}

# Respaldo si `ufw app info` no responde. Se evalúan en orden, así que las
# variantes 'full' (80+443) van antes que 'http' y 'https' por separado.
PERFILES_APP_UFW: list[tuple[str, list[str]]] = [
    ("nginx full",    ["80/tcp", "443/tcp"]),
    ("apache full",   ["80/tcp", "443/tcp"]),
    ("nginx https",   ["443/tcp"]),
    ("nginx http",    ["80/tcp"]),
    ("apache secure", ["443/tcp"]),
    ("apache",        ["80/tcp"]),
    ("openssh",       ["22/tcp"]),
]


def _normalizar_puertos(especificacion: str) -> list[str]:
    """
    Convierte una especificación de puertos en una lista normalizada
    "puerto/protocolo" (o solo "puerto" si no indica protocolo).

    Ejemplos:
        "8080/tcp"      → ["8080/tcp"]
        "80,443/tcp"    → ["80/tcp", "443/tcp"]
        "6000:6007/tcp" → ["6000-6007/tcp"]
        "53"            → ["53"]
    """
    numeros, _, protocolo = especificacion.strip().partition("/")
    sufijo = f"/{protocolo.lower()}" if protocolo else ""
    return [
        n.strip().replace(":", "-") + sufijo
        for n in numeros.split(",")
        if n.strip()
    ]


def _es_puerto_esencial(puerto: str, esenciales: set[str]) -> bool:
    """Un puerto es esencial si su número está en la lista y es TCP (o sin protocolo)."""
    numero, _, protocolo = puerto.partition("/")
    return numero in esenciales and protocolo in ("", "tcp")


def _zonas_firewalld(resultado: dict) -> list[str]:
    """Zona por defecto + zonas activas (con interfaces o fuentes asignadas)."""
    zonas: list[str] = []
    codigo_d, stdout_d, _ = ejecutar_comando(["firewall-cmd", "--get-default-zone"])
    if codigo_d == 0 and stdout_d:
        zonas.append(stdout_d.split()[0])

    codigo_a, stdout_a, _ = ejecutar_comando(["firewall-cmd", "--get-active-zones"])
    if codigo_a == 0:
        for linea in stdout_a.splitlines():
            # Los nombres de zona no van indentados; sus propiedades sí.
            if linea and not linea[0].isspace():
                zona = linea.split()[0]
                if zona not in zonas:
                    zonas.append(zona)

    if not zonas:
        _registrar_error(
            resultado,
            "No se pudieron obtener las zonas de firewalld; se audita solo la zona 'public'.",
        )
        zonas = ["public"]
    return zonas


def _puertos_servicio_firewalld(servicio: str) -> Optional[list[str]]:
    """Puertos de un servicio de firewalld según `firewall-cmd --info-service`."""
    codigo, stdout, _ = ejecutar_comando(["firewall-cmd", f"--info-service={servicio}"])
    if codigo == 0:
        for linea in stdout.splitlines():
            linea = linea.strip()
            if linea.startswith("ports:"):
                puertos: list[str] = []
                for especificacion in linea[len("ports:"):].split():
                    puertos.extend(_normalizar_puertos(especificacion))
                return puertos
    return MAPA_SERVICIOS_FIREWALLD.get(servicio)


def _auditar_firewalld(esenciales: set[str]) -> dict:
    """Audita firewalld en todas las zonas activas (RHEL / CentOS / Fedora / Rocky)."""
    resultado = _nuevo_resultado(
        herramienta="firewalld",
        activo=False,
        zonas=[],
        puertos_abiertos=[],
        puertos_a_revisar=[],
        detalle_puertos=[],   # list[dict]: zona, puerto, origen (puerto | servicio)
    )

    codigo, stdout, _ = ejecutar_comando(["systemctl", "is-active", "firewalld"])
    if codigo != 0 or stdout != "active":
        _registrar_hallazgo(
            resultado, "firewall_inactivo",
            "firewalld no está activo. El sistema puede estar expuesto.",
        )
        print("  [✘] firewalld NO está activo.")
        return resultado

    resultado["activo"] = True
    print("  [✔] firewalld está activo.")

    zonas = _zonas_firewalld(resultado)
    resultado["zonas"] = zonas
    print(f"  [i] Zonas auditadas: {', '.join(zonas)}")

    for zona in zonas:
        listas: dict[str, list[str]] = {}
        for tipo in ("ports", "services", "rich-rules", "forward-ports"):
            codigo_l, stdout_l, stderr_l = ejecutar_comando(
                ["firewall-cmd", f"--list-{tipo}", f"--zone={zona}"]
            )
            if codigo_l != 0:
                _registrar_error(
                    resultado, f"Zona {zona}: no se pudo obtener --list-{tipo}: {stderr_l or codigo_l}"
                )
                listas[tipo] = []
            elif tipo == "rich-rules":
                listas[tipo] = [r for r in stdout_l.splitlines() if r.strip()]
            else:
                listas[tipo] = stdout_l.split()

        for especificacion in listas["ports"]:
            for puerto in _normalizar_puertos(especificacion):
                resultado["detalle_puertos"].append(
                    {"zona": zona, "puerto": puerto, "origen": "puerto"}
                )

        for servicio in listas["services"]:
            puertos_srv = _puertos_servicio_firewalld(servicio)
            if puertos_srv is None:
                _registrar_hallazgo(
                    resultado, "firewall_reglas_a_revisar",
                    f"Zona {zona}: no se pudieron resolver los puertos del servicio '{servicio}'.",
                )
                continue
            for puerto in puertos_srv:
                resultado["detalle_puertos"].append(
                    {"zona": zona, "puerto": puerto, "origen": f"servicio:{servicio}"}
                )

        if listas["rich-rules"]:
            _registrar_hallazgo(
                resultado, "firewall_reglas_a_revisar",
                f"Zona {zona}: {len(listas['rich-rules'])} regla(s) rich que deben revisarse manualmente.",
            )
        if listas["forward-ports"]:
            _registrar_hallazgo(
                resultado, "firewall_reglas_a_revisar",
                f"Zona {zona}: {len(listas['forward-ports'])} redirección(es) de puertos activas.",
            )

    resultado["puertos_abiertos"] = sorted({d["puerto"] for d in resultado["detalle_puertos"]})
    a_revisar = [
        d for d in resultado["detalle_puertos"] if not _es_puerto_esencial(d["puerto"], esenciales)
    ]
    resultado["puertos_a_revisar"] = sorted({d["puerto"] for d in a_revisar})

    print(f"  [i] Puertos abiertos: {', '.join(resultado['puertos_abiertos']) or 'ninguno'}")

    if a_revisar:
        msg = f"Puertos no esenciales detectados: {', '.join(resultado['puertos_a_revisar'])}"
        _registrar_hallazgo(resultado, "puertos_no_esenciales", msg)
        print(f"  [⚠] {msg}")
        print("      Recomendación (DRY-RUN): evaluar y, si procede, cerrar con:")
        vistos: set[str] = set()
        for d in a_revisar:
            if d["origen"].startswith("servicio:"):
                orden = (
                    f"firewall-cmd --permanent --zone={d['zona']} "
                    f"--remove-service={d['origen'].split(':', 1)[1]}"
                )
            else:
                orden = f"firewall-cmd --permanent --zone={d['zona']} --remove-port={d['puerto']}"
            if orden not in vistos:
                vistos.add(orden)
                print(f"        {orden}")
        print("        firewall-cmd --reload")
    elif not resultado["hallazgos"]:
        print("  [✔] Solo están abiertos los puertos esenciales.")

    for adv in resultado["advertencias"]:
        if not adv.startswith("Puertos no esenciales"):
            print(f"  [⚠] {adv}")

    return resultado


def _puertos_perfil_ufw(perfil: str) -> Optional[list[str]]:
    """Puertos de un perfil de aplicación UFW (`ufw app info`, con respaldo estático)."""
    codigo, stdout, _ = ejecutar_comando(["ufw", "app", "info", perfil])
    if codigo == 0 and "Ports:" in stdout:
        puertos: list[str] = []
        for linea in stdout.split("Ports:", 1)[1].splitlines():
            if linea.strip():
                puertos.extend(_normalizar_puertos(linea.strip()))
        if puertos:
            return puertos
    perfil_lower = perfil.lower()
    for fragmento, puertos_fijos in PERFILES_APP_UFW:
        if fragmento in perfil_lower:
            return puertos_fijos
    return None


def _auditar_ufw(esenciales: set[str]) -> dict:
    """
    Audita el firewall mediante UFW (Debian / Ubuntu).

    Interpreta la tabla de `ufw status verbose` por columnas (To / Action /
    From) y solo tiene en cuenta reglas de entrada (ALLOW/LIMIT IN):
      - "22/tcp", "80,443/tcp", "6000:6007/tcp" → puertos normalizados.
      - "Anywhere" → la regla permite TODO el tráfico desde el origen.
      - Nombre de perfil ("Nginx Full") → se resuelve con `ufw app info`.
    """
    resultado = _nuevo_resultado(
        herramienta="ufw",
        activo=False,
        puertos_abiertos=[],
        puertos_a_revisar=[],
    )

    codigo, stdout, stderr = ejecutar_comando(["ufw", "status", "verbose"])
    if codigo != 0:
        _registrar_error(resultado, f"No se pudo obtener el estado de UFW: {stderr or codigo}")
        print("  [?] No se pudo obtener el estado de UFW.")
        return resultado

    if re.search(r"(?im)^status:\s*inactive", stdout):
        _registrar_hallazgo(
            resultado, "firewall_inactivo", "UFW está INACTIVO. El sistema puede estar expuesto."
        )
        print("  [✘] UFW NO está activo.")
        return resultado

    resultado["activo"] = True
    print("  [✔] UFW está activo.")

    puertos_detectados: set[str] = set()
    for linea in stdout.splitlines():
        columnas = re.split(r"\s{2,}", linea.strip())
        if len(columnas) < 3:
            continue
        destino, accion, origen = columnas[0], columnas[1].upper(), columnas[2]
        if not re.fullmatch(r"(ALLOW|LIMIT)(\s+IN)?", accion):
            continue

        destino = re.sub(r"\s*\(v6\)", "", destino)
        destino = re.sub(r"\s+on\s+\S+$", "", destino).strip()
        origen = re.sub(r"\s*\(v6\)", "", origen).strip()

        if destino.lower() == "anywhere":
            _registrar_hallazgo(
                resultado, "firewall_reglas_a_revisar",
                f"Regla UFW que permite TODO el tráfico entrante desde {origen}.",
            )
        elif re.fullmatch(r"[\d,:]+(/(tcp|udp))?", destino, re.IGNORECASE):
            puertos_detectados.update(_normalizar_puertos(destino))
        else:
            puertos_perfil = _puertos_perfil_ufw(destino)
            if puertos_perfil is None:
                _registrar_hallazgo(
                    resultado, "firewall_reglas_a_revisar",
                    f"No se pudieron resolver los puertos del perfil UFW '{destino}'.",
                )
            else:
                print(f"      • Perfil {destino} → {', '.join(puertos_perfil)}")
                puertos_detectados.update(puertos_perfil)

    resultado["puertos_abiertos"] = sorted(puertos_detectados)
    resultado["puertos_a_revisar"] = [
        p for p in resultado["puertos_abiertos"] if not _es_puerto_esencial(p, esenciales)
    ]

    print(f"  [i] Puertos permitidos: {', '.join(resultado['puertos_abiertos']) or 'ninguno'}")

    if resultado["puertos_a_revisar"]:
        msg = f"Puertos no esenciales detectados: {', '.join(resultado['puertos_a_revisar'])}"
        _registrar_hallazgo(resultado, "puertos_no_esenciales", msg)
        print(f"  [⚠] {msg}")
        print("      Recomendación (DRY-RUN): evaluar y, si procede, cerrar con:")
        for p in resultado["puertos_a_revisar"]:
            print(f"        ufw delete allow {p.replace('-', ':')}")
    elif not resultado["hallazgos"]:
        print("  [✔] Solo están abiertos los puertos esenciales.")

    for adv in resultado["advertencias"]:
        if not adv.startswith("Puertos no esenciales"):
            print(f"  [⚠] {adv}")

    return resultado


def auditar_firewall(puertos_ssh: Optional[list[str]] = None) -> dict:
    """
    Detecta automáticamente si el sistema usa firewalld o ufw
    y delega en la función de auditoría correspondiente.

    Args:
        puertos_ssh: Puertos en los que escucha sshd; se consideran esenciales.

    Returns:
        Diccionario con los resultados del firewall.
    """
    print("=" * 64)
    print("  [3] GESTIÓN DE FIREWALL")
    print("=" * 64)

    esenciales = PUERTOS_ESENCIALES | set(puertos_ssh or [])

    if shutil.which("firewall-cmd"):
        print("  [i] Gestor detectado: firewalld (RHEL/CentOS/Rocky/Fedora)\n")
        resultado = _auditar_firewalld(esenciales)
    elif shutil.which("ufw"):
        print("  [i] Gestor detectado: UFW (Debian/Ubuntu)\n")
        resultado = _auditar_ufw(esenciales)
    else:
        resultado = _nuevo_resultado(
            herramienta="ninguno",
            activo=False,
            puertos_abiertos=[],
            puertos_a_revisar=[],
        )
        _registrar_hallazgo(
            resultado, "firewall_ausente",
            "No se encontró firewalld ni ufw. El sistema NO tiene firewall gestionado.",
        )
        print("  [✘] No se encontró ningún gestor de firewall (firewalld / ufw).")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [4] AUDITORÍA DE USUARIOS (ACLs / PERMISOS)
# ─────────────────────────────────────────────────────────────────────────────

def _cuenta_sin_contrasena(resultado: dict, usuario: str, fichero: str) -> None:
    if usuario in resultado["cuentas_sin_contrasena"]:
        return
    adv = f"Cuenta '{usuario}' tiene contraseña VACÍA en {fichero}."
    resultado["cuentas_sin_contrasena"].append(usuario)
    _registrar_hallazgo(resultado, "cuenta_sin_contrasena", adv)
    print(f"  [✘] CRÍTICO: {adv}")


def auditar_usuarios() -> dict:
    """
    Audita /etc/passwd y /etc/shadow en busca de:
      - Usuarios con UID 0 distintos de root (escalada de privilegios).
      - Cuentas con el campo de contraseña vacío en /etc/passwd o
        /etc/shadow (permiten iniciar sesión sin contraseña).

    Returns:
        Diccionario con los hallazgos de la auditoría de usuarios.
    """
    print("=" * 64)
    print("  [4] AUDITORÍA DE USUARIOS (ACLs / PERMISOS)")
    print("=" * 64)

    resultado = _nuevo_resultado(
        usuarios_uid0_no_root=[],
        cuentas_sin_contrasena=[],
        total_usuarios=0,
        total_usuarios_sistema=0,
    )

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
                    _registrar_hallazgo(resultado, "usuario_uid0_no_root", adv)
                    print(f"  [✘] CRÍTICO: {adv}")

                # Campo de contraseña vacío en passwd ("user::...") → sin contraseña.
                # "x" o "*" delegan en /etc/shadow o bloquean la cuenta.
                if partes[1] == "":
                    _cuenta_sin_contrasena(resultado, usuario, RUTA_PASSWD)

        if not resultado["usuarios_uid0_no_root"]:
            print("  [✔] Ningún usuario con UID 0 fuera de root.")
        print(
            f"  [i] Total entradas en passwd: {resultado['total_usuarios']} "
            f"({resultado['total_usuarios_sistema']} cuentas de sistema)"
        )

    except OSError as exc:
        err = f"No se pudo leer {RUTA_PASSWD}: {exc.strerror or exc}"
        _registrar_error(resultado, err)
        print(f"  [?] {err}")

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

                # Campo vacío "" → contraseña en blanco real (riesgo crítico)
                # "!" o "*" → cuenta bloqueada/sin login → no es un riesgo directo
                if partes[1] == "":
                    _cuenta_sin_contrasena(resultado, partes[0], RUTA_SHADOW)

    except OSError as exc:
        err = f"No se pudo leer {RUTA_SHADOW}: {exc.strerror or exc}"
        _registrar_error(resultado, err)
        print(f"  [?] {err}")

    if not resultado["cuentas_sin_contrasena"] and not resultado["errores"]:
        print("  [✔] Ninguna cuenta con contraseña vacía detectada.")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [5] AUDITORÍA DE SSH
# ─────────────────────────────────────────────────────────────────────────────

def _procesar_fichero_sshd(
    ruta: str,
    estado: dict,
    contexto_match: Optional[str],
    profundidad: int,
) -> None:
    """
    Procesa un fichero de configuración de sshd con su misma semántica:

      - Admite "Clave valor" y "Clave=valor"; claves insensibles a mayúsculas.
      - Gana el PRIMER valor de cada directiva (sshd ignora los siguientes).
      - Las directivas tras un bloque ``Match`` son condicionales: se guardan
        aparte y no cuentan como valor global.
      - ``Include`` admite varios patrones y comodines, rutas relativas a
        /etc/ssh y anidamiento hasta SSHD_MAX_PROFUNDIDAD_INCLUDE niveles.
        Un ``Match`` abierto dentro de un fichero incluido no se propaga al
        fichero que lo incluye.
    """
    if profundidad > SSHD_MAX_PROFUNDIDAD_INCLUDE:
        estado["errores"].append(f"Include demasiado anidado en {ruta}; se ignora.")
        return

    try:
        with open(ruta, "r", encoding="utf-8", errors="replace") as fh:
            lineas = fh.readlines()
    except OSError as exc:
        estado["errores"].append(f"No se pudo leer {ruta}: {exc.strerror or exc}")
        return

    if ruta not in estado["archivos"]:
        estado["archivos"].append(ruta)

    directorio_ssh = os.path.dirname(RUTA_SSHD_CFG)

    for num, linea in enumerate(lineas, start=1):
        limpia = linea.strip()
        if not limpia or limpia.startswith("#"):
            continue

        coincidencia = re.match(r"([A-Za-z0-9]+)\s*(?:=\s*|\s+)(.*)$", limpia)
        if not coincidencia:
            continue
        clave = coincidencia.group(1).lower()
        valor = coincidencia.group(2).strip().strip('"')

        if clave == "match":
            contexto_match = None if valor.lower() == "all" else valor
            continue

        if clave == "include":
            for patron in valor.split():
                if not os.path.isabs(patron):
                    patron = os.path.join(directorio_ssh, patron)
                for incluido in sorted(glob.glob(patron)):
                    _procesar_fichero_sshd(incluido, estado, contexto_match, profundidad + 1)
            continue

        entrada = {"valor": valor, "archivo": ruta, "linea": num}
        if contexto_match is None:
            if clave == "port":
                estado["puertos"].append(valor)   # Port es acumulativo en sshd
            estado["valores"].setdefault(clave, entrada)
        else:
            estado["condicionales"].append({**entrada, "clave": clave, "match": contexto_match})


def _parsear_sshd_config(ruta: str) -> dict:
    """Analiza sshd_config y sus Include. Ver _procesar_fichero_sshd."""
    estado: dict = {"valores": {}, "condicionales": [], "archivos": [], "errores": [], "puertos": []}
    _procesar_fichero_sshd(ruta, estado, None, 0)
    return estado


def _config_efectiva_sshd() -> tuple[Optional[dict[str, list[str]]], str]:
    """
    Obtiene la configuración efectiva con `sshd -T` (solo lectura: sshd
    valida y vuelca la configuración sin arrancar ni modificar nada).

    Returns:
        (valores, motivo). ``valores`` es None si no se pudo obtener, y
        ``motivo`` explica por qué.
    """
    if not shutil.which("sshd"):
        return None, "sshd no está en el PATH"
    codigo, stdout, stderr = ejecutar_comando(["sshd", "-T", "-f", RUTA_SSHD_CFG])
    if codigo != 0 or not stdout:
        return None, f"sshd -T falló: {stderr or codigo}"
    valores: dict[str, list[str]] = {}
    for linea in stdout.splitlines():
        clave, _, valor = linea.strip().partition(" ")
        if clave:
            valores.setdefault(clave.lower(), []).append(valor.strip())
    return valores, ""


def cargar_config_ssh() -> dict:
    """
    Determina los valores efectivos de las directivas de riesgo de sshd.

    Fuente principal: `sshd -T`. Si no está disponible se usa el análisis
    de los ficheros con la semántica de sshd y sus valores por defecto.
    En ambos casos se intenta localizar el fichero y la línea de origen.

    Returns:
        Diccionario con: fuente, valores (clave → valor/archivo/línea),
        condicionales, archivos, puertos, errores y existe.
    """
    existe = os.path.exists(RUTA_SSHD_CFG)
    parseado = (
        _parsear_sshd_config(RUTA_SSHD_CFG)
        if existe
        else {"valores": {}, "condicionales": [], "archivos": [], "errores": [], "puertos": []}
    )
    efectiva, motivo = _config_efectiva_sshd() if existe else (None, "")

    valores: dict[str, dict] = {}
    for clave in SSHD_DIRECTIVAS_RIESGO:
        origen = parseado["valores"].get(clave)
        if efectiva is not None and clave in efectiva:
            valor = efectiva[clave][0]
            if origen and origen["valor"].lower() == valor.lower():
                valores[clave] = {**origen, "valor": valor}
            else:
                valores[clave] = {"valor": valor, "archivo": None, "linea": 0}
        elif origen:
            valores[clave] = origen
        elif efectiva is None and clave in SSHD_VALORES_DEFECTO:
            valores[clave] = {"valor": SSHD_VALORES_DEFECTO[clave], "archivo": None, "linea": 0}

    if efectiva is not None and efectiva.get("port"):
        puertos = efectiva["port"]
    else:
        puertos = parseado["puertos"] or ["22"]

    return {
        "existe":        existe,
        "fuente":        "sshd -T" if efectiva is not None else "análisis de ficheros",
        "motivo_fuente": motivo,
        "valores":       valores,
        "condicionales": parseado["condicionales"],
        "archivos":      parseado["archivos"],
        "puertos":       puertos,
        "errores":       parseado["errores"],
    }


def auditar_ssh(config: Optional[dict] = None) -> dict:
    """
    Evalúa la configuración efectiva de sshd en busca de directivas de riesgo.

    Args:
        config: Resultado de cargar_config_ssh(); si es None se calcula.

    Returns:
        Diccionario con directivas peligrosas (con fichero y línea de
        origen cuando se conocen), puertos, hallazgos y errores.
    """
    print("=" * 64)
    print("  [5] AUDITORÍA DE SSH (configuración efectiva)")
    print("=" * 64)

    config = config if config is not None else cargar_config_ssh()

    resultado = _nuevo_resultado(
        estado="OK",
        ruta_config=RUTA_SSHD_CFG,
        fuente=config["fuente"],
        archivos_analizados=config["archivos"],
        directivas_riesgo=[],          # list[dict]
        directivas_condicionales=[],   # list[dict] — dentro de bloques Match
        directivas_seguras=[],
        puertos_ssh=config["puertos"],
        puerto_ssh=", ".join(config["puertos"]),
    )

    if not config["existe"]:
        resultado["estado"] = "NO_INSTALADO"
        print(f"  [i] No se encontró {RUTA_SSHD_CFG}: el servidor SSH no parece instalado.")
        print()
        return resultado

    print(f"  [i] Fuente: {config['fuente']}")
    if config["motivo_fuente"]:
        print(f"      ({config['motivo_fuente']}; se analizan los ficheros directamente)")
    for arc in config["archivos"]:
        print(f"      • {arc}")

    if config["fuente"] != "sshd -T":
        for err in config["errores"]:
            _registrar_error(resultado, err)
            print(f"  [?] {err}")

    for clave, (nombre, peligroso, codigo) in SSHD_DIRECTIVAS_RIESGO.items():
        entrada = config["valores"].get(clave)
        if entrada is None:
            continue
        valor = entrada["valor"]
        if valor.lower() != peligroso:
            resultado["directivas_seguras"].append(f"{nombre} {valor}")
            continue

        if entrada["archivo"]:
            origen = f"{entrada['archivo']}:{entrada['linea']}"
        elif config["fuente"] == "sshd -T":
            origen = "configuración efectiva (sshd -T, valor por defecto)"
        else:
            origen = "valor por defecto de OpenSSH"

        hallazgo = {
            "directiva":   nombre,
            "valor":       valor,
            "linea_num":   entrada["linea"],
            "archivo":     entrada["archivo"],
            "origen":      origen,
            "descripcion": SSHD_DESCRIPCIONES[clave],
        }
        resultado["directivas_riesgo"].append(hallazgo)
        _registrar_hallazgo(
            resultado, codigo, f"{origen}: '{nombre} {valor}' — {SSHD_DESCRIPCIONES[clave]}"
        )
        print(f"  [✘] RIESGO — {origen}: {nombre} {valor}")
        print(f"      {SSHD_DESCRIPCIONES[clave]}")

    for cond in config["condicionales"]:
        riesgo = SSHD_DIRECTIVAS_RIESGO.get(cond["clave"])
        if riesgo and cond["valor"].lower() == riesgo[1]:
            nombre = riesgo[0]
            origen = f"{cond['archivo']}:{cond['linea']}"
            resultado["directivas_condicionales"].append(
                {"directiva": nombre, "valor": cond["valor"], "match": cond["match"], "origen": origen}
            )
            _registrar_hallazgo(
                resultado, "ssh_riesgo_condicional",
                f"{origen}: '{nombre} {cond['valor']}' dentro de 'Match {cond['match']}'.",
            )
            print(f"  [⚠] Condicional — {origen}: Match {cond['match']} → {nombre} {cond['valor']}")

    if not resultado["hallazgos"]:
        print("  [✔] No se detectaron directivas SSH de riesgo.")

    print(f"  [i] Puerto(s) SSH             : {resultado['puerto_ssh']}")
    print(f"  [i] Directivas de riesgo       : {len(resultado['directivas_riesgo'])}")
    print(f"  [i] Directivas seguras halladas: {len(resultado['directivas_seguras'])}")

    if resultado["directivas_riesgo"]:
        print()
        print("  Recomendaciones (DRY-RUN) para /etc/ssh/sshd_config:")
        riesgos = {h["directiva"].lower() for h in resultado["directivas_riesgo"]}
        if "permitrootlogin" in riesgos:
            print("    PermitRootLogin no           # Deshabilitar login directo como root")
        if "passwordauthentication" in riesgos:
            print("    PasswordAuthentication no    # Usar solo autenticación por clave pública")
        if "permitemptypasswords" in riesgos:
            print("    PermitEmptyPasswords no      # NUNCA permitir contraseñas vacías")
        if "x11forwarding" in riesgos:
            print("    X11Forwarding no             # Desactivar reenvío X11")
        print("    Tras editar: systemctl restart sshd")

    print()
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# [6] AUDITORÍA DE ACTUALIZACIONES DE SEGURIDAD (RHEL/Rocky)
# ─────────────────────────────────────────────────────────────────────────────

_PATRON_AVISO = re.compile(r"[A-Z][A-Z0-9-]*-\d{4}[:-][0-9A-Za-z]+")
_PATRON_FECHA = re.compile(r"\d{4}-\d{2}-\d{2}")
_SEVERIDADES_DNF = ("Critical", "Important", "Moderate", "Low")


def _parsear_updateinfo(stdout: str) -> list[dict]:
    """
    Interpreta la salida de `dnf updateinfo list --security` (dnf4 y dnf5).

      dnf4: RHSA-2024:3306 Moderate/Sec.  kernel-5.14.0-427.el9.x86_64
      dnf5: RHSA-2024:3306 security Moderate kernel-5.14.0-427.el9.x86_64 2024-05-28 23:18:13

    Returns:
        Lista de avisos: {"aviso", "severidad", "paquete"}.
    """
    avisos: list[dict] = []
    for linea in stdout.splitlines():
        tokens = linea.split()
        if len(tokens) < 2 or not _PATRON_AVISO.fullmatch(tokens[0]):
            continue
        severidad = "Desconocida"
        for tok in tokens[1:]:
            base = tok.split("/")[0].capitalize()
            if base in _SEVERIDADES_DNF:
                severidad = base
                break
        candidatos = [
            t for t in tokens[1:]
            if "/" not in t and "." in t and re.search(r"-\d", t) and not _PATRON_FECHA.fullmatch(t)
        ]
        paquete = candidatos[-1] if candidatos else tokens[-1]
        avisos.append({"aviso": tokens[0], "severidad": severidad, "paquete": paquete})
    return avisos


def auditar_actualizaciones(offline: bool = False) -> dict:
    """
    Comprueba si existen actualizaciones de seguridad pendientes en sistemas
    basados en RPM/DNF (RHEL, Rocky Linux, AlmaLinux, CentOS Stream, Fedora)
    con `dnf -q updateinfo list --security`, que lista los avisos de
    seguridad aplicables a los paquetes instalados.

    Args:
        offline: Si es True se añade ``-C`` (solo caché): dnf no contacta con
            los repositorios ni actualiza sus metadatos en /var/cache/dnf.

    Returns:
        Diccionario con el estado de actualización, paquetes pendientes,
        avisos por severidad, hallazgos y errores.
    """
    print("=" * 64)
    print("  [6] AUDITORÍA DE ACTUALIZACIONES DE SEGURIDAD")
    print("=" * 64)

    resultado = _nuevo_resultado(
        gestor="dnf",
        estado="DESCONOCIDO",
        paquetes_pendientes=[],   # list[str] — "paquete [aviso, severidad]"
        total_pendientes=0,
        avisos=[],                # list[dict]
        severidades={},           # severidad → nº de avisos
    )

    # Verificar que dnf está disponible antes de molestar a los repositorios
    if not shutil.which("dnf"):
        err = "dnf no está disponible. Este módulo es específico de RHEL/Rocky/Fedora."
        _registrar_error(resultado, err)
        resultado["estado"] = "NO_DISPONIBLE"
        print(f"  [?] {err}")
        print()
        return resultado

    comando = ["dnf", "-q"] + (["-C"] if offline else []) + ["updateinfo", "list", "--security"]
    if offline:
        print("  [i] Modo offline: se usa solo la caché local de dnf (-C).")

    # dnf puede tardar la vida consultando metadatos remotos — el spinner evita
    # que el operario piense que el proceso se ha colgado y lo mate con Ctrl+C
    with Spinner("Consultando avisos de seguridad con dnf updateinfo..."):
        codigo, stdout, stderr = ejecutar_comando(comando, timeout=120)

    if codigo == -2:
        err = (
            "Timeout esperando respuesta de dnf. "
            "Revisa la conectividad con los repositorios — puede que algún mirror esté caído."
        )
        _registrar_error(resultado, err)
        resultado["estado"] = "ERROR_TIMEOUT"
        print(f"  [?] {err}")
        print()
        return resultado

    if codigo != 0:
        err = f"dnf updateinfo terminó con error (código {codigo}): {stderr or stdout}"
        _registrar_error(resultado, err)
        resultado["estado"] = "ERROR"
        print(f"  [?] {err}")
        print()
        return resultado

    avisos = _parsear_updateinfo(stdout)
    resultado["avisos"] = avisos

    if not avisos:
        resultado["estado"] = "ACTUALIZADO"
        print("  [✔] No hay actualizaciones de seguridad pendientes. Sistema al día.")
        print()
        return resultado

    resultado["estado"] = "ACTUALIZACIONES_PENDIENTES"
    por_paquete: dict[str, list[dict]] = {}
    for aviso in avisos:
        por_paquete.setdefault(aviso["paquete"], []).append(aviso)
        resultado["severidades"][aviso["severidad"]] = (
            resultado["severidades"].get(aviso["severidad"], 0) + 1
        )
    resultado["paquetes_pendientes"] = [
        f"{pkg}  [" + ", ".join(f"{a['aviso']} {a['severidad']}" for a in lista) + "]"
        for pkg, lista in por_paquete.items()
    ]
    resultado["total_pendientes"] = len(por_paquete)

    resumen_sev = ", ".join(
        f"{n} {sev}" for sev, n in sorted(
            resultado["severidades"].items(),
            key=lambda kv: (_SEVERIDADES_DNF + ("Desconocida",)).index(kv[0]),
        )
    )
    adv = (
        f"{len(por_paquete)} paquete(s) con actualizaciones de seguridad pendientes "
        f"({len(avisos)} aviso(s): {resumen_sev})."
    )
    _registrar_hallazgo(resultado, "actualizaciones_seguridad", adv)
    print(f"  [✘] {adv}")

    # Mostrar solo los primeros 10 — más que eso es basura visual en consola
    limite = min(10, len(resultado["paquetes_pendientes"]))
    print(f"\n  Primeros {limite} paquetes pendientes:")
    for pkg in resultado["paquetes_pendientes"][:limite]:
        print(f"    • {pkg}")
    if len(resultado["paquetes_pendientes"]) > 10:
        print(f"    ... y {len(resultado['paquetes_pendientes']) - 10} más (ver reporte completo).")

    print()
    print("  Recomendación (DRY-RUN): aplicar actualizaciones con:")
    print("    sudo dnf update --security -y")

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
    Nivel de riesgo global: la severidad máxima de todos los hallazgos, según
    la tabla SEVERIDADES. Sin hallazgos → "BAJO".

    Los errores (comprobaciones no realizadas) no suben el nivel; se
    informan aparte con _comprobaciones_no_realizadas().

    Returns:
        "BAJO", "MEDIO", "ALTO" o "CRÍTICO".
    """
    indice = 0
    for modulo in MODULOS:
        for hallazgo in resultados.get(modulo, {}).get("hallazgos", []):
            indice = max(indice, NIVELES_RIESGO.index(hallazgo["severidad"]))
    return NIVELES_RIESGO[indice]


def _comprobaciones_no_realizadas(resultados: dict) -> list[str]:
    """Errores de todos los módulos: si hay alguno, la auditoría está INCOMPLETA."""
    return [
        f"[{modulo}] {err}"
        for modulo in MODULOS
        for err in resultados.get(modulo, {}).get("errores", [])
    ]


def _total_advertencias(resultados: dict) -> int:
    return sum(len(resultados.get(m, {}).get("advertencias", [])) for m in MODULOS)


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

    sl = resultados.get("selinux", {})
    s  = resultados.get("ssh", {})
    ac = resultados.get("actualizaciones", {})
    no_realizadas = _comprobaciones_no_realizadas(resultados)
    estado_auditoria = (
        f"INCOMPLETA ({len(no_realizadas)} comprobación(es) no realizada(s))"
        if no_realizadas else "COMPLETA"
    )

    def _sep(titulo: str = "") -> str:
        return f"{'─' * 64}\n{titulo}" if titulo else "─" * 64

    def _avisos(modulo: dict) -> list[str]:
        return (
            [f"  [⚠] {adv}" for adv in modulo.get("advertencias", [])]
            + [f"  [?] No comprobado: {err}" for err in modulo.get("errores", [])]
        )

    lineas: list[str] = [
        "=" * 64,
        "  REPORTE DE AUDITORÍA DE SEGURIDAD DEL SERVIDOR",
        "  jaimefg1888 — GhostCheck",
        "=" * 64,
        f"  Fecha y hora    : {ts}",
        f"  Hostname        : {hostname}",
        f"  Modo            : DRY-RUN (solo auditoría, sin cambios)",
        f"  Nivel de riesgo : {nivel_riesgo}",
        f"  Auditoría       : {estado_auditoria}",
        "=" * 64,
        "",
        _sep("[1] PRIVILEGIOS DE EJECUCIÓN"),
        _sep(),
        "  Script ejecutado correctamente como root (UID 0).",
        "",
        _sep("[2] AUDITORÍA DE SELINUX"),
        _sep(),
        f"  Estado            : {sl.get('estado') or 'N/A'}",
        f"  Modo              : {sl.get('modo') or 'N/A'}",
        f"  Modo persistente  : {sl.get('modo_persistente') or 'N/A'}",
        f"  Política          : {sl.get('politica') or 'N/A'}",
    ]
    lineas += _avisos(sl)

    fw = resultados.get("firewall", {})
    lineas += [
        "",
        _sep("[3] GESTIÓN DE FIREWALL"),
        _sep(),
        f"  Herramienta     : {fw.get('herramienta', 'N/A')}",
        f"  Activo          : {'Sí' if fw.get('activo') else 'No'}",
        f"  Zonas auditadas : {', '.join(fw.get('zonas', [])) or 'N/A'}",
        f"  Puertos abiertos: {', '.join(fw.get('puertos_abiertos', [])) or 'ninguno'}",
        f"  A revisar       : {', '.join(fw.get('puertos_a_revisar', [])) or 'ninguno'}",
    ]
    lineas += _avisos(fw)

    u = resultados.get("usuarios", {})
    lineas += [
        "",
        _sep("[4] AUDITORÍA DE USUARIOS"),
        _sep(),
        f"  Total entradas /etc/passwd : {u.get('total_usuarios', 0)}",
        f"  Usuarios con UID 0 (≠root) : {', '.join(u.get('usuarios_uid0_no_root', [])) or 'ninguno'}",
        f"  Cuentas sin contraseña     : {', '.join(u.get('cuentas_sin_contrasena', [])) or 'ninguna'}",
    ]
    lineas += _avisos(u)

    # ── Sección SSH ───────────────────────────────────────────────────────────
    lineas += [
        "",
        _sep("[5] AUDITORÍA DE SSH"),
        _sep(),
        f"  Configuración       : {s.get('ruta_config', RUTA_SSHD_CFG)}",
        f"  Fuente              : {s.get('fuente', 'N/A')}",
        f"  Puerto(s) SSH       : {s.get('puerto_ssh', '22')}",
        f"  Directivas de riesgo: {len(s.get('directivas_riesgo', []))}",
    ]
    if s.get("directivas_riesgo"):
        lineas.append("  Detalle de hallazgos:")
        for h in s["directivas_riesgo"]:
            lineas.append(f"    [✘] {h['origen']}: {h['directiva']} {h['valor']}")
            lineas.append(f"         → {h['descripcion']}")
    else:
        lineas.append("  [✔] No se detectaron directivas SSH de riesgo en la configuración global.")
    lineas += _avisos(s)

    # ── Sección Actualizaciones ───────────────────────────────────────────────
    lineas += [
        "",
        _sep("[6] ACTUALIZACIONES DE SEGURIDAD"),
        _sep(),
        f"  Gestor de paquetes  : {ac.get('gestor', 'N/A')}",
        f"  Estado              : {ac.get('estado', 'N/A')}",
        f"  Paquetes pendientes : {ac.get('total_pendientes', 0)}",
    ]
    if ac.get("severidades"):
        lineas.append(
            "  Avisos por severidad: "
            + ", ".join(f"{sev}: {n}" for sev, n in ac["severidades"].items())
        )
    if ac.get("paquetes_pendientes"):
        lineas.append("  Listado (primeros 20):")
        for pkg in ac["paquetes_pendientes"][:20]:
            lineas.append(f"    • {pkg}")
        restantes = ac.get("total_pendientes", 0) - 20
        if restantes > 0:
            lineas.append(f"    ... y {restantes} paquete(s) más.")
    lineas += _avisos(ac)

    total_adv = _total_advertencias(resultados)
    lineas += [
        "",
        "=" * 64,
        "RESUMEN EJECUTIVO",
        "=" * 64,
        f"  Nivel de riesgo global : {nivel_riesgo}",
        f"  Estado de la auditoría : {estado_auditoria}",
        f"  Total de advertencias  : {total_adv}",
    ]
    if no_realizadas:
        lineas.append("  Comprobaciones no realizadas (no suben el nivel de riesgo):")
        lineas += [f"    [?] {err}" for err in no_realizadas]
    lineas += [
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

    def lista_adv(modulo: dict) -> str:
        advs = modulo.get("advertencias", [])
        errs = modulo.get("errores", [])
        if not advs and not errs:
            return '<p style="color:#28a745;margin:4px 0">✔ Sin advertencias.</p>'
        items = "".join(
            f'<li style="color:#c0392b;margin-bottom:3px">⚠ {esc(a)}</li>' for a in advs
        ) + "".join(
            f'<li style="color:#6c757d;margin-bottom:3px">? No comprobado: {esc(e)}</li>'
            for e in errs
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

    total_adv = _total_advertencias(resultados)
    no_realizadas = _comprobaciones_no_realizadas(resultados)
    estado_auditoria = (
        f"INCOMPLETA ({len(no_realizadas)} comprobación(es) no realizada(s))"
        if no_realizadas else "COMPLETA"
    )

    # ── HTML tabla de directivas SSH peligrosas ───────────────────────────────
    if s.get("directivas_riesgo"):
        rows_ssh = "".join(
            f'<tr style="background:#fff5f5">'
            f'<td style="padding:5px 10px;color:#c0392b;font-weight:700">{esc(h["origen"])}</td>'
            f'<td style="padding:5px 10px;font-family:monospace">{esc(h["directiva"])} {esc(h["valor"])}</td>'
            f'<td style="padding:5px 10px;color:#7f0000">{esc(h["descripcion"])}</td>'
            f'</tr>'
            for h in s["directivas_riesgo"]
        )
        ssh_directivas_html = f"""
        <table style="width:100%;border-collapse:collapse;margin-top:8px;font-size:.88em">
          <thead>
            <tr style="background:#f8d7da">
              <th style="padding:6px 10px;text-align:left">Origen</th>
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
    <span><b>Auditoría:</b> {esc(estado_auditoria)}</span>
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
      {fila("Modo persistente:", esc(sl.get('modo_persistente')))}
      {fila("Política cargada:", esc(sl.get('politica')))}
      {fila("Advertencias:", lista_adv(sl))}
    </table>
  </div>

  <!-- [3] Firewall -->
  <div class="sec">
    <h2>[3] Gestión de Firewall</h2>
    <table class="props">
      {fila("Herramienta:", esc(fw.get('herramienta')))}
      {fila("Zonas auditadas:", esc(', '.join(fw.get('zonas', [])) or 'N/A'))}
      {fila("Estado:", badge(fw.get('activo', False), 'Activo', 'Inactivo'))}
      {fila("Puertos abiertos:", esc(', '.join(fw.get('puertos_abiertos', [])) or '—'))}
      {fila("Puertos a revisar:",
        f'<span style="color:#e74c3c;font-weight:700">'
        f'{esc(", ".join(fw.get("puertos_a_revisar", [])) or "—")}</span>')}
      {fila("Advertencias:", lista_adv(fw))}
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
      {fila("Advertencias:", lista_adv(u))}
    </table>
  </div>

  <!-- [5] SSH -->
  <div class="sec">
    <h2>[5] Auditoría de SSH
      <span style="font-size:.75em;color:#888;font-weight:400">(sshd_config)</span>
    </h2>
    <table class="props">
      {fila("Archivo analizado:", f'<code style="background:#eee;padding:1px 5px;border-radius:3px">{esc(s.get("ruta_config", RUTA_SSHD_CFG))}</code>')}
      {fila("Fuente:", esc(s.get('fuente')))}
      {fila("Puerto(s) SSH:", esc(s.get('puerto_ssh','22')))}
      {fila("Estado:", badge(
        s.get('ok', False),
        'Sin riesgos detectados',
        f'{len(s.get("directivas_riesgo", []))} directiva(s) de riesgo'
      ))}
      {fila("Directivas peligrosas:", ssh_directivas_html)}
      {fila("Advertencias:", lista_adv(s))}
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
      {fila("Advertencias:", lista_adv(ac))}
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
    parser.add_argument(
        "--offline",
        action="store_true",
        help="dnf usa solo su caché local (-C): no contacta con los repositorios "
             "ni actualiza los metadatos en /var/cache/dnf.",
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

    # La configuración SSH se carga una vez: el firewall necesita sus puertos
    config_ssh = cargar_config_ssh()

    # ── [3] Gestión de Firewall ───────────────────────────────────────────────
    resultados["firewall"] = auditar_firewall(config_ssh["puertos"])

    # ── [4] Auditoría de Usuarios ─────────────────────────────────────────────
    resultados["usuarios"] = auditar_usuarios()

    # ── [5] Auditoría de SSH ──────────────────────────────────────────────────
    resultados["ssh"] = auditar_ssh(config_ssh)

    # ── [6] Auditoría de Actualizaciones de Seguridad ─────────────────────────
    resultados["actualizaciones"] = auditar_actualizaciones(offline=args.offline)

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
    no_realizadas = _comprobaciones_no_realizadas(resultados)
    if no_realizadas:
        print(f"  [?] Auditoría INCOMPLETA: {len(no_realizadas)} comprobación(es) no realizada(s)")
    print(f"  TXT  → {ruta_txt}")
    print(f"  HTML → {ruta_html}")
    print(f"{'=' * 64}\n")


if __name__ == "__main__":
    main()
