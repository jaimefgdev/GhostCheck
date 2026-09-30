#!/usr/bin/env python3
"""
==============================================================================
  GhostCheck — Auditoría de Seguridad para Servidores Linux / RHEL
  Modo: DRY-RUN (solo auditoría, sin cambios en el sistema)
  Autor   : jaimefg1888
  Tool    : GhostCheck

  Módulos de auditoría:
    [1] Control de privilegios root
    [2] SELinux — modo en ejecución, modo persistente y política
    [3] Firewall — firewalld (todas las zonas activas) / ufw
    [4] Usuarios — UID 0 duplicados, contraseñas vacías
    [5] SSH — configuración efectiva de sshd (sshd -T / sshd_config)
    [6] Actualizaciones de seguridad — dnf updateinfo
    [7] Generación de reportes TXT / HTML / JSON

  Organización del código:
    · Modelo          — dataclasses Hallazgo, ResultadoModulo, Informe.
    · Comandos        — ejecución restringida a una lista blanca de lectura.
    · Comprobaciones  — funciones puras: devuelven un ResultadoModulo y no
                        imprimen nada.
    · Riesgo          — tabla de severidades y nivel global.
    · Reportes        — TXT, HTML y JSON a partir de un Informe.
    · Consola / CLI   — presentación en terminal, argumentos y códigos de salida.
==============================================================================
"""

from __future__ import annotations

import argparse
import glob
import html
import itertools
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn, Optional, TextIO

__version__ = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES GLOBALES
# ─────────────────────────────────────────────────────────────────────────────

# Puertos considerados esenciales (SSH, HTTP, HTTPS). Solo cuentan en TCP.
# Los puertos en los que escucha sshd se añaden a esta lista en tiempo de ejecución.
PUERTOS_ESENCIALES: frozenset[str] = frozenset({"22", "80", "443"})


@dataclass(frozen=True)
class Rutas:
    """Ficheros del sistema que se auditan. Se pasan como parámetro a las
    comprobaciones para poder auditar (y probar) otros árboles de ficheros."""

    passwd: str = "/etc/passwd"
    shadow: str = "/etc/shadow"
    sshd_config: str = "/etc/ssh/sshd_config"
    selinux_config: str = "/etc/selinux/config"


# Rutas usadas cuando una comprobación no recibe otras explícitamente
RUTAS = Rutas()

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

# Código de salida del proceso según el nivel de riesgo (útil en cron / CI)
CODIGOS_SALIDA: dict[str, int] = {"BAJO": 0, "MEDIO": 1, "ALTO": 2, "CRÍTICO": 3}
SALIDA_ERROR: int = 4           # error de uso o de ejecución
SALIDA_INTERRUMPIDO: int = 130  # Ctrl+C

# Módulos de auditoría: nombre → (número, título)
MODULOS: dict[str, tuple[int, str]] = {
    "selinux":         (2, "AUDITORÍA DE SELINUX"),
    "firewall":        (3, "GESTIÓN DE FIREWALL"),
    "usuarios":        (4, "AUDITORÍA DE USUARIOS"),
    "ssh":             (5, "AUDITORÍA DE SSH"),
    "actualizaciones": (6, "ACTUALIZACIONES DE SEGURIDAD"),
}

FORMATOS_REPORTE: tuple[str, ...] = ("txt", "html", "json")

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


# ─────────────────────────────────────────────────────────────────────────────
# MODELO — Resultados de las comprobaciones
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Hallazgo:
    """Un problema de seguridad detectado. Su severidad sale de SEVERIDADES."""

    codigo: str
    severidad: str
    mensaje: str


@dataclass
class ResultadoModulo:
    """
    Resultado de un módulo de auditoría.

    Attributes:
        nombre:          Clave del módulo en MODULOS.
        hallazgos:       Problemas de seguridad detectados.
        errores:         Comprobaciones que NO se pudieron realizar.
        datos:           Datos propios del módulo (puertos, modo, paquetes...).
        info:            Líneas informativas para mostrar al operador.
        recomendaciones: Órdenes o cambios sugeridos (nunca se ejecutan).
        mensaje_ok:      Texto a mostrar si no hay hallazgos ni errores.
    """

    nombre: str
    hallazgos: list[Hallazgo] = field(default_factory=list)
    errores: list[str] = field(default_factory=list)
    datos: dict[str, Any] = field(default_factory=dict)
    info: list[str] = field(default_factory=list)
    recomendaciones: list[str] = field(default_factory=list)
    mensaje_ok: str = "Sin problemas detectados."

    @property
    def numero(self) -> int:
        return MODULOS[self.nombre][0]

    @property
    def titulo(self) -> str:
        return MODULOS[self.nombre][1]

    @property
    def ok(self) -> bool:
        """Sin hallazgos y con todas las comprobaciones realizadas."""
        return not self.hallazgos and not self.errores

    @property
    def advertencias(self) -> list[str]:
        return [h.mensaje for h in self.hallazgos]

    def codigos(self) -> list[str]:
        return [h.codigo for h in self.hallazgos]

    def hallazgo(self, codigo: str, mensaje: str) -> None:
        """Registra un hallazgo con la severidad de la tabla SEVERIDADES."""
        self.hallazgos.append(Hallazgo(codigo, SEVERIDADES[codigo], mensaje))

    def error(self, mensaje: str) -> None:
        """Registra una comprobación no realizada (marca la auditoría INCOMPLETA)."""
        self.errores.append(mensaje)


@dataclass
class Informe:
    """Todo lo necesario para generar los reportes, calculado una sola vez."""

    fecha: datetime
    hostname: str
    como_root: bool
    resultados: dict[str, ResultadoModulo]
    omitidos: list[str] = field(default_factory=list)

    @property
    def nivel_riesgo(self) -> str:
        return calcular_nivel_riesgo(self.resultados)

    @property
    def no_realizadas(self) -> list[str]:
        notas = [] if self.como_root else [
            "[general] Ejecución sin privilegios de root: algunas comprobaciones son parciales."
        ]
        return notas + comprobaciones_no_realizadas(self.resultados)

    @property
    def completa(self) -> bool:
        return not self.no_realizadas

    @property
    def estado_auditoria(self) -> str:
        n = len(self.no_realizadas)
        return "COMPLETA" if n == 0 else f"INCOMPLETA ({n} comprobación(es) no realizada(s))"

    @property
    def total_advertencias(self) -> int:
        return sum(len(r.hallazgos) for r in self.resultados.values())


# ─────────────────────────────────────────────────────────────────────────────
# COMANDOS — Ejecución restringida a la lista blanca
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
        return -3, "", f"Error inesperado: {exc}"


def _leer_lineas(ruta: str) -> list[str]:
    """Lee un fichero de texto tolerando bytes no UTF-8. Lanza OSError."""
    with open(ruta, "r", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


# ─────────────────────────────────────────────────────────────────────────────
# [2] SELINUX
# ─────────────────────────────────────────────────────────────────────────────

def _leer_modo_selinux_persistente(ruta: str) -> Optional[str]:
    """
    Devuelve el modo configurado en /etc/selinux/config (el que se aplicará
    tras reiniciar), en minúsculas, o None si no se puede determinar.
    """
    try:
        lineas = _leer_lineas(ruta)
    except OSError:
        return None
    for linea in lineas:
        coincidencia = re.match(r"\s*SELINUX\s*=\s*(\w+)", linea)
        if coincidencia:
            return coincidencia.group(1).lower()
    return None


def auditar_selinux(rutas: Optional[Rutas] = None) -> ResultadoModulo:
    """
    Comprueba el estado de SELinux: modo en ejecución (`getenforce`),
    política cargada (`sestatus`) y modo persistente (/etc/selinux/config).
    """
    rutas = rutas or RUTAS
    r = ResultadoModulo(
        "selinux",
        datos={"estado": "DESCONOCIDO", "modo": None, "modo_persistente": None, "politica": None},
        mensaje_ok="SELinux está en modo Enforcing.",
    )

    codigo, stdout, stderr = ejecutar_comando(["getenforce"])
    if codigo == -1:
        r.datos["estado"] = "NO_DISPONIBLE"
        r.hallazgo("selinux_no_disponible", "SELinux no está instalado o no está disponible en este sistema.")
        return r
    if codigo != 0:
        r.datos["estado"] = "ERROR"
        r.error(f"Error al ejecutar getenforce: {stderr or stdout}")
        return r

    modo = stdout.strip()
    r.datos["modo"] = modo

    codigo_s, stdout_s, _ = ejecutar_comando(["sestatus"])
    if codigo_s == 0:
        for linea in stdout_s.splitlines():
            if "Loaded policy name" in linea:
                r.datos["politica"] = linea.split(":", 1)[1].strip()
    r.info.append(f"Política cargada: {r.datos['politica'] or 'N/A'}")

    persistente = _leer_modo_selinux_persistente(rutas.selinux_config)
    r.datos["modo_persistente"] = persistente

    if modo == "Enforcing":
        r.datos["estado"] = "OK"
        if persistente and persistente != "enforcing":
            r.hallazgo(
                "selinux_no_persistente",
                f"SELinux está en Enforcing pero {rutas.selinux_config} indica "
                f"SELINUX={persistente}: el cambio NO sobrevivirá a un reinicio.",
            )
            r.recomendaciones.append(f"Establecer SELINUX=enforcing en {rutas.selinux_config}")
    elif modo == "Permissive":
        r.datos["estado"] = "ADVERTENCIA"
        r.hallazgo("selinux_permissive",
                   "SELinux en modo PERMISSIVE: las políticas se registran pero NO se aplican.")
        r.recomendaciones.append(f"Cambiar a Enforcing: SELINUX=enforcing en {rutas.selinux_config} "
                                 "(revisar antes las denegaciones con `ausearch -m avc`)")
    elif modo == "Disabled":
        r.datos["estado"] = "DESHABILITADO"
        r.hallazgo("selinux_deshabilitado",
                   "SELinux DESHABILITADO: el sistema carece de control de acceso obligatorio (MAC).")
        r.recomendaciones.append("Habilitar SELinux (primero en Permissive para reetiquetar) y reiniciar.")
    else:
        r.datos["estado"] = "DESCONOCIDO"
        r.error(f"Estado de SELinux desconocido: '{modo}'")
    return r


# ─────────────────────────────────────────────────────────────────────────────
# [3] FIREWALL
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
    return [n.strip().replace(":", "-") + sufijo for n in numeros.split(",") if n.strip()]


def _es_puerto_esencial(puerto: str, esenciales: frozenset[str]) -> bool:
    """Un puerto es esencial si su número está en la lista y es TCP (o sin protocolo)."""
    numero, _, protocolo = puerto.partition("/")
    return numero in esenciales and protocolo in ("", "tcp")


def _zonas_firewalld(r: ResultadoModulo) -> list[str]:
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
        r.error("No se pudieron obtener las zonas de firewalld; se audita solo la zona 'public'.")
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


def _auditar_firewalld(r: ResultadoModulo, esenciales: frozenset[str]) -> None:
    """Audita firewalld en todas las zonas activas (RHEL / CentOS / Fedora / Rocky)."""
    r.datos.update(herramienta="firewalld", zonas=[], detalle_puertos=[])

    codigo, stdout, _ = ejecutar_comando(["systemctl", "is-active", "firewalld"])
    if codigo != 0 or stdout != "active":
        r.hallazgo("firewall_inactivo", "firewalld no está activo. El sistema puede estar expuesto.")
        r.recomendaciones.append("systemctl enable --now firewalld")
        return
    r.datos["activo"] = True

    zonas = _zonas_firewalld(r)
    r.datos["zonas"] = zonas
    r.info.append(f"Zonas auditadas: {', '.join(zonas)}")

    detalle: list[dict] = r.datos["detalle_puertos"]
    for zona in zonas:
        listas: dict[str, list[str]] = {}
        for tipo in ("ports", "services", "rich-rules", "forward-ports"):
            codigo_l, stdout_l, stderr_l = ejecutar_comando(
                ["firewall-cmd", f"--list-{tipo}", f"--zone={zona}"]
            )
            if codigo_l != 0:
                r.error(f"Zona {zona}: no se pudo obtener --list-{tipo}: {stderr_l or codigo_l}")
                listas[tipo] = []
            elif tipo == "rich-rules":
                listas[tipo] = [regla for regla in stdout_l.splitlines() if regla.strip()]
            else:
                listas[tipo] = stdout_l.split()

        for especificacion in listas["ports"]:
            for puerto in _normalizar_puertos(especificacion):
                detalle.append({"zona": zona, "puerto": puerto, "origen": "puerto"})

        for servicio in listas["services"]:
            puertos_srv = _puertos_servicio_firewalld(servicio)
            if puertos_srv is None:
                r.hallazgo("firewall_reglas_a_revisar",
                           f"Zona {zona}: no se pudieron resolver los puertos del servicio '{servicio}'.")
                continue
            for puerto in puertos_srv:
                detalle.append({"zona": zona, "puerto": puerto, "origen": f"servicio:{servicio}"})

        if listas["rich-rules"]:
            r.hallazgo("firewall_reglas_a_revisar",
                       f"Zona {zona}: {len(listas['rich-rules'])} regla(s) rich que deben revisarse manualmente.")
        if listas["forward-ports"]:
            r.hallazgo("firewall_reglas_a_revisar",
                       f"Zona {zona}: {len(listas['forward-ports'])} redirección(es) de puertos activas.")

    r.datos["puertos_abiertos"] = sorted({d["puerto"] for d in detalle})
    a_revisar = [d for d in detalle if not _es_puerto_esencial(d["puerto"], esenciales)]
    r.datos["puertos_a_revisar"] = sorted({d["puerto"] for d in a_revisar})
    r.info.append(f"Puertos abiertos: {', '.join(r.datos['puertos_abiertos']) or 'ninguno'}")

    if a_revisar:
        r.hallazgo("puertos_no_esenciales",
                   f"Puertos no esenciales detectados: {', '.join(r.datos['puertos_a_revisar'])}")
        for d in a_revisar:
            if d["origen"].startswith("servicio:"):
                orden = (f"firewall-cmd --permanent --zone={d['zona']} "
                         f"--remove-service={d['origen'].split(':', 1)[1]}")
            else:
                orden = f"firewall-cmd --permanent --zone={d['zona']} --remove-port={d['puerto']}"
            if orden not in r.recomendaciones:
                r.recomendaciones.append(orden)
        r.recomendaciones.append("firewall-cmd --reload")


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


def _auditar_ufw(r: ResultadoModulo, esenciales: frozenset[str]) -> None:
    """
    Audita UFW (Debian / Ubuntu) interpretando la tabla de `ufw status
    verbose` por columnas (To / Action / From). Solo cuentan las reglas de
    entrada (ALLOW/LIMIT IN):
      - "22/tcp", "80,443/tcp", "6000:6007/tcp" → puertos normalizados.
      - "Anywhere" → la regla permite TODO el tráfico desde el origen.
      - Nombre de perfil ("Nginx Full") → se resuelve con `ufw app info`.
    """
    r.datos["herramienta"] = "ufw"

    codigo, stdout, stderr = ejecutar_comando(["ufw", "status", "verbose"])
    if codigo != 0:
        r.error(f"No se pudo obtener el estado de UFW: {stderr or codigo}")
        return
    if re.search(r"(?im)^status:\s*inactive", stdout):
        r.hallazgo("firewall_inactivo", "UFW está INACTIVO. El sistema puede estar expuesto.")
        r.recomendaciones.append("ufw enable")
        return
    r.datos["activo"] = True

    puertos: set[str] = set()
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
            r.hallazgo("firewall_reglas_a_revisar",
                       f"Regla UFW que permite TODO el tráfico entrante desde {origen}.")
        elif re.fullmatch(r"[\d,:]+(/(tcp|udp))?", destino, re.IGNORECASE):
            puertos.update(_normalizar_puertos(destino))
        else:
            puertos_perfil = _puertos_perfil_ufw(destino)
            if puertos_perfil is None:
                r.hallazgo("firewall_reglas_a_revisar",
                           f"No se pudieron resolver los puertos del perfil UFW '{destino}'.")
            else:
                r.info.append(f"Perfil {destino} → {', '.join(puertos_perfil)}")
                puertos.update(puertos_perfil)

    r.datos["puertos_abiertos"] = sorted(puertos)
    r.datos["puertos_a_revisar"] = [
        p for p in r.datos["puertos_abiertos"] if not _es_puerto_esencial(p, esenciales)
    ]
    r.info.append(f"Puertos permitidos: {', '.join(r.datos['puertos_abiertos']) or 'ninguno'}")

    if r.datos["puertos_a_revisar"]:
        r.hallazgo("puertos_no_esenciales",
                   f"Puertos no esenciales detectados: {', '.join(r.datos['puertos_a_revisar'])}")
        for p in r.datos["puertos_a_revisar"]:
            r.recomendaciones.append(f"ufw delete allow {p.replace('-', ':')}")


def auditar_firewall(puertos_ssh: Optional[list[str]] = None) -> ResultadoModulo:
    """
    Detecta si el sistema usa firewalld o ufw y lo audita.

    Args:
        puertos_ssh: Puertos en los que escucha sshd; se consideran esenciales.
    """
    r = ResultadoModulo(
        "firewall",
        datos={"herramienta": "ninguno", "activo": False, "puertos_abiertos": [], "puertos_a_revisar": []},
        mensaje_ok="Solo están abiertos los puertos esenciales.",
    )
    esenciales = PUERTOS_ESENCIALES | frozenset(puertos_ssh or [])

    if shutil.which("firewall-cmd"):
        r.info.append("Gestor detectado: firewalld")
        _auditar_firewalld(r, esenciales)
    elif shutil.which("ufw"):
        r.info.append("Gestor detectado: UFW")
        _auditar_ufw(r, esenciales)
    else:
        r.hallazgo("firewall_ausente",
                   "No se encontró firewalld ni ufw. El sistema NO tiene firewall gestionado.")
        r.recomendaciones.append("dnf install firewalld && systemctl enable --now firewalld")

    if r.recomendaciones and r.datos["puertos_a_revisar"]:
        r.recomendaciones.append(
            "Precaución: mantén una sesión SSH abierta mientras cambias reglas y no cierres el puerto de SSH."
        )
    return r


# ─────────────────────────────────────────────────────────────────────────────
# [4] USUARIOS
# ─────────────────────────────────────────────────────────────────────────────

SHELLS_SIN_LOGIN: frozenset[str] = frozenset({"/sbin/nologin", "/bin/false", "/usr/sbin/nologin"})


def auditar_usuarios(rutas: Optional[Rutas] = None) -> ResultadoModulo:
    """
    Audita /etc/passwd y /etc/shadow en busca de:
      - Usuarios con UID 0 distintos de root (escalada de privilegios).
      - Cuentas con el campo de contraseña vacío en /etc/passwd o
        /etc/shadow (permiten iniciar sesión sin contraseña).
    """
    rutas = rutas or RUTAS
    r = ResultadoModulo(
        "usuarios",
        datos={"usuarios_uid0_no_root": [], "cuentas_sin_contrasena": [],
               "total_usuarios": 0, "total_usuarios_sistema": 0},
        mensaje_ok="Ni usuarios con UID 0 distintos de root ni cuentas sin contraseña.",
    )
    sin_contrasena: list[str] = r.datos["cuentas_sin_contrasena"]

    def _sin_contrasena(usuario: str, fichero: str) -> None:
        if usuario not in sin_contrasena:
            sin_contrasena.append(usuario)
            r.hallazgo("cuenta_sin_contrasena", f"Cuenta '{usuario}' tiene contraseña VACÍA en {fichero}.")

    # ── /etc/passwd ──────────────────────────────────────────────────────────
    try:
        for linea in _leer_lineas(rutas.passwd):
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = linea.split(":")
            if len(partes) < 4:
                continue
            usuario, contrasena, uid = partes[0], partes[1], partes[2]
            shell = partes[6] if len(partes) > 6 else ""

            r.datos["total_usuarios"] += 1
            if shell in SHELLS_SIN_LOGIN:
                r.datos["total_usuarios_sistema"] += 1

            if uid == "0" and usuario != "root":
                r.datos["usuarios_uid0_no_root"].append(usuario)
                r.hallazgo("usuario_uid0_no_root",
                           f"Usuario '{usuario}' tiene UID 0 — privilegios equivalentes a root.")

            # Campo vacío en passwd ("user::...") → sin contraseña.
            # "x" o "*" delegan en /etc/shadow o bloquean la cuenta.
            if contrasena == "":
                _sin_contrasena(usuario, rutas.passwd)
        r.info.append(
            f"Entradas en {rutas.passwd}: {r.datos['total_usuarios']} "
            f"({r.datos['total_usuarios_sistema']} cuentas de sistema)"
        )
    except OSError as exc:
        r.error(f"No se pudo leer {rutas.passwd}: {exc.strerror or exc}")

    # ── /etc/shadow ───────────────────────────────────────────────────────────
    try:
        for linea in _leer_lineas(rutas.shadow):
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = linea.split(":")
            # Campo vacío "" → contraseña en blanco real (riesgo crítico)
            # "!" o "*" → cuenta bloqueada/sin login → no es un riesgo directo
            if len(partes) >= 2 and partes[1] == "":
                _sin_contrasena(partes[0], rutas.shadow)
    except OSError as exc:
        r.error(f"No se pudo leer {rutas.shadow}: {exc.strerror or exc}")

    if r.datos["usuarios_uid0_no_root"]:
        r.recomendaciones.append("Eliminar o cambiar el UID de los usuarios con UID 0 distintos de root.")
    if sin_contrasena:
        r.recomendaciones.append("Asignar contraseña (`passwd <usuario>`) o bloquear (`passwd -l <usuario>`) "
                                 "las cuentas sin contraseña.")
    return r


# ─────────────────────────────────────────────────────────────────────────────
# [5] SSH
# ─────────────────────────────────────────────────────────────────────────────

def _procesar_fichero_sshd(
    ruta: str,
    estado: dict,
    contexto_match: Optional[str],
    profundidad: int,
    directorio_ssh: str,
) -> None:
    """
    Procesa un fichero de configuración de sshd con su misma semántica:

      - Admite "Clave valor" y "Clave=valor"; claves insensibles a mayúsculas.
      - Gana el PRIMER valor de cada directiva (sshd ignora los siguientes).
      - Las directivas tras un bloque ``Match`` son condicionales: se guardan
        aparte y no cuentan como valor global.
      - ``Include`` admite varios patrones y comodines, rutas relativas al
        directorio de sshd_config y anidamiento hasta
        SSHD_MAX_PROFUNDIDAD_INCLUDE niveles. Un ``Match`` abierto dentro de
        un fichero incluido no se propaga al fichero que lo incluye.
    """
    if profundidad > SSHD_MAX_PROFUNDIDAD_INCLUDE:
        estado["errores"].append(f"Include demasiado anidado en {ruta}; se ignora.")
        return

    try:
        lineas = _leer_lineas(ruta)
    except OSError as exc:
        estado["errores"].append(f"No se pudo leer {ruta}: {exc.strerror or exc}")
        return

    if ruta not in estado["archivos"]:
        estado["archivos"].append(ruta)

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
                    _procesar_fichero_sshd(incluido, estado, contexto_match, profundidad + 1, directorio_ssh)
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
    _procesar_fichero_sshd(ruta, estado, None, 0, os.path.dirname(ruta))
    return estado


def _config_efectiva_sshd(ruta: str) -> tuple[Optional[dict[str, list[str]]], str]:
    """
    Obtiene la configuración efectiva con `sshd -T` (solo lectura: sshd
    valida y vuelca la configuración sin arrancar ni modificar nada).

    Returns:
        (valores, motivo). ``valores`` es None si no se pudo obtener, y
        ``motivo`` explica por qué.
    """
    if not shutil.which("sshd"):
        return None, "sshd no está en el PATH"
    codigo, stdout, stderr = ejecutar_comando(["sshd", "-T", "-f", ruta])
    if codigo != 0 or not stdout:
        return None, f"sshd -T falló: {stderr or codigo}"
    valores: dict[str, list[str]] = {}
    for linea in stdout.splitlines():
        clave, _, valor = linea.strip().partition(" ")
        if clave:
            valores.setdefault(clave.lower(), []).append(valor.strip())
    return valores, ""


def cargar_config_ssh(rutas: Optional[Rutas] = None) -> dict:
    """
    Determina los valores efectivos de las directivas de riesgo de sshd.

    Fuente principal: `sshd -T`. Si no está disponible se usa el análisis
    de los ficheros con la semántica de sshd y sus valores por defecto.
    En ambos casos se intenta localizar el fichero y la línea de origen.

    Returns:
        Diccionario con: ruta, existe, fuente, motivo_fuente, valores
        (clave → valor/archivo/línea), condicionales, archivos, puertos y errores.
    """
    ruta = (rutas or RUTAS).sshd_config
    existe = os.path.exists(ruta)
    parseado = (
        _parsear_sshd_config(ruta)
        if existe
        else {"valores": {}, "condicionales": [], "archivos": [], "errores": [], "puertos": []}
    )
    efectiva, motivo = _config_efectiva_sshd(ruta) if existe else (None, "")

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
        "ruta":          ruta,
        "existe":        existe,
        "fuente":        "sshd -T" if efectiva is not None else "análisis de ficheros",
        "motivo_fuente": motivo,
        "valores":       valores,
        "condicionales": parseado["condicionales"],
        "archivos":      parseado["archivos"],
        "puertos":       puertos,
        "errores":       parseado["errores"],
    }


def auditar_ssh(config: Optional[dict] = None, rutas: Optional[Rutas] = None) -> ResultadoModulo:
    """
    Evalúa la configuración efectiva de sshd en busca de directivas de riesgo.

    Args:
        config: Resultado de cargar_config_ssh(); si es None se calcula.
    """
    config = config if config is not None else cargar_config_ssh(rutas)
    r = ResultadoModulo(
        "ssh",
        datos={
            "estado": "OK",
            "ruta_config": config["ruta"],
            "fuente": config["fuente"],
            "archivos_analizados": config["archivos"],
            "directivas_riesgo": [],
            "directivas_condicionales": [],
            "directivas_seguras": [],
            "puertos_ssh": config["puertos"],
        },
        mensaje_ok="No se detectaron directivas SSH de riesgo.",
    )

    if not config["existe"]:
        r.datos["estado"] = "NO_INSTALADO"
        r.info.append(f"No se encontró {config['ruta']}: el servidor SSH no parece instalado.")
        r.mensaje_ok = "Servidor SSH no instalado: nada que auditar."
        return r

    fuente = config["fuente"]
    if config["motivo_fuente"]:
        fuente += f" ({config['motivo_fuente']})"
    r.info.append(f"Fuente: {fuente}")
    r.info.extend(f"Fichero analizado: {arc}" for arc in config["archivos"])
    r.info.append(f"Puerto(s) SSH: {', '.join(config['puertos'])}")

    if config["fuente"] != "sshd -T":
        for err in config["errores"]:
            r.error(err)

    for clave, (nombre, peligroso, codigo) in SSHD_DIRECTIVAS_RIESGO.items():
        entrada = config["valores"].get(clave)
        if entrada is None:
            continue
        valor = entrada["valor"]
        if valor.lower() != peligroso:
            r.datos["directivas_seguras"].append(f"{nombre} {valor}")
            continue

        if entrada["archivo"]:
            origen = f"{entrada['archivo']}:{entrada['linea']}"
        elif config["fuente"] == "sshd -T":
            origen = "configuración efectiva (sshd -T, valor por defecto)"
        else:
            origen = "valor por defecto de OpenSSH"

        r.datos["directivas_riesgo"].append({
            "directiva":   nombre,
            "valor":       valor,
            "linea_num":   entrada["linea"],
            "archivo":     entrada["archivo"],
            "origen":      origen,
            "descripcion": SSHD_DESCRIPCIONES[clave],
        })
        r.hallazgo(codigo, f"{origen}: '{nombre} {valor}' — {SSHD_DESCRIPCIONES[clave]}")

    for cond in config["condicionales"]:
        riesgo = SSHD_DIRECTIVAS_RIESGO.get(cond["clave"])
        if riesgo and cond["valor"].lower() == riesgo[1]:
            nombre = riesgo[0]
            origen = f"{cond['archivo']}:{cond['linea']}"
            r.datos["directivas_condicionales"].append(
                {"directiva": nombre, "valor": cond["valor"], "match": cond["match"], "origen": origen}
            )
            r.hallazgo("ssh_riesgo_condicional",
                       f"{origen}: '{nombre} {cond['valor']}' dentro de 'Match {cond['match']}'.")

    riesgos = {h["directiva"].lower() for h in r.datos["directivas_riesgo"]}
    if riesgos:
        cambios = {
            "permitrootlogin":        "PermitRootLogin no",
            "passwordauthentication": "PasswordAuthentication no",
            "permitemptypasswords":   "PermitEmptyPasswords no",
            "x11forwarding":          "X11Forwarding no",
            "protocol":               "Eliminar la directiva Protocol (solo existe SSHv2)",
        }
        r.recomendaciones.extend(cambios[c] for c in SSHD_DIRECTIVAS_RIESGO if c in riesgos)
        if "passwordauthentication" in riesgos or "permitrootlogin" in riesgos:
            r.recomendaciones.append(
                "ANTES de desactivar contraseñas o el login de root: comprueba que puedes entrar "
                "con clave pública con un usuario con sudo, desde OTRA sesión."
            )
        r.recomendaciones.append(
            "Valida la sintaxis antes de aplicar y conserva la sesión actual abierta: "
            "sshd -t && systemctl reload sshd"
        )
    return r


# ─────────────────────────────────────────────────────────────────────────────
# [6] ACTUALIZACIONES DE SEGURIDAD (RHEL/Rocky)
# ─────────────────────────────────────────────────────────────────────────────

_PATRON_AVISO = re.compile(r"[A-Z][A-Z0-9-]*-\d{4}[:-][0-9A-Za-z]+")
_PATRON_FECHA = re.compile(r"\d{4}-\d{2}-\d{2}")
_SEVERIDADES_DNF: tuple[str, ...] = ("Critical", "Important", "Moderate", "Low", "Desconocida")


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


def auditar_actualizaciones(offline: bool = False) -> ResultadoModulo:
    """
    Comprueba si existen actualizaciones de seguridad pendientes en sistemas
    basados en RPM/DNF con `dnf -q updateinfo list --security`, que lista los
    avisos de seguridad aplicables a los paquetes instalados.

    Args:
        offline: Si es True se añade ``-C`` (solo caché): dnf no contacta con
            los repositorios ni actualiza sus metadatos en /var/cache/dnf.
    """
    r = ResultadoModulo(
        "actualizaciones",
        datos={"gestor": "dnf", "estado": "DESCONOCIDO", "paquetes_pendientes": [],
               "total_pendientes": 0, "avisos": [], "severidades": {}},
        mensaje_ok="No hay actualizaciones de seguridad pendientes. Sistema al día.",
    )

    if not shutil.which("dnf"):
        r.datos["estado"] = "NO_DISPONIBLE"
        r.error("dnf no está disponible. Este módulo es específico de RHEL/Rocky/Fedora.")
        return r

    comando = ["dnf", "-q"] + (["-C"] if offline else []) + ["updateinfo", "list", "--security"]
    if offline:
        r.info.append("Modo offline: se usa solo la caché local de dnf (-C).")

    codigo, stdout, stderr = ejecutar_comando(comando, timeout=120)
    if codigo == -2:
        r.datos["estado"] = "ERROR_TIMEOUT"
        r.error("Timeout esperando respuesta de dnf. Revisa la conectividad con los "
                "repositorios — puede que algún mirror esté caído.")
        return r
    if codigo != 0:
        r.datos["estado"] = "ERROR"
        r.error(f"dnf updateinfo terminó con error (código {codigo}): {stderr or stdout}")
        return r

    avisos = _parsear_updateinfo(stdout)
    r.datos["avisos"] = avisos
    if not avisos:
        r.datos["estado"] = "ACTUALIZADO"
        return r

    r.datos["estado"] = "ACTUALIZACIONES_PENDIENTES"
    por_paquete: dict[str, list[dict]] = {}
    severidades: dict[str, int] = {}
    for aviso in avisos:
        por_paquete.setdefault(aviso["paquete"], []).append(aviso)
        severidades[aviso["severidad"]] = severidades.get(aviso["severidad"], 0) + 1
    r.datos["severidades"] = dict(sorted(severidades.items(), key=lambda kv: _SEVERIDADES_DNF.index(kv[0])))
    r.datos["paquetes_pendientes"] = [
        f"{pkg}  [" + ", ".join(f"{a['aviso']} {a['severidad']}" for a in lista) + "]"
        for pkg, lista in por_paquete.items()
    ]
    r.datos["total_pendientes"] = len(por_paquete)

    resumen = ", ".join(f"{n} {sev}" for sev, n in r.datos["severidades"].items())
    r.hallazgo(
        "actualizaciones_seguridad",
        f"{len(por_paquete)} paquete(s) con actualizaciones de seguridad pendientes "
        f"({len(avisos)} aviso(s): {resumen}).",
    )
    r.recomendaciones.append("dnf update --security   # revisar la lista antes de aplicar")
    return r


# ─────────────────────────────────────────────────────────────────────────────
# RIESGO — Nivel global a partir de la tabla SEVERIDADES
# ─────────────────────────────────────────────────────────────────────────────

def calcular_nivel_riesgo(resultados: dict[str, ResultadoModulo]) -> str:
    """
    Nivel de riesgo global: la severidad máxima de todos los hallazgos, según
    la tabla SEVERIDADES. Sin hallazgos → "BAJO". Los errores
    (comprobaciones no realizadas) no suben el nivel.
    """
    indice = 0
    for r in resultados.values():
        for h in r.hallazgos:
            indice = max(indice, NIVELES_RIESGO.index(h.severidad))
    return NIVELES_RIESGO[indice]


def comprobaciones_no_realizadas(resultados: dict[str, ResultadoModulo]) -> list[str]:
    """Errores de todos los módulos: si hay alguno, la auditoría está INCOMPLETA."""
    return [f"[{r.nombre}] {err}" for r in resultados.values() for err in r.errores]


# ─────────────────────────────────────────────────────────────────────────────
# [7] REPORTES — TXT, HTML y JSON
# ─────────────────────────────────────────────────────────────────────────────

RECOMENDACIONES_GENERALES: tuple[str, ...] = (
    "Mantener SELinux en modo Enforcing, también en /etc/selinux/config.",
    "Mantener firewalld/ufw activo y exponer solo los puertos imprescindibles.",
    "Eliminar o bloquear usuarios con UID 0 que no sean root.",
    "Asignar contraseña o bloquear todas las cuentas sin contraseña.",
    "Usar autenticación SSH por clave pública; validar con `sshd -t` antes de recargar sshd.",
    "Aplicar las actualizaciones de seguridad pendientes tras revisarlas.",
    "Repetir la auditoría periódicamente y complementarla con Lynis / OpenSCAP.",
)


def obtener_hostname() -> str:
    """FQDN del equipo (`hostname -f`), con respaldo en socket.gethostname()."""
    codigo, stdout, _ = ejecutar_comando(["hostname", "-f"])
    if codigo == 0 and stdout:
        return stdout
    return socket.gethostname() or "desconocido"


def _texto(valor: Any) -> str:
    """Representación legible de un dato para los reportes."""
    if valor is None or valor == "":
        return "N/A"
    if valor == [] or valor == {}:
        return "ninguno"
    if isinstance(valor, bool):
        return "Sí" if valor else "No"
    if isinstance(valor, (list, tuple)):
        return ", ".join(str(v) for v in valor)
    if isinstance(valor, dict):
        return ", ".join(f"{k}: {v}" for k, v in valor.items())
    return str(valor)


def resumen_modulo(r: ResultadoModulo) -> list[tuple[str, str]]:
    """Propiedades principales de un módulo como pares (etiqueta, valor)."""
    d = r.datos
    if r.nombre == "selinux":
        campos = [("Estado", d.get("estado")), ("Modo", d.get("modo")),
                  ("Modo persistente", d.get("modo_persistente")), ("Política", d.get("politica"))]
    elif r.nombre == "firewall":
        campos = [("Herramienta", d.get("herramienta")), ("Activo", bool(d.get("activo"))),
                  ("Zonas auditadas", d.get("zonas")), ("Puertos abiertos", d.get("puertos_abiertos")),
                  ("Puertos a revisar", d.get("puertos_a_revisar"))]
    elif r.nombre == "usuarios":
        campos = [("Entradas en passwd", d.get("total_usuarios")),
                  ("UID 0 (≠ root)", d.get("usuarios_uid0_no_root")),
                  ("Sin contraseña", d.get("cuentas_sin_contrasena"))]
    elif r.nombre == "ssh":
        campos = [("Configuración", d.get("ruta_config")), ("Fuente", d.get("fuente")),
                  ("Puerto(s) SSH", d.get("puertos_ssh")),
                  ("Directivas de riesgo", len(d.get("directivas_riesgo", [])))]
    elif r.nombre == "actualizaciones":
        campos = [("Gestor de paquetes", d.get("gestor")), ("Estado", d.get("estado")),
                  ("Paquetes pendientes", d.get("total_pendientes")),
                  ("Avisos por severidad", d.get("severidades"))]
    else:
        campos = list(d.items())
    return [(etiqueta, _texto(valor)) for etiqueta, valor in campos]


def detalle_modulo(r: ResultadoModulo, limite: int = 25) -> list[str]:
    """Listado adicional de un módulo (p. ej. paquetes pendientes)."""
    if r.nombre != "actualizaciones":
        return []
    paquetes = r.datos.get("paquetes_pendientes", [])
    lineas = list(paquetes[:limite])
    if len(paquetes) > limite:
        lineas.append(f"... y {len(paquetes) - limite} paquete(s) más.")
    return lineas


def renderizar_txt(informe: Informe) -> str:
    """Reporte en texto plano."""
    def sep(titulo: str) -> list[str]:
        return ["", "─" * 64, titulo, "─" * 64]

    lineas: list[str] = [
        "=" * 64,
        "  REPORTE DE AUDITORÍA DE SEGURIDAD DEL SERVIDOR",
        f"  GhostCheck {__version__}",
        "=" * 64,
        f"  Fecha y hora    : {informe.fecha:%Y-%m-%d %H:%M:%S}",
        f"  Hostname        : {informe.hostname}",
        "  Modo            : DRY-RUN (solo auditoría, sin cambios)",
        f"  Ejecutado como  : {'root' if informe.como_root else 'usuario sin privilegios (parcial)'}",
        f"  Nivel de riesgo : {informe.nivel_riesgo}",
        f"  Auditoría       : {informe.estado_auditoria}",
        "=" * 64,
    ]

    for r in informe.resultados.values():
        lineas += sep(f"[{r.numero}] {r.titulo}")
        ancho = max((len(e) for e, _ in resumen_modulo(r)), default=0)
        lineas += [f"  {e:<{ancho}} : {v}" for e, v in resumen_modulo(r)]
        lineas += [f"  [{'✘' if h.severidad in ('ALTO', 'CRÍTICO') else '⚠'}] {h.severidad}: {h.mensaje}"
                   for h in r.hallazgos]
        lineas += [f"  [?] No comprobado: {e}" for e in r.errores]
        if r.ok:
            lineas.append(f"  [✔] {r.mensaje_ok}")
        if detalle_modulo(r):
            lineas.append("  Detalle:")
            lineas += [f"    • {linea}" for linea in detalle_modulo(r)]
        if r.recomendaciones:
            lineas.append("  Recomendaciones (DRY-RUN, no se han aplicado):")
            lineas += [f"    - {rec}" for rec in r.recomendaciones]

    for nombre in informe.omitidos:
        numero, titulo = MODULOS[nombre]
        lineas += sep(f"[{numero}] {titulo}") + ["  Omitido (--skip)."]

    lineas += [
        "",
        "=" * 64,
        "RESUMEN EJECUTIVO",
        "=" * 64,
        f"  Nivel de riesgo global : {informe.nivel_riesgo}",
        f"  Estado de la auditoría : {informe.estado_auditoria}",
        f"  Total de advertencias  : {informe.total_advertencias}",
    ]
    if informe.no_realizadas:
        lineas.append("  Comprobaciones no realizadas (no suben el nivel de riesgo):")
        lineas += [f"    [?] {e}" for e in informe.no_realizadas]
    lineas += ["", "  RECOMENDACIONES GENERALES (DRY-RUN):"]
    lineas += [f"  {i}. {rec}" for i, rec in enumerate(RECOMENDACIONES_GENERALES, start=1)]
    lineas += ["=" * 64, ""]
    return "\n".join(lineas)


COLORES_RIESGO: dict[str, str] = {
    "BAJO": "#28a745", "MEDIO": "#b8860b", "ALTO": "#fd7e14", "CRÍTICO": "#dc3545",
}


def renderizar_html(informe: Informe) -> str:
    """Reporte HTML autocontenido. Todo dato del sistema se escapa."""

    def esc(valor: object) -> str:
        return html.escape(str(valor))

    nivel = informe.nivel_riesgo
    color_nivel = COLORES_RIESGO[nivel]

    def badge(texto: str, color: str) -> str:
        return f'<span class="badge" style="background:{color}">{esc(texto)}</span>'

    secciones: list[str] = []
    for r in informe.resultados.values():
        filas = "".join(
            f"<tr><th>{esc(e)}</th><td>{esc(v)}</td></tr>" for e, v in resumen_modulo(r)
        )
        items = "".join(
            f'<li>{badge(h.severidad, COLORES_RIESGO[h.severidad])} {esc(h.mensaje)}</li>'
            for h in r.hallazgos
        ) + "".join(f'<li class="gris">? No comprobado: {esc(e)}</li>' for e in r.errores)
        if r.ok:
            items = f'<li class="ok">✔ {esc(r.mensaje_ok)}</li>'
        detalle = "".join(f"<li><code>{esc(linea)}</code></li>" for linea in detalle_modulo(r))
        recs = "".join(f"<li><code>{esc(rec)}</code></li>" for rec in r.recomendaciones)
        secciones.append(
            f'<section class="sec"><h2>[{r.numero}] {esc(r.titulo)}</h2>'
            f'<table class="props">{filas}</table>'
            f"<ul>{items}</ul>"
            + (f"<h3>Detalle</h3><ul>{detalle}</ul>" if detalle else "")
            + (f"<h3>Recomendaciones (DRY-RUN, no aplicadas)</h3><ul>{recs}</ul>" if recs else "")
            + "</section>"
        )
    for nombre in informe.omitidos:
        numero, titulo = MODULOS[nombre]
        secciones.append(f'<section class="sec"><h2>[{numero}] {esc(titulo)}</h2>'
                         '<p class="gris">Omitido (--skip).</p></section>')

    no_realizadas = "".join(f"<li>{esc(e)}</li>" for e in informe.no_realizadas)
    generales = "".join(f"<li>{esc(rec)}</li>" for rec in RECOMENDACIONES_GENERALES)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Auditoría de Seguridad — {esc(informe.hostname)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ font-family: system-ui, 'Segoe UI', Arial, sans-serif; background: #eef1f5;
           color: #2c3e50; margin: 0; padding: 24px; font-size: 14px; line-height: 1.55; }}
    .wrap {{ max-width: 980px; margin: 0 auto; background: #fff; border-radius: 10px;
            box-shadow: 0 3px 18px rgba(0,0,0,.12); overflow: hidden; }}
    .hdr {{ background: linear-gradient(135deg, #1a252f 0%, #2c3e50 100%); color: #fff; padding: 28px 36px; }}
    .hdr h1 {{ margin: 0 0 6px; font-size: 1.5em; }}
    .hdr p {{ margin: 0; font-size: .88em; opacity: .75; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 12px 28px; padding: 13px 36px; background: #f8f9fa;
            border-bottom: 1px solid #dee2e6; font-size: .86em; }}
    .sec {{ padding: 20px 36px; border-bottom: 1px solid #e9ecef; }}
    .sec h2 {{ margin: 0 0 12px; font-size: 1em; border-left: 4px solid #3498db; padding-left: 11px; }}
    .sec h3 {{ font-size: .9em; margin: 14px 0 4px; color: #555; }}
    .sec ul {{ margin: 8px 0 0 18px; padding: 0; }}
    .sec li {{ margin-bottom: 4px; }}
    table.props {{ border-collapse: collapse; }}
    table.props th {{ text-align: left; color: #555; padding: 3px 14px 3px 0; white-space: nowrap;
                      vertical-align: top; font-weight: 600; }}
    table.props td {{ padding: 3px 0; overflow-wrap: anywhere; }}
    .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: .78em; font-weight: 700; }}
    .ok {{ color: #28a745; list-style: none; margin-left: -18px; }}
    .gris {{ color: #6c757d; }}
    code {{ background: #f1f3f5; padding: 1px 5px; border-radius: 3px; overflow-wrap: anywhere; }}
    .risk {{ margin: 22px 36px 30px; padding: 18px 24px; border-radius: 8px; background: #f8f9fa;
             border: 2px solid {color_nivel}; }}
    .risk h2 {{ margin: 0 0 10px; color: {color_nivel}; font-size: 1.15em; }}
    .ftr {{ text-align: center; padding: 13px; font-size: .76em; color: #888; background: #f8f9fa; }}
    @media (max-width: 600px) {{ body {{ padding: 8px; }} .hdr, .sec, .meta {{ padding-left: 16px; padding-right: 16px; }}
                                 .risk {{ margin: 16px; }} }}
  </style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <h1>Reporte de Auditoría de Seguridad</h1>
    <p>GhostCheck {esc(__version__)} · Modo DRY-RUN — solo lectura, sin cambios en el sistema</p>
  </div>
  <div class="meta">
    <span><b>Fecha:</b> {informe.fecha:%Y-%m-%d %H:%M:%S}</span>
    <span><b>Hostname:</b> {esc(informe.hostname)}</span>
    <span><b>Ejecutado como:</b> {'root' if informe.como_root else 'usuario sin privilegios (parcial)'}</span>
    <span><b>Total advertencias:</b> {informe.total_advertencias}</span>
    <span><b>Auditoría:</b> {esc(informe.estado_auditoria)}</span>
    <span><b>Nivel de riesgo:</b> {badge(nivel, color_nivel)}</span>
  </div>
  {''.join(secciones)}
  <div class="risk">
    <h2>Resumen ejecutivo — Nivel de riesgo: {esc(nivel)}</h2>
    {f'<p><b>Comprobaciones no realizadas</b> (no suben el nivel de riesgo):</p><ul>{no_realizadas}</ul>'
     if no_realizadas else ''}
    <p><b>Recomendaciones generales</b> (DRY-RUN):</p>
    <ul>{generales}</ul>
  </div>
  <div class="ftr">Generado por GhostCheck · DRY-RUN — No se realizó ningún cambio en el sistema</div>
</div>
</body>
</html>
"""


def renderizar_json(informe: Informe) -> str:
    """Reporte JSON para automatización."""
    datos = {
        "herramienta": "GhostCheck",
        "version": __version__,
        "modo": "DRY-RUN",
        "fecha": informe.fecha.isoformat(timespec="seconds"),
        "hostname": informe.hostname,
        "como_root": informe.como_root,
        "nivel_riesgo": informe.nivel_riesgo,
        "auditoria_completa": informe.completa,
        "comprobaciones_no_realizadas": informe.no_realizadas,
        "total_advertencias": informe.total_advertencias,
        "omitidos": informe.omitidos,
        "modulos": {
            nombre: {
                "titulo": r.titulo,
                "ok": r.ok,
                "hallazgos": [asdict(h) for h in r.hallazgos],
                "errores": r.errores,
                "datos": r.datos,
                "recomendaciones": r.recomendaciones,
            }
            for nombre, r in informe.resultados.items()
        },
    }
    return json.dumps(datos, ensure_ascii=False, indent=2) + "\n"


RENDERIZADORES = {"txt": renderizar_txt, "html": renderizar_html, "json": renderizar_json}


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


def nombre_reporte(informe: Informe, formato: str) -> str:
    return f"auditoria_servidor_{informe.fecha:%Y%m%d_%H%M%S}.{formato}"


def guardar_reportes(
    informe: Informe, directorio: str, formatos: list[str]
) -> tuple[list[str], list[str]]:
    """
    Genera y guarda los reportes pedidos.

    Returns:
        (rutas_generadas, errores)
    """
    generadas: list[str] = []
    errores: list[str] = []
    for formato in formatos:
        ruta = os.path.join(directorio, nombre_reporte(informe, formato))
        try:
            escribir_reporte_seguro(ruta, RENDERIZADORES[formato](informe))
            generadas.append(str(Path(ruta).resolve()))
        except OSError as exc:
            errores.append(f"No se pudo guardar el reporte {formato.upper()} en {ruta}: {exc}")
    return generadas, errores


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLA — Presentación en terminal
# ─────────────────────────────────────────────────────────────────────────────

ANSI_RIESGO: dict[str, str] = {
    "BAJO": "\033[32m", "MEDIO": "\033[33m", "ALTO": "\033[91m", "CRÍTICO": "\033[31m",
}
ANSI_RESET = "\033[0m"


class Consola:
    """
    Salida en terminal. Los colores y el spinner solo se usan en una
    terminal interactiva, sin --no-color y sin la variable NO_COLOR.
    En modo silencioso solo se imprime el resumen final y los errores.
    """

    def __init__(self, color: bool = True, silencioso: bool = False,
                 salida: Optional[TextIO] = None) -> None:
        self.salida = salida or sys.stdout
        self.interactiva = bool(getattr(self.salida, "isatty", lambda: False)())
        self.color = color and self.interactiva and "NO_COLOR" not in os.environ
        self.silencioso = silencioso

    def linea(self, texto: str = "", forzar: bool = False) -> None:
        if forzar or not self.silencioso:
            print(texto, file=self.salida)

    def error(self, texto: str) -> None:
        print(texto, file=sys.stderr)

    def colorear(self, texto: str, nivel: str) -> str:
        return f"{ANSI_RIESGO[nivel]}{texto}{ANSI_RESET}" if self.color else texto

    def cabecera(self, titulo: str) -> None:
        self.linea("=" * 64)
        self.linea(f"  {titulo}")
        self.linea("=" * 64)

    def spinner(self, mensaje: str) -> "Spinner":
        return Spinner(mensaje, self.salida, activo=self.interactiva and not self.silencioso)


class Spinner:
    """
    Animación de carga en consola mientras un comando lento (dnf) trabaja.
    Si ``activo`` es False (salida redirigida, cron, --quiet) no escribe nada.

    Uso:
        with Spinner("Consultando repositorios...", sys.stdout):
            resultado = operacion_lenta()
    """

    _FRAMES: tuple[str, ...] = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    _DELAY: float = 0.1

    def __init__(self, mensaje: str, salida: TextIO, activo: bool = True) -> None:
        self._mensaje = mensaje
        self._salida = salida
        self._activo_cfg = activo
        self._parar = threading.Event()
        self._hilo: Optional[threading.Thread] = None

    def _girar(self) -> None:
        for frame in itertools.cycle(self._FRAMES):
            if self._parar.is_set():
                break
            self._salida.write(f"\r  {frame}  {self._mensaje}")
            self._salida.flush()
            time.sleep(self._DELAY)
        self._salida.write(f"\r{' ' * (len(self._mensaje) + 8)}\r")
        self._salida.flush()

    def __enter__(self) -> "Spinner":
        if self._activo_cfg:
            self._hilo = threading.Thread(target=self._girar, daemon=True)
            self._hilo.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._parar.set()
        if self._hilo:
            self._hilo.join()


def imprimir_resultado(consola: Consola, r: ResultadoModulo) -> None:
    """Muestra en terminal el resultado de un módulo."""
    consola.cabecera(f"[{r.numero}] {r.titulo}")
    for linea in r.info:
        consola.linea(f"  [i] {linea}")
    for h in r.hallazgos:
        simbolo = "✘" if h.severidad in ("ALTO", "CRÍTICO") else "⚠"
        consola.linea(f"  [{simbolo}] {consola.colorear(h.severidad, h.severidad)}: {h.mensaje}")
    for err in r.errores:
        consola.linea(f"  [?] No comprobado: {err}")
    if r.ok:
        consola.linea(f"  [✔] {r.mensaje_ok}")
    for linea in detalle_modulo(r, limite=10):
        consola.linea(f"      • {linea}")
    if r.recomendaciones:
        consola.linea("  Recomendaciones (DRY-RUN, no se aplican):")
        for rec in r.recomendaciones:
            consola.linea(f"    - {rec}")
    consola.linea()


# ─────────────────────────────────────────────────────────────────────────────
# CLI — Argumentos, privilegios y orquestación
# ─────────────────────────────────────────────────────────────────────────────

class _Parser(argparse.ArgumentParser):
    """ArgumentParser que sale con SALIDA_ERROR (4) en errores de uso, para no
    confundirlos con los códigos 0–3 del nivel de riesgo."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(SALIDA_ERROR, f"{self.prog}: error: {message}\n")


def _lista_csv(opciones: tuple[str, ...]):
    def convertir(valor: str) -> list[str]:
        elegidos = [v.strip().lower() for v in valor.split(",") if v.strip()]
        invalidos = [v for v in elegidos if v not in opciones]
        if invalidos or not elegidos:
            raise argparse.ArgumentTypeError(
                f"valor no válido: {valor!r} (opciones: {', '.join(opciones)})"
            )
        return list(dict.fromkeys(elegidos))
    return convertir


def parsear_argumentos(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Define y procesa los argumentos de línea de comandos."""
    parser = _Parser(
        prog="ghostcheck",
        description="Auditoría de seguridad para servidores Linux / RHEL en modo DRY-RUN: "
                    "solo lee el sistema, nunca lo modifica.",
        epilog="Códigos de salida: 0 BAJO · 1 MEDIO · 2 ALTO · 3 CRÍTICO · "
               "4 error de uso o de ejecución · 130 interrumpido.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-o", "--output-dir", default=".",
                        help="Directorio donde se guardan los reportes (por defecto: el actual).")
    parser.add_argument("-f", "--format", dest="formatos", type=_lista_csv(FORMATOS_REPORTE),
                        default=["txt", "html"],
                        help="Formatos de reporte separados por comas: txt, html, json "
                             "(por defecto: txt,html).")
    parser.add_argument("--skip", dest="omitir", type=_lista_csv(tuple(MODULOS)), default=[],
                        help=f"Módulos a omitir, separados por comas: {', '.join(MODULOS)}.")
    parser.add_argument("--offline", action="store_true",
                        help="dnf usa solo su caché local (-C): no contacta con los repositorios "
                             "ni actualiza los metadatos en /var/cache/dnf.")
    parser.add_argument("--no-color", action="store_true", help="Desactiva los colores ANSI.")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Muestra solo el resumen final.")
    parser.add_argument("--allow-non-root", action="store_true",
                        help="Permite ejecutar sin root: auditoría parcial (p. ej. sin /etc/shadow) "
                             "marcada como INCOMPLETA.")
    return parser.parse_args(argv)


def es_root() -> bool:
    return os.getuid() == 0


def ejecutar_auditoria(args: argparse.Namespace, consola: Consola) -> dict[str, ResultadoModulo]:
    """Ejecuta los módulos no omitidos y muestra cada resultado."""
    resultados: dict[str, ResultadoModulo] = {}
    # La configuración SSH se carga siempre: el firewall necesita sus puertos
    config_ssh = cargar_config_ssh()

    for nombre in MODULOS:
        if nombre in args.omitir:
            continue
        if nombre == "selinux":
            r = auditar_selinux()
        elif nombre == "firewall":
            r = auditar_firewall(config_ssh["puertos"])
        elif nombre == "usuarios":
            r = auditar_usuarios()
        elif nombre == "ssh":
            r = auditar_ssh(config_ssh)
        else:
            with consola.spinner("Consultando avisos de seguridad con dnf updateinfo..."):
                r = auditar_actualizaciones(offline=args.offline)
        resultados[nombre] = r
        imprimir_resultado(consola, r)
    return resultados


def main(argv: Optional[list[str]] = None) -> int:
    """
    Punto de entrada. Devuelve el código de salida:
    0–3 según el nivel de riesgo, 4 en error de uso/ejecución, 130 si se interrumpe.
    """
    args = parsear_argumentos(argv)
    consola = Consola(color=not args.no_color, silencioso=args.quiet)

    if not os.path.isdir(args.output_dir):
        consola.error(f"[✘ ERROR] El directorio de salida no existe: {args.output_dir}")
        return SALIDA_ERROR

    consola.cabecera(f"GHOSTCHECK {__version__}  —  Modo DRY-RUN: sin cambios en el sistema")
    consola.linea()

    como_root = es_root()
    if not como_root and not args.allow_non_root:
        consola.error("[✘ ERROR] Este script debe ejecutarse como root (UID 0).")
        consola.error("  Utiliza: sudo python3 ghostcheck.py   (o --allow-non-root para una auditoría parcial)")
        return SALIDA_ERROR
    consola.linea("[✔] Ejecutando como root. Privilegios verificados.\n" if como_root else
                  "[⚠] Ejecutando SIN root: la auditoría será parcial e INCOMPLETA.\n")

    try:
        fecha = datetime.now()
        resultados = ejecutar_auditoria(args, consola)
        informe = Informe(
            fecha=fecha,
            hostname=obtener_hostname(),
            como_root=como_root,
            resultados=resultados,
            omitidos=[m for m in MODULOS if m in args.omitir],
        )
        consola.cabecera("[7] GENERACIÓN DE REPORTES")
        generadas, errores = guardar_reportes(informe, args.output_dir, args.formatos)
    except KeyboardInterrupt:
        consola.error("\n[!] Auditoría interrumpida por el usuario. No se ha generado ningún reporte.")
        return SALIDA_INTERRUMPIDO

    for ruta in generadas:
        consola.linea(f"[✔] Reporte generado: {ruta}")
    for err in errores:
        consola.error(f"[✘] {err}")

    nivel = informe.nivel_riesgo
    consola.linea(f"\n{'=' * 64}", forzar=True)
    consola.linea(f"  Auditoría completada — Nivel de riesgo: {consola.colorear(nivel, nivel)}", forzar=True)
    if not informe.completa:
        consola.linea(f"  [?] Auditoría {informe.estado_auditoria}", forzar=True)
    for ruta in generadas:
        consola.linea(f"  → {ruta}", forzar=True)
    consola.linea("=" * 64, forzar=True)

    return SALIDA_ERROR if errores else CODIGOS_SALIDA[nivel]


if __name__ == "__main__":
    sys.exit(main())
