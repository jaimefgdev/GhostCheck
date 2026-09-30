"""
Base de pruebas de GhostCheck.

Garantías que aplica a TODOS los tests (fixture autouse ``sistema_aislado``):

  * Ningún test ejecuta comandos reales: ``subprocess.run`` se sustituye por
    un simulador que devuelve respuestas registradas con ``comandos.registrar``.
  * Lista blanca propia de los tests (``COMANDOS_SOLO_LECTURA``), independiente
    de la del script: cualquier intento de ejecutar un comando que no esté en
    ella hace fallar el test al instante, aunque el script lo bloqueara.
  * ``shutil.which`` se simula: solo "existen" los binarios declarados con
    ``comandos.instalar``.
  * Las rutas del sistema (/etc/passwd, /etc/shadow, sshd_config) apuntan a
    ficheros inexistentes dentro de ``tmp_path`` y el directorio de trabajo
    es ``tmp_path``, así que los reportes nunca se escriben en el repositorio.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ghostcheck  # noqa: E402

# Plantillas de comandos de solo lectura aceptados en los tests. Misma sintaxis
# que ghostcheck.COMANDOS_PERMITIDOS. Se mantiene aparte a propósito: ampliar la
# lista del script obliga a ampliar también esta, y ese cambio queda visible en
# la revisión (ver test_lista_blanca_del_script_esta_cubierta_por_los_tests).
COMANDOS_SOLO_LECTURA: tuple[tuple[str, ...], ...] = (
    ("getenforce",),
    ("sestatus",),
    ("systemctl", "is-active", "firewalld"),
    ("firewall-cmd", "--list-ports",    r"--zone=[\w.-]+"),
    ("firewall-cmd", "--list-services", r"--zone=[\w.-]+"),
    ("ufw", "status", "verbose"),
    ("dnf", "check-update", "--security"),
    ("hostname", "-f"),
)


def es_solo_lectura(comando: list[str]) -> bool:
    return any(
        len(plantilla) == len(comando)
        and all(re.fullmatch(p, a) for p, a in zip(plantilla, comando))
        for plantilla in COMANDOS_SOLO_LECTURA
    )


@dataclass
class Respuesta:
    codigo: int = 0
    stdout: str = ""
    stderr: str = ""
    excepcion: BaseException | None = None


@dataclass
class ComandosSimulados:
    """Registro de respuestas simuladas y de los comandos invocados."""

    respuestas: dict[tuple[str, ...], Respuesta] = field(default_factory=dict)
    instalados: set[str] = field(default_factory=set)
    ejecutados: list[list[str]] = field(default_factory=list)
    kwargs_run: list[dict] = field(default_factory=list)

    def registrar(self, comando: list[str], codigo: int = 0, stdout: str = "",
                  stderr: str = "", excepcion: BaseException | None = None) -> None:
        assert es_solo_lectura(comando), f"Respuesta para comando no permitido: {comando}"
        self.respuestas[tuple(comando)] = Respuesta(codigo, stdout, stderr, excepcion)
        self.instalados.add(comando[0])

    def instalar(self, *binarios: str) -> None:
        self.instalados.update(binarios)

    # ── Sustitutos ───────────────────────────────────────────────────────────

    def which(self, nombre: str, *_, **__) -> str | None:
        return f"/usr/bin/{nombre}" if nombre in self.instalados else None

    def run(self, comando, *args, **kwargs):
        comando = list(comando)
        if not es_solo_lectura(comando):
            pytest.fail(f"DRY-RUN violado: subprocess.run({comando!r}) no está en la lista blanca")
        self.ejecutados.append(comando)
        self.kwargs_run.append(kwargs)
        resp = self.respuestas.get(tuple(comando))
        if resp is None:
            # Comando permitido pero no registrado: se simula "no instalado".
            raise FileNotFoundError(2, "No such file or directory", comando[0])
        if resp.excepcion is not None:
            raise resp.excepcion
        return subprocess.CompletedProcess(comando, resp.codigo, resp.stdout, resp.stderr)


@pytest.fixture
def comandos() -> ComandosSimulados:
    return ComandosSimulados()


@pytest.fixture(autouse=True)
def sistema_aislado(monkeypatch, tmp_path, comandos):
    ejecutar_real = ghostcheck.ejecutar_comando

    def ejecutar_vigilado(comando, timeout=10):
        if not es_solo_lectura(list(comando)):
            pytest.fail(f"DRY-RUN violado: se intentó ejecutar {comando!r}")
        return ejecutar_real(comando, timeout)

    monkeypatch.setattr(ghostcheck, "ejecutar_comando", ejecutar_vigilado)
    monkeypatch.setattr(ghostcheck.subprocess, "run", comandos.run)
    monkeypatch.setattr(ghostcheck.shutil, "which", comandos.which)

    etc = tmp_path / "etc"
    etc.mkdir()
    monkeypatch.setattr(ghostcheck, "RUTA_PASSWD", str(etc / "passwd"))
    monkeypatch.setattr(ghostcheck, "RUTA_SHADOW", str(etc / "shadow"))
    monkeypatch.setattr(ghostcheck, "RUTA_SSHD_CFG", str(etc / "ssh" / "sshd_config"))
    monkeypatch.chdir(tmp_path)
    return ejecutar_real


@pytest.fixture
def ejecutar_real(sistema_aislado):
    """``ejecutar_comando`` original, sin el vigilante de los tests (sigue sin
    ejecutar nada real: subprocess.run está simulado)."""
    return sistema_aislado


@pytest.fixture
def etc(tmp_path) -> Path:
    return tmp_path / "etc"
