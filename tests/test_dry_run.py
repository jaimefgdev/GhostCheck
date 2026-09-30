"""El modo DRY-RUN: solo se ejecutan comandos de lectura de la lista blanca."""

from __future__ import annotations

import os
import stat

import pytest

import ghostcheck
from conftest import COMANDOS_SOLO_LECTURA

COMANDOS_PELIGROSOS = [
    ["rm", "-rf", "/"],
    ["dnf", "update", "--security", "-y"],
    ["dnf", "-q", "updateinfo", "list", "--security", "-y"],
    ["dnf", "check-update", "--security"],
    ["sshd", "-t"],
    ["sshd", "-T", "-f", "/etc/ssh/sshd_config;id"],
    ["ufw", "app", "info", "x;reboot"],
    ["firewall-cmd", "--permanent", "--remove-port=8080/tcp"],
    ["firewall-cmd", "--list-ports", "--zone=public;reboot"],
    ["systemctl", "restart", "sshd"],
    ["systemctl", "is-active", "firewalld", "--now"],
    ["ufw", "deny", "8080"],
    ["setenforce", "1"],
    ["sh", "-c", "getenforce"],
    ["which", "dnf"],
]


def test_lista_blanca_del_script_esta_cubierta_por_los_tests():
    """Toda plantilla del script debe estar revisada en la lista de los tests."""
    faltan = set(ghostcheck.COMANDOS_PERMITIDOS) - set(COMANDOS_SOLO_LECTURA)
    assert not faltan, f"Plantillas sin revisar en tests/conftest.py: {faltan}"


@pytest.mark.parametrize("comando", COMANDOS_PELIGROSOS, ids=" ".join)
def test_el_script_bloquea_comandos_fuera_de_la_lista(comando, ejecutar_real, comandos):
    codigo, stdout, stderr = ejecutar_real(comando)
    assert codigo == -4
    assert stdout == ""
    assert "DRY-RUN" in stderr
    assert comandos.ejecutados == []  # nunca llegó a subprocess.run


@pytest.mark.parametrize("comando", COMANDOS_PELIGROSOS, ids=" ".join)
def test_los_tests_fallan_si_se_intenta_un_comando_no_permitido(comando):
    with pytest.raises(pytest.fail.Exception, match="DRY-RUN violado"):
        ghostcheck.ejecutar_comando(comando)


def test_codigos_de_error_de_ejecutar_comando(ejecutar_real, comandos):
    import subprocess

    assert ejecutar_real(["getenforce"])[0] == -1  # no registrado → no instalado
    comandos.registrar(["sestatus"], excepcion=subprocess.TimeoutExpired("sestatus", 10))
    assert ejecutar_real(["sestatus"])[0] == -2
    comandos.registrar(["hostname", "-f"], excepcion=RuntimeError("boom"))
    assert ejecutar_real(["hostname", "-f"])[0] == -3


def test_la_salida_de_comandos_se_decodifica_sin_fallar(comandos):
    comandos.registrar(["getenforce"], stdout="Enforcing\n")
    ghostcheck.ejecutar_comando(["getenforce"])
    assert comandos.kwargs_run[-1].get("errors") == "replace"
    assert comandos.kwargs_run[-1].get("text") is True
    assert "shell" not in comandos.kwargs_run[-1]


def test_ejecucion_completa_solo_usa_comandos_de_lectura(monkeypatch, tmp_path, comandos, etc):
    """main() de principio a fin sobre un sistema simulado."""
    monkeypatch.setattr(ghostcheck.os, "getuid", lambda: 0)
    comandos.registrar(["getenforce"], stdout="Enforcing")
    comandos.registrar(["sestatus"], stdout="Loaded policy name:             targeted")
    comandos.firewalld_activo(puertos="8080/tcp", servicios="ssh")
    comandos.registrar(["firewall-cmd", "--info-service=ssh"], stdout="ssh\n  ports: 22/tcp")
    comandos.registrar(["dnf", "-q", "updateinfo", "list", "--security"], codigo=0)
    comandos.registrar(["hostname", "-f"], stdout="srv.example.test")
    (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    salida = tmp_path / "reportes"
    salida.mkdir()

    ghostcheck.main(["--output-dir", str(salida)])

    usados = {c[0] for c in comandos.ejecutados}
    assert usados <= {"getenforce", "sestatus", "systemctl", "firewall-cmd", "dnf", "hostname", "sshd"}
    reportes = sorted(salida.iterdir())
    assert [p.suffix for p in reportes] == [".html", ".txt"]
    for p in reportes:
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert not list(tmp_path.glob("auditoria_servidor_*"))  # nada fuera de --output-dir


def test_output_dir_inexistente_termina_con_error(tmp_path):
    with pytest.raises(SystemExit) as exc:
        ghostcheck.main(["--output-dir", str(tmp_path / "no-existe")])
    assert exc.value.code == 2
