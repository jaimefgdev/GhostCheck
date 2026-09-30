"""Puntos 11–15: CLI, códigos de salida, salida en terminal, ejecución sin
root, recomendaciones seguras y separación comprobación / presentación."""

from __future__ import annotations

import io
import json

import pytest

import ghostcheck
from conftest import informe, resultado

SOLO_USUARIOS = ["--skip", "selinux,firewall,ssh,actualizaciones"]


@pytest.fixture
def root(monkeypatch):
    monkeypatch.setattr(ghostcheck.os, "getuid", lambda: 0)


@pytest.fixture
def salida(tmp_path):
    d = tmp_path / "reportes"
    d.mkdir()
    return d


def passwd(etc, extra: str = "") -> None:
    (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n" + extra)
    (etc / "shadow").write_text("root:$6$abc:19000::::::\n")


# ── Punto 11: argumentos y códigos de salida ─────────────────────────────────

def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        ghostcheck.main(["--version"])
    assert exc.value.code == 0
    assert ghostcheck.__version__ in capsys.readouterr().out


@pytest.mark.parametrize("args", [["--format", "pdf"], ["--skip", "kernel"], ["--desconocida"], ["--format", ""]])
def test_argumentos_invalidos_salen_con_4(args):
    with pytest.raises(SystemExit) as exc:
        ghostcheck.main(args)
    assert exc.value.code == ghostcheck.SALIDA_ERROR


@pytest.mark.parametrize("extra, codigo", [
    ("", 0),                                              # BAJO
    ("toor:x:0:0::/root:/bin/bash\n", 3),                 # CRÍTICO
])
def test_codigo_de_salida_segun_nivel(root, etc, salida, extra, codigo):
    passwd(etc, extra)
    assert ghostcheck.main(["-o", str(salida), *SOLO_USUARIOS]) == codigo


def test_codigo_de_salida_medio_y_alto(root, comandos, salida):
    comandos.registrar(["getenforce"], stdout="Permissive")
    assert ghostcheck.main(["-o", str(salida), "--skip", "firewall,usuarios,ssh,actualizaciones"]) == 1
    assert ghostcheck.main(["-o", str(salida / ".."), "--skip", "selinux,usuarios,ssh,actualizaciones"]) == 2


def test_formato_json(root, etc, salida):
    passwd(etc)
    ghostcheck.main(["-o", str(salida), "--format", "json", *SOLO_USUARIOS])
    ficheros = list(salida.iterdir())
    assert [f.suffix for f in ficheros] == [".json"]
    datos = json.loads(ficheros[0].read_text())
    assert datos["nivel_riesgo"] == "BAJO"
    assert list(datos["modulos"]) == ["usuarios"]
    assert datos["omitidos"] == ["selinux", "firewall", "ssh", "actualizaciones"]


def test_varios_formatos(root, etc, salida):
    passwd(etc)
    ghostcheck.main(["-o", str(salida), "-f", "txt,json,html", *SOLO_USUARIOS])
    assert sorted(f.suffix for f in salida.iterdir()) == [".html", ".json", ".txt"]


def test_skip_no_ejecuta_los_modulos_omitidos(root, etc, salida, comandos):
    passwd(etc)
    ghostcheck.main(["-o", str(salida), "-f", "txt", *SOLO_USUARIOS])
    assert {c[0] for c in comandos.ejecutados} <= {"hostname"}
    texto = next(salida.iterdir()).read_text()
    assert "Omitido (--skip)" in texto


def test_error_al_guardar_reporte_sale_con_4(root, etc, salida, monkeypatch):
    passwd(etc)

    def falla(*_):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(ghostcheck, "escribir_reporte_seguro", falla)
    assert ghostcheck.main(["-o", str(salida), *SOLO_USUARIOS]) == ghostcheck.SALIDA_ERROR


# ── Punto 12: salida en terminal ─────────────────────────────────────────────

class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_sin_colores_si_no_es_terminal(root, etc, salida, capsys):
    passwd(etc, "toor:x:0:0::/root:/bin/bash\n")
    ghostcheck.main(["-o", str(salida), *SOLO_USUARIOS])
    assert "\033[" not in capsys.readouterr().out


def test_colores_en_terminal_y_su_desactivacion(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert ghostcheck.Consola(salida=TTY()).color is True
    assert ghostcheck.Consola(color=False, salida=TTY()).color is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert ghostcheck.Consola(salida=TTY()).color is False


def test_spinner_inactivo_fuera_de_terminal():
    buf = io.StringIO()
    with ghostcheck.Consola(salida=buf).spinner("trabajando"):
        pass
    assert buf.getvalue() == ""


def test_spinner_activo_en_terminal_se_limpia():
    buf = TTY()
    with ghostcheck.Consola(salida=buf).spinner("trabajando"):
        pass
    assert buf.getvalue().endswith("\r")


def test_modo_silencioso_solo_muestra_el_resumen(root, etc, salida, capsys):
    passwd(etc)
    ghostcheck.main(["-o", str(salida), "--quiet", *SOLO_USUARIOS])
    out = capsys.readouterr().out
    assert "AUDITORÍA DE USUARIOS" not in out
    assert "Nivel de riesgo: BAJO" in out


def test_ctrl_c_sale_con_130_sin_reportes(root, salida, monkeypatch, capsys):
    def interrumpir(*_, **__):
        raise KeyboardInterrupt
    monkeypatch.setattr(ghostcheck, "auditar_selinux", interrumpir)
    assert ghostcheck.main(["-o", str(salida)]) == ghostcheck.SALIDA_INTERRUMPIDO
    assert list(salida.iterdir()) == []
    assert "Traceback" not in capsys.readouterr().err


# ── Punto 13: ejecución sin root ─────────────────────────────────────────────

def test_sin_root_falla_por_defecto(monkeypatch, salida):
    monkeypatch.setattr(ghostcheck.os, "getuid", lambda: 1000)
    assert ghostcheck.main(["-o", str(salida)]) == ghostcheck.SALIDA_ERROR
    assert list(salida.iterdir()) == []


def test_sin_root_con_permiso_es_parcial_e_incompleta(monkeypatch, etc, salida):
    monkeypatch.setattr(ghostcheck.os, "getuid", lambda: 1000)
    (etc / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")  # shadow ilegible/ausente
    codigo = ghostcheck.main(["-o", str(salida), "-f", "json", "--allow-non-root", *SOLO_USUARIOS])
    assert codigo == 0
    datos = json.loads(next(salida.iterdir()).read_text())
    assert datos["como_root"] is False
    assert datos["auditoria_completa"] is False


# ── Punto 14: recomendaciones que no dejan sin acceso ────────────────────────

def test_recomendaciones_ssh_validan_y_avisan(etc):
    (etc / "ssh").mkdir()
    (etc / "ssh" / "sshd_config").write_text("PermitRootLogin yes\nPasswordAuthentication yes\n")
    recs = "\n".join(ghostcheck.auditar_ssh().recomendaciones)
    assert "sshd -t && systemctl reload sshd" in recs
    assert "clave pública" in recs and "OTRA sesión" in recs
    assert "restart" not in recs


def test_recomendaciones_firewall_avisan_de_no_cerrar_ssh(comandos):
    comandos.firewalld_activo(puertos="8080/tcp")
    recs = ghostcheck.auditar_firewall().recomendaciones
    assert any("no cierres el puerto de SSH" in r for r in recs)


# ── Punto 15: estructura ─────────────────────────────────────────────────────

def test_las_comprobaciones_no_imprimen(etc, comandos, capsys):
    passwd(etc)
    comandos.registrar(["getenforce"], stdout="Enforcing")
    ghostcheck.auditar_selinux()
    ghostcheck.auditar_firewall()
    ghostcheck.auditar_usuarios()
    ghostcheck.auditar_ssh()
    ghostcheck.auditar_actualizaciones()
    assert capsys.readouterr() == ("", "")


def test_rutas_como_parametro(tmp_path):
    otro = tmp_path / "otro"
    otro.mkdir()
    (otro / "passwd").write_text("admin:x:0:0::/root:/bin/bash\n")
    (otro / "shadow").write_text("")
    r = ghostcheck.auditar_usuarios(ghostcheck.Rutas(passwd=str(otro / "passwd"), shadow=str(otro / "shadow")))
    assert r.datos["usuarios_uid0_no_root"] == ["admin"]


def test_hostname_se_consulta_una_sola_vez(root, etc, salida, comandos):
    passwd(etc)
    comandos.registrar(["hostname", "-f"], stdout="srv.example.test")
    ghostcheck.main(["-o", str(salida), "-f", "txt,html,json", *SOLO_USUARIOS])
    assert comandos.ejecutados.count(["hostname", "-f"]) == 1


def test_la_fecha_no_se_fija_al_importar():
    assert not hasattr(ghostcheck, "HOY")
    inf = informe()
    assert ghostcheck.nombre_reporte(inf, "txt") == "auditoria_servidor_20260102_030405.txt"


def test_resultado_ok_solo_sin_hallazgos_ni_errores():
    assert resultado("ssh").ok
    assert not resultado("ssh", "ssh_x11_forwarding").ok
    assert not resultado("ssh", errores=("x",)).ok
