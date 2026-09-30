"""Puntos 7 (usuarios) y 8 (SELinux)."""

from __future__ import annotations

import pytest

import ghostcheck


# ── Usuarios ──────────────────────────────────────────────────────────────────

def test_campo_vacio_en_passwd_es_cuenta_sin_contrasena(etc):
    (etc / "passwd").write_text("root:x:0:0::/root:/bin/bash\nnopw::1001:1001::/home/n:/bin/bash\n")
    (etc / "shadow").write_text("root:$6$x:19000::::::\n")
    r = ghostcheck.auditar_usuarios()
    assert r["cuentas_sin_contrasena"] == ["nopw"]
    assert r["hallazgos"][0]["severidad"] == "CRÍTICO"


def test_cuenta_vacia_en_passwd_y_shadow_se_cuenta_una_vez(etc):
    (etc / "passwd").write_text("nopw::1001:1001::/home/n:/bin/bash\n")
    (etc / "shadow").write_text("nopw::19000::::::\n")
    r = ghostcheck.auditar_usuarios()
    assert r["cuentas_sin_contrasena"] == ["nopw"]
    assert len(r["hallazgos"]) == 1


def test_cuentas_bloqueadas_no_son_hallazgo(etc):
    (etc / "passwd").write_text("a:x:1:1::/:/sbin/nologin\nb:*:2:2::/:/sbin/nologin\n")
    (etc / "shadow").write_text("a:!!:19000::::::\nb:*:19000::::::\n")
    r = ghostcheck.auditar_usuarios()
    assert r["hallazgos"] == [] and r["ok"] is True


def test_shadow_ilegible_no_da_ok(etc):
    (etc / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")
    r = ghostcheck.auditar_usuarios()  # shadow no existe
    assert r["ok"] is False
    assert r["hallazgos"] == []
    assert any("shadow" in e for e in r["errores"])


# ── SELinux ───────────────────────────────────────────────────────────────────

@pytest.fixture
def selinux_cfg(etc):
    (etc / "selinux").mkdir()

    def escribir(modo: str) -> None:
        (etc / "selinux" / "config").write_text(
            f"# comentario\nSELINUX={modo}\nSELINUXTYPE=targeted\n"
        )
    return escribir


def test_politica_desconocida_no_muestra_none(comandos, capsys):
    comandos.registrar(["getenforce"], stdout="Enforcing")
    comandos.registrar(["sestatus"], codigo=1)
    r = ghostcheck.auditar_selinux()
    assert r["politica"] is None
    assert "None" not in capsys.readouterr().out


def test_enforcing_persistente(comandos, selinux_cfg):
    selinux_cfg("enforcing")
    comandos.registrar(["getenforce"], stdout="Enforcing")
    comandos.registrar(["sestatus"], stdout="Loaded policy name:             targeted")
    r = ghostcheck.auditar_selinux()
    assert r["ok"] is True and r["politica"] == "targeted"
    assert r["modo_persistente"] == "enforcing"


def test_enforcing_no_persistente(comandos, selinux_cfg):
    selinux_cfg("permissive")
    comandos.registrar(["getenforce"], stdout="Enforcing")
    r = ghostcheck.auditar_selinux()
    assert [h["codigo"] for h in r["hallazgos"]] == ["selinux_no_persistente"]


def test_selinuxtype_no_se_confunde_con_selinux(comandos, etc):
    (etc / "selinux").mkdir()
    (etc / "selinux" / "config").write_text("SELINUXTYPE=targeted\nSELINUX=enforcing\n")
    comandos.registrar(["getenforce"], stdout="Enforcing")
    assert ghostcheck.auditar_selinux()["modo_persistente"] == "enforcing"


@pytest.mark.parametrize("modo, codigo, nivel", [
    ("Permissive", "selinux_permissive", "MEDIO"),
    ("Disabled", "selinux_deshabilitado", "ALTO"),
])
def test_modos_inseguros(comandos, modo, codigo, nivel):
    comandos.registrar(["getenforce"], stdout=modo)
    r = ghostcheck.auditar_selinux()
    assert [h["codigo"] for h in r["hallazgos"]] == [codigo]
    assert ghostcheck._calcular_nivel_riesgo({"selinux": r}) == nivel


def test_getenforce_con_error_es_comprobacion_no_realizada(comandos):
    comandos.registrar(["getenforce"], codigo=1, stderr="boom")
    r = ghostcheck.auditar_selinux()
    assert r["hallazgos"] == [] and r["errores"]


def test_selinux_no_disponible_es_hallazgo():
    r = ghostcheck.auditar_selinux()  # getenforce no instalado
    assert [h["codigo"] for h in r["hallazgos"]] == ["selinux_no_disponible"]
