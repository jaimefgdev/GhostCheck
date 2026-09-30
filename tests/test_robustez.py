"""Punto 3 (codificación y errores de E/S) y punto 4 (sin depender de `which`)."""

from __future__ import annotations

import ghostcheck


def test_passwd_con_bytes_no_utf8_no_aborta(etc):
    (etc / "passwd").write_bytes(
        b"root:x:0:0::/root:/bin/bash\n"
        b"jos\xe9:x:0:0::/home/j:/bin/bash\n"
    )
    r = ghostcheck.auditar_usuarios()
    assert r.datos["total_usuarios"] == 2
    assert len(r.datos["usuarios_uid0_no_root"]) == 1  # el usuario con UID 0 se detecta igual


def test_shadow_con_bytes_no_utf8_no_aborta(etc):
    (etc / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")
    (etc / "shadow").write_bytes(b"root:$6$abc:19000::::::\nm\xfc:::::::\n")
    r = ghostcheck.auditar_usuarios()
    assert len(r.datos["cuentas_sin_contrasena"]) == 1


def test_passwd_que_es_un_directorio_no_aborta(etc):
    (etc / "passwd").mkdir()
    r = ghostcheck.auditar_usuarios()
    assert any("passwd" in e for e in r.errores)


def test_sshd_config_con_bytes_no_utf8_no_aborta(etc):
    (etc / "ssh").mkdir()
    (etc / "ssh" / "sshd_config").write_bytes(b"# caf\xe9\nPermitRootLogin yes\n")
    r = ghostcheck.auditar_ssh()
    assert "PermitRootLogin" in [h["directiva"] for h in r.datos["directivas_riesgo"]]


def test_include_que_apunta_a_un_directorio_no_aborta(etc):
    ssh = etc / "ssh"
    (ssh / "sshd_config.d" / "subdir.conf").mkdir(parents=True)
    (ssh / "sshd_config.d" / "10-ok.conf").write_text("X11Forwarding yes\n")
    (ssh / "sshd_config").write_text(f"Include {ssh}/sshd_config.d/*.conf\n")
    r = ghostcheck.auditar_ssh()
    assert "X11Forwarding" in [h["directiva"] for h in r.datos["directivas_riesgo"]]
    assert any("subdir.conf" in e for e in r.errores)


def test_firewall_se_detecta_sin_el_binario_which(comandos):
    comandos.firewalld_activo(servicios="ssh")  # "which" NO está instalado
    r = ghostcheck.auditar_firewall()
    assert r.datos["herramienta"] == "firewalld"
    assert r.datos["activo"] is True
    assert all(c[0] != "which" for c in comandos.ejecutados)


def test_ufw_se_detecta_sin_el_binario_which(comandos):
    comandos.registrar(["ufw", "status", "verbose"], stdout="Status: active\n22/tcp                     ALLOW IN    Anywhere\n")
    r = ghostcheck.auditar_firewall()
    assert r.datos["herramienta"] == "ufw"
    assert r.datos["puertos_abiertos"] == ["22/tcp"]


def test_sin_gestor_de_firewall():
    r = ghostcheck.auditar_firewall()
    assert r.datos["herramienta"] == "ninguno"


def test_dnf_se_detecta_sin_el_binario_which(comandos):
    comandos.registrar(["dnf", "-q", "updateinfo", "list", "--security"], codigo=0)
    r = ghostcheck.auditar_actualizaciones()
    assert r.datos["estado"] == "ACTUALIZADO"


def test_dnf_no_instalado():
    r = ghostcheck.auditar_actualizaciones()
    assert r.datos["estado"] == "NO_DISPONIBLE"
