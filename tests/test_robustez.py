"""Punto 3 (codificación y errores de E/S) y punto 4 (sin depender de `which`)."""

from __future__ import annotations

import ghostcheck


def test_passwd_con_bytes_no_utf8_no_aborta(etc):
    (etc / "passwd").write_bytes(
        b"root:x:0:0::/root:/bin/bash\n"
        b"jos\xe9:x:0:0::/home/j:/bin/bash\n"
    )
    r = ghostcheck.auditar_usuarios()
    assert r["total_usuarios"] == 2
    assert len(r["usuarios_uid0_no_root"]) == 1  # el usuario con UID 0 se detecta igual


def test_shadow_con_bytes_no_utf8_no_aborta(etc):
    (etc / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")
    (etc / "shadow").write_bytes(b"root:$6$abc:19000::::::\nm\xfc:::::::\n")
    r = ghostcheck.auditar_usuarios()
    assert len(r["cuentas_sin_contrasena"]) == 1


def test_passwd_que_es_un_directorio_no_aborta(etc):
    (etc / "passwd").mkdir()
    r = ghostcheck.auditar_usuarios()
    assert any("passwd" in a for a in r["advertencias"])


def test_sshd_config_con_bytes_no_utf8_no_aborta(etc):
    (etc / "ssh").mkdir()
    (etc / "ssh" / "sshd_config").write_bytes(b"# caf\xe9\nPermitRootLogin yes\n")
    r = ghostcheck.auditar_ssh()
    assert [h["directiva"] for h in r["directivas_riesgo"]] == ["PermitRootLogin"]


def test_include_que_apunta_a_un_directorio_no_aborta(etc):
    ssh = etc / "ssh"
    (ssh / "sshd_config.d" / "subdir.conf").mkdir(parents=True)
    (ssh / "sshd_config.d" / "10-ok.conf").write_text("X11Forwarding yes\n")
    (ssh / "sshd_config").write_text(f"Include {ssh}/sshd_config.d/*.conf\n")
    r = ghostcheck.auditar_ssh()
    assert [h["directiva"] for h in r["directivas_riesgo"]] == ["X11Forwarding"]


def test_firewall_se_detecta_sin_el_binario_which(comandos):
    comandos.instalar("firewall-cmd")  # "which" NO está instalado
    comandos.registrar(["systemctl", "is-active", "firewalld"], stdout="active")
    comandos.registrar(["firewall-cmd", "--list-ports", "--zone=public"], stdout="")
    comandos.registrar(["firewall-cmd", "--list-services", "--zone=public"], stdout="ssh")
    r = ghostcheck.auditar_firewall()
    assert r["herramienta"] == "firewalld"
    assert r["activo"] is True
    assert all(c[0] != "which" for c in comandos.ejecutados)


def test_ufw_se_detecta_sin_el_binario_which(comandos):
    comandos.registrar(["ufw", "status", "verbose"], stdout="Status: active\n22/tcp ALLOW IN Anywhere\n")
    r = ghostcheck.auditar_firewall()
    assert r["herramienta"] == "ufw"
    assert r["puertos_abiertos"] == ["22"]


def test_sin_gestor_de_firewall():
    r = ghostcheck.auditar_firewall()
    assert r["herramienta"] == "ninguno"


def test_dnf_se_detecta_sin_el_binario_which(comandos):
    comandos.registrar(["dnf", "check-update", "--security"], codigo=0)
    r = ghostcheck.auditar_actualizaciones()
    assert r["estado"] == "ACTUALIZADO"


def test_dnf_no_instalado():
    r = ghostcheck.auditar_actualizaciones()
    assert r["estado"] == "NO_DISPONIBLE"
