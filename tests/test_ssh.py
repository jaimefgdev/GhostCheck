"""Punto 5: la auditoría SSH refleja lo que sshd aplica de verdad."""

from __future__ import annotations

import pytest

import ghostcheck


@pytest.fixture
def ssh_dir(etc):
    d = etc / "ssh"
    d.mkdir()
    return d


def riesgos(r: dict) -> dict[str, str]:
    return {h["directiva"]: h["valor"] for h in r.datos["directivas_riesgo"]}


def escribir(ssh_dir, texto: str) -> None:
    (ssh_dir / "sshd_config").write_text(texto)


# ── Análisis de ficheros (sin sshd -T) ────────────────────────────────────────

def test_gana_el_primer_valor_como_en_sshd(ssh_dir):
    escribir(ssh_dir, "PermitRootLogin no\nPermitRootLogin yes\nPasswordAuthentication no\n")
    r = ghostcheck.auditar_ssh()
    assert "PermitRootLogin" not in riesgos(r)
    assert "PermitRootLogin no" in r.datos["directivas_seguras"]


def test_sintaxis_clave_igual_valor(ssh_dir):
    escribir(ssh_dir, "PasswordAuthentication=yes\nPermitEmptyPasswords = yes\n")
    r = ghostcheck.auditar_ssh()
    assert riesgos(r) == {"PasswordAuthentication": "yes", "PermitEmptyPasswords": "yes"}


def test_claves_insensibles_a_mayusculas(ssh_dir):
    escribir(ssh_dir, "permitrootlogin YES\nPasswordAuthentication no\n")
    assert riesgos(ghostcheck.auditar_ssh()) == {"PermitRootLogin": "YES"}


def test_directivas_en_bloque_match_son_condicionales(ssh_dir):
    escribir(ssh_dir, (
        "PasswordAuthentication no\n"
        "Match User bob\n"
        "    X11Forwarding yes\n"
        "    PermitRootLogin yes\n"
    ))
    r = ghostcheck.auditar_ssh()
    assert riesgos(r) == {}
    assert {c["directiva"] for c in r.datos["directivas_condicionales"]} == {"X11Forwarding", "PermitRootLogin"}
    assert set(r.codigos()) == {"ssh_riesgo_condicional"}
    assert ghostcheck.calcular_nivel_riesgo({"ssh": r}) == "MEDIO"


def test_match_all_vuelve_al_contexto_global(ssh_dir):
    escribir(ssh_dir, "Match User bob\n  X11Forwarding no\nMatch all\nPermitRootLogin yes\nPasswordAuthentication no\n")
    assert riesgos(ghostcheck.auditar_ssh()) == {"PermitRootLogin": "yes"}


def test_valor_por_defecto_de_passwordauthentication(ssh_dir):
    escribir(ssh_dir, "PermitRootLogin no\n")
    r = ghostcheck.auditar_ssh()
    assert riesgos(r) == {"PasswordAuthentication": "yes"}
    assert r.datos["directivas_riesgo"][0]["origen"] == "valor por defecto de OpenSSH"


def test_include_relativo_multiple_y_anidado(ssh_dir):
    (ssh_dir / "a.conf").write_text("Include nivel2.conf\n")
    (ssh_dir / "nivel2.conf").write_text("PermitRootLogin yes\n")
    (ssh_dir / "b.conf").write_text("X11Forwarding yes\n")
    escribir(ssh_dir, "Include a.conf b.conf\nPasswordAuthentication no\nPermitRootLogin no\n")
    r = ghostcheck.auditar_ssh()
    assert riesgos(r) == {"PermitRootLogin": "yes", "X11Forwarding": "yes"}
    origen = next(h for h in r.datos["directivas_riesgo"] if h["directiva"] == "PermitRootLogin")
    assert origen["archivo"] == str(ssh_dir / "nivel2.conf")
    assert origen["linea_num"] == 1
    assert origen["origen"] == f"{ssh_dir / 'nivel2.conf'}:1"


def test_include_con_comodin_se_procesa_en_orden_alfabetico(ssh_dir):
    d = ssh_dir / "sshd_config.d"
    d.mkdir()
    (d / "50-b.conf").write_text("PermitRootLogin yes\n")
    (d / "10-a.conf").write_text("PermitRootLogin no\n")
    escribir(ssh_dir, "Include sshd_config.d/*.conf\nPasswordAuthentication no\n")
    assert "PermitRootLogin" not in riesgos(ghostcheck.auditar_ssh())


def test_include_recursivo_no_cuelga(ssh_dir):
    escribir(ssh_dir, "Include sshd_config\nPasswordAuthentication no\n")
    r = ghostcheck.auditar_ssh()
    assert any("anidado" in e for e in r.errores)


def test_match_en_fichero_incluido_no_se_propaga(ssh_dir):
    (ssh_dir / "m.conf").write_text("Match User bob\n  X11Forwarding no\n")
    escribir(ssh_dir, "Include m.conf\nPermitRootLogin yes\nPasswordAuthentication no\n")
    assert riesgos(ghostcheck.auditar_ssh()) == {"PermitRootLogin": "yes"}


def test_varios_puertos(ssh_dir):
    escribir(ssh_dir, "Port 22\nPort 2222\nPasswordAuthentication no\n")
    r = ghostcheck.auditar_ssh()
    assert r.datos["puertos_ssh"] == ["22", "2222"]


def test_sin_sshd_config_no_es_hallazgo_ni_error():
    r = ghostcheck.auditar_ssh()
    assert r.datos["estado"] == "NO_INSTALADO"
    assert r.hallazgos == [] and r.errores == []


# ── Configuración efectiva con sshd -T ────────────────────────────────────────

def sshd_t(comandos, ssh_dir, salida: str) -> None:
    comandos.registrar(["sshd", "-T", "-f", str(ssh_dir / "sshd_config")], stdout=salida)


def test_sshd_T_es_la_fuente_principal(ssh_dir, comandos):
    # El fichero dice "yes" pero sshd -T (la verdad) dice "no"
    escribir(ssh_dir, "PermitRootLogin yes\n")
    sshd_t(comandos, ssh_dir, "port 22\npermitrootlogin no\npasswordauthentication no\n"
                              "permitemptypasswords no\nx11forwarding no\n")
    r = ghostcheck.auditar_ssh()
    assert r.datos["fuente"] == "sshd -T"
    assert riesgos(r) == {}


def test_sshd_T_localiza_fichero_y_linea(ssh_dir, comandos):
    escribir(ssh_dir, "# comentario\nPermitRootLogin yes\n")
    sshd_t(comandos, ssh_dir, "port 22\npermitrootlogin yes\npasswordauthentication no\n")
    h = ghostcheck.auditar_ssh().datos["directivas_riesgo"][0]
    assert h["origen"] == f"{ssh_dir / 'sshd_config'}:2"


def test_sshd_T_valor_implicito(ssh_dir, comandos):
    escribir(ssh_dir, "PermitRootLogin no\n")
    sshd_t(comandos, ssh_dir, "port 22\npermitrootlogin no\npasswordauthentication yes\n")
    h = ghostcheck.auditar_ssh().datos["directivas_riesgo"][0]
    assert h["directiva"] == "PasswordAuthentication"
    assert "sshd -T" in h["origen"]


def test_sshd_T_puertos(ssh_dir, comandos):
    escribir(ssh_dir, "Port 2222\n")
    sshd_t(comandos, ssh_dir, "port 2222\nport 22\npasswordauthentication no\n")
    assert ghostcheck.cargar_config_ssh()["puertos"] == ["2222", "22"]


def test_si_sshd_T_falla_se_usa_el_analisis_de_ficheros(ssh_dir, comandos):
    escribir(ssh_dir, "PermitRootLogin yes\nPasswordAuthentication no\n")
    comandos.registrar(["sshd", "-T", "-f", str(ssh_dir / "sshd_config")],
                       codigo=1, stderr="sshd: no hostkeys available -- exiting.")
    r = ghostcheck.auditar_ssh()
    assert r.datos["fuente"] == "análisis de ficheros"
    assert riesgos(r) == {"PermitRootLogin": "yes"}
