"""Punto 10: actualizaciones de seguridad con dnf updateinfo."""

from __future__ import annotations

import subprocess

import pytest

import ghostcheck

CMD = ["dnf", "-q", "updateinfo", "list", "--security"]

DNF4 = """\
RHSA-2024:3306 Moderate/Sec.  kernel-5.14.0-427.18.1.el9_4.x86_64
RHSA-2024:3306 Moderate/Sec.  kernel-core-5.14.0-427.18.1.el9_4.x86_64
RHSA-2024:4000 Important/Sec. openssl-libs-1:3.0.7-27.el9.x86_64
RHSA-2024:4001 Critical/Sec.  kernel-5.14.0-427.18.1.el9_4.x86_64
"""

DNF5 = """\
Name           Type     Severity  Package                                   Issued
RLSA-2024:3306 security Moderate  kernel-5.14.0-427.18.1.el9_4.x86_64       2024-05-28 23:18:13
FEDORA-2024-a1b2c3 security Low   curl-8.6.0-1.fc40.x86_64                  2024-05-01 00:00:00
"""


def test_formato_dnf4():
    avisos = ghostcheck._parsear_updateinfo(DNF4)
    assert [a["paquete"] for a in avisos] == [
        "kernel-5.14.0-427.18.1.el9_4.x86_64",
        "kernel-core-5.14.0-427.18.1.el9_4.x86_64",
        "openssl-libs-1:3.0.7-27.el9.x86_64",
        "kernel-5.14.0-427.18.1.el9_4.x86_64",
    ]
    assert [a["severidad"] for a in avisos] == ["Moderate", "Moderate", "Important", "Critical"]


def test_formato_dnf5_ignora_cabecera_y_fecha():
    avisos = ghostcheck._parsear_updateinfo(DNF5)
    assert [(a["aviso"], a["severidad"], a["paquete"]) for a in avisos] == [
        ("RLSA-2024:3306", "Moderate", "kernel-5.14.0-427.18.1.el9_4.x86_64"),
        ("FEDORA-2024-a1b2c3", "Low", "curl-8.6.0-1.fc40.x86_64"),
    ]


def test_lineas_ajenas_no_cuentan_como_paquetes():
    salida = "Last metadata expiration check: 0:01:02 ago.\nObsoleting Packages\nfoo.x86_64 1-1 repo\n"
    assert ghostcheck._parsear_updateinfo(salida) == []


def test_pendientes_agrupados_por_paquete(comandos):
    comandos.registrar(CMD, stdout=DNF4)
    r = ghostcheck.auditar_actualizaciones()
    assert r["estado"] == "ACTUALIZACIONES_PENDIENTES"
    assert r["total_pendientes"] == 3
    assert r["severidades"] == {"Moderate": 2, "Important": 1, "Critical": 1}
    assert [h["codigo"] for h in r["hallazgos"]] == ["actualizaciones_seguridad"]


def test_sin_pendientes(comandos):
    comandos.registrar(CMD, stdout="")
    r = ghostcheck.auditar_actualizaciones()
    assert r["estado"] == "ACTUALIZADO" and r["ok"] is True


def test_modo_offline_usa_solo_cache(comandos):
    comandos.registrar(["dnf", "-q", "-C", "updateinfo", "list", "--security"], stdout="")
    r = ghostcheck.auditar_actualizaciones(offline=True)
    assert r["estado"] == "ACTUALIZADO"
    assert comandos.ejecutados == [["dnf", "-q", "-C", "updateinfo", "list", "--security"]]


@pytest.mark.parametrize("respuesta, estado", [
    ({"codigo": 1, "stderr": "Error: Failed to download metadata"}, "ERROR"),
    ({"excepcion": subprocess.TimeoutExpired("dnf", 120)}, "ERROR_TIMEOUT"),
])
def test_errores_de_dnf_no_son_hallazgos(comandos, respuesta, estado):
    comandos.registrar(CMD, **respuesta)
    r = ghostcheck.auditar_actualizaciones()
    assert r["estado"] == estado
    assert r["hallazgos"] == [] and r["errores"]
    assert ghostcheck._calcular_nivel_riesgo({"actualizaciones": r}) == "BAJO"


def test_comandos_se_ejecutan_con_locale_c(comandos):
    comandos.registrar(CMD, stdout="")
    ghostcheck.auditar_actualizaciones()
    env = comandos.kwargs_run[-1]["env"]
    assert env["LC_ALL"] == "C" and env["LANG"] == "C"
