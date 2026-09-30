"""Punto 1 (escapado HTML) y punto 2 (escritura segura de reportes)."""

from __future__ import annotations

import os
import stat

import pytest

import ghostcheck

XSS = '<script>alert("x")</script>'


def resultados_maliciosos() -> dict:
    return {
        "selinux": {"estado": XSS, "modo": XSS, "politica": XSS, "advertencias": [XSS], "ok": False},
        "firewall": {"herramienta": XSS, "activo": True, "puertos_abiertos": [XSS],
                     "puertos_a_revisar": [XSS], "advertencias": [XSS]},
        "usuarios": {"usuarios_uid0_no_root": [XSS], "cuentas_sin_contrasena": [XSS],
                     "total_usuarios": 1, "advertencias": [XSS]},
        "ssh": {"ruta_config": XSS, "puerto_ssh": XSS, "ok": False, "advertencias": [XSS],
                "directivas_riesgo": [{"directiva": XSS, "valor": XSS, "linea_num": 1,
                                       "archivo": XSS, "descripcion": XSS}]},
        "actualizaciones": {"gestor": XSS, "estado": XSS, "total_pendientes": 1,
                            "paquetes_pendientes": [XSS], "advertencias": [XSS]},
    }


def test_html_escapa_todos_los_datos_del_sistema(tmp_path, comandos):
    comandos.registrar(["hostname", "-f"], stdout=XSS)
    ruta = ghostcheck.generar_reporte_html(resultados_maliciosos(), str(tmp_path / "r.html"))
    contenido = open(ruta, encoding="utf-8").read()
    assert "<script" not in contenido
    assert "&lt;script&gt;" in contenido


def test_html_incluye_csp_restrictiva(tmp_path):
    ruta = ghostcheck.generar_reporte_html({}, str(tmp_path / "r.html"))
    contenido = open(ruta, encoding="utf-8").read()
    assert "Content-Security-Policy" in contenido
    assert "default-src 'none'" in contenido


def test_html_con_valores_none_no_muestra_none(tmp_path):
    res = {"selinux": {"modo": None, "politica": None, "advertencias": []}}
    ruta = ghostcheck.generar_reporte_html(res, str(tmp_path / "r.html"))
    assert ">None<" not in open(ruta, encoding="utf-8").read()


@pytest.mark.parametrize("generar", [ghostcheck.generar_reporte_txt, ghostcheck.generar_reporte_html])
def test_reportes_se_crean_con_permisos_0600(generar, tmp_path):
    ruta = generar({}, str(tmp_path / "r"))
    assert stat.S_IMODE(os.stat(ruta).st_mode) == 0o600


@pytest.mark.parametrize("generar", [ghostcheck.generar_reporte_txt, ghostcheck.generar_reporte_html])
def test_reportes_no_sobrescriben_ficheros_existentes(generar, tmp_path):
    existente = tmp_path / "r"
    existente.write_text("original")
    generar({}, str(existente))
    assert existente.read_text() == "original"


@pytest.mark.parametrize("generar", [ghostcheck.generar_reporte_txt, ghostcheck.generar_reporte_html])
def test_reportes_no_siguen_enlaces_simbolicos(generar, tmp_path):
    victima = tmp_path / "victima"
    victima.write_text("no tocar")
    enlace = tmp_path / "r"
    enlace.symlink_to(victima)
    generar({}, str(enlace))
    assert victima.read_text() == "no tocar"


def test_escribir_reporte_seguro_lanza_oserror_si_existe(tmp_path):
    ruta = tmp_path / "r"
    ruta.write_text("x")
    with pytest.raises(FileExistsError):
        ghostcheck.escribir_reporte_seguro(str(ruta), "y")
