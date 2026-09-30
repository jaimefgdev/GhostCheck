"""Punto 1 (escapado HTML) y punto 2 (escritura segura de reportes)."""

from __future__ import annotations

import json
import os
import stat

import pytest

import ghostcheck
from conftest import informe, resultado

XSS = '<script>alert("x")</script>'


def informe_malicioso() -> ghostcheck.Informe:
    modulos = []
    for nombre in ghostcheck.MODULOS:
        r = resultado(nombre, errores=(XSS,), estado=XSS, modo=XSS, politica=XSS, herramienta=XSS,
                      puertos_abiertos=[XSS], usuarios_uid0_no_root=[XSS], ruta_config=XSS,
                      fuente=XSS, gestor=XSS, paquetes_pendientes=[XSS], severidades={XSS: 1})
        r.hallazgos.append(ghostcheck.Hallazgo("x", "ALTO", XSS))
        r.info.append(XSS)
        r.recomendaciones.append(XSS)
        modulos.append(r)
    return informe(*modulos, hostname=XSS)


def test_html_escapa_todos_los_datos_del_sistema():
    contenido = ghostcheck.renderizar_html(informe_malicioso())
    assert "<script" not in contenido
    assert "&lt;script&gt;" in contenido


def test_html_incluye_csp_restrictiva():
    contenido = ghostcheck.renderizar_html(informe())
    assert "Content-Security-Policy" in contenido
    assert "default-src 'none'" in contenido


def test_valores_none_no_se_muestran_como_none():
    r = resultado("selinux", modo=None, politica=None)
    assert ">None<" not in ghostcheck.renderizar_html(informe(r))
    assert ": None" not in ghostcheck.renderizar_txt(informe(r))


def test_json_es_valido_y_completo():
    datos = json.loads(ghostcheck.renderizar_json(informe(resultado("ssh", "ssh_permit_root_login"))))
    assert datos["nivel_riesgo"] == "CRÍTICO"
    assert datos["modo"] == "DRY-RUN"
    assert datos["modulos"]["ssh"]["hallazgos"][0]["codigo"] == "ssh_permit_root_login"


@pytest.mark.parametrize("formato", ghostcheck.FORMATOS_REPORTE)
def test_reportes_se_crean_con_permisos_0600(formato, tmp_path):
    rutas, errores = ghostcheck.guardar_reportes(informe(), str(tmp_path), [formato])
    assert errores == []
    assert stat.S_IMODE(os.stat(rutas[0]).st_mode) == 0o600


@pytest.mark.parametrize("formato", ghostcheck.FORMATOS_REPORTE)
def test_reportes_no_sobrescriben_ficheros_existentes(formato, tmp_path):
    inf = informe()
    existente = tmp_path / ghostcheck.nombre_reporte(inf, formato)
    existente.write_text("original")
    rutas, errores = ghostcheck.guardar_reportes(inf, str(tmp_path), [formato])
    assert rutas == [] and errores
    assert existente.read_text() == "original"


@pytest.mark.parametrize("formato", ghostcheck.FORMATOS_REPORTE)
def test_reportes_no_siguen_enlaces_simbolicos(formato, tmp_path):
    inf = informe()
    victima = tmp_path / "victima"
    victima.write_text("no tocar")
    (tmp_path / ghostcheck.nombre_reporte(inf, formato)).symlink_to(victima)
    _, errores = ghostcheck.guardar_reportes(inf, str(tmp_path), [formato])
    assert errores
    assert victima.read_text() == "no tocar"


def test_escribir_reporte_seguro_lanza_oserror_si_existe(tmp_path):
    ruta = tmp_path / "r"
    ruta.write_text("x")
    with pytest.raises(FileExistsError):
        ghostcheck.escribir_reporte_seguro(str(ruta), "y")
