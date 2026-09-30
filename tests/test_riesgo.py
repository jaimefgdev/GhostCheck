"""Punto 9: nivel de riesgo coherente y separación hallazgos / errores."""

from __future__ import annotations

import pytest

import ghostcheck
from conftest import informe, resultado


def con(*codigos: str, errores: tuple[str, ...] = (), nombre: str = "ssh") -> ghostcheck.ResultadoModulo:
    return resultado(nombre, *codigos, errores=errores)


@pytest.mark.parametrize("codigos, nivel", [
    ((), "BAJO"),
    (("puertos_no_esenciales",), "MEDIO"),
    (("puertos_no_esenciales", "selinux_permissive", "ssh_x11_forwarding",
      "firewall_reglas_a_revisar", "selinux_no_disponible"), "MEDIO"),  # muchos MEDIO siguen siendo MEDIO
    (("selinux_deshabilitado",), "ALTO"),
    (("firewall_inactivo",), "ALTO"),
    (("actualizaciones_seguridad",), "ALTO"),
    (("ssh_password_authentication",), "ALTO"),
    (("ssh_permit_root_login",), "CRÍTICO"),
    (("usuario_uid0_no_root", "puertos_no_esenciales"), "CRÍTICO"),
])
def test_tabla_de_severidades(codigos, nivel):
    assert ghostcheck.calcular_nivel_riesgo({"ssh": con(*codigos)}) == nivel


def test_nivel_es_el_maximo_entre_modulos():
    res = {"selinux": con("selinux_permissive", nombre="selinux"),
           "firewall": con("firewall_inactivo", nombre="firewall")}
    assert ghostcheck.calcular_nivel_riesgo(res) == "ALTO"


def test_todos_los_codigos_tienen_nivel_valido():
    assert set(ghostcheck.SEVERIDADES.values()) <= set(ghostcheck.NIVELES_RIESGO)


def test_errores_no_suben_el_nivel_pero_marcan_incompleta():
    res = {"usuarios": con(errores=("shadow",), nombre="usuarios"),
           "actualizaciones": con(errores=("timeout",), nombre="actualizaciones")}
    assert ghostcheck.calcular_nivel_riesgo(res) == "BAJO"
    assert ghostcheck.comprobaciones_no_realizadas(res) == ["[usuarios] shadow", "[actualizaciones] timeout"]


def test_reporte_txt_indica_auditoria_incompleta():
    texto = ghostcheck.renderizar_txt(informe(con(errores=("timeout de dnf",), nombre="actualizaciones")))
    assert "INCOMPLETA" in texto
    assert "No comprobado: timeout de dnf" in texto
    assert "Nivel de riesgo global : BAJO" in texto


def test_reporte_html_indica_auditoria_incompleta():
    texto = ghostcheck.renderizar_html(informe(con(errores=("sin shadow",), nombre="usuarios")))
    assert "INCOMPLETA" in texto and "No comprobado: sin shadow" in texto


def test_sin_root_la_auditoria_es_incompleta():
    inf = informe(con(), como_root=False)
    assert not inf.completa
    assert "sin privilegios" in inf.no_realizadas[0]
