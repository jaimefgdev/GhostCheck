"""Punto 9: nivel de riesgo coherente y separación hallazgos / errores."""

from __future__ import annotations

import pytest

import ghostcheck


def con(*codigos: str, errores: tuple[str, ...] = ()) -> dict:
    modulo = {"hallazgos": [], "advertencias": [], "errores": list(errores)}
    for c in codigos:
        modulo["hallazgos"].append({"codigo": c, "severidad": ghostcheck.SEVERIDADES[c], "mensaje": c})
        modulo["advertencias"].append(c)
    return modulo


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
    assert ghostcheck._calcular_nivel_riesgo({"ssh": con(*codigos)}) == nivel


def test_nivel_es_el_maximo_entre_modulos():
    res = {"selinux": con("selinux_permissive"), "firewall": con("firewall_inactivo")}
    assert ghostcheck._calcular_nivel_riesgo(res) == "ALTO"


def test_todos_los_codigos_tienen_nivel_valido():
    assert set(ghostcheck.SEVERIDADES.values()) <= set(ghostcheck.NIVELES_RIESGO)


def test_errores_no_suben_el_nivel_pero_marcan_incompleta():
    res = {"actualizaciones": con(errores=("timeout",)), "usuarios": con(errores=("shadow",))}
    assert ghostcheck._calcular_nivel_riesgo(res) == "BAJO"
    assert ghostcheck._comprobaciones_no_realizadas(res) == ["[usuarios] shadow", "[actualizaciones] timeout"]


def test_reporte_txt_indica_auditoria_incompleta(tmp_path):
    res = {"actualizaciones": con(errores=("timeout de dnf",))}
    ruta = ghostcheck.generar_reporte_txt(res, str(tmp_path / "r.txt"))
    texto = open(ruta, encoding="utf-8").read()
    assert "INCOMPLETA" in texto
    assert "No comprobado: timeout de dnf" in texto
    assert "Nivel de riesgo global : BAJO" in texto


def test_reporte_html_indica_auditoria_incompleta(tmp_path):
    res = {"usuarios": con(errores=("sin shadow",))}
    ruta = ghostcheck.generar_reporte_html(res, str(tmp_path / "r.html"))
    texto = open(ruta, encoding="utf-8").read()
    assert "INCOMPLETA" in texto and "No comprobado: sin shadow" in texto
