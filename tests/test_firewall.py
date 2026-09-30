"""Punto 6: auditoría de firewalld y UFW."""

from __future__ import annotations

import ghostcheck


# ── firewalld ─────────────────────────────────────────────────────────────────

def test_servicio_cockpit_se_resuelve_con_info_service(comandos):
    comandos.firewalld_activo(servicios="cockpit dhcpv6-client ssh")
    comandos.registrar(["firewall-cmd", "--info-service=cockpit"], stdout="cockpit\n  ports: 9090/tcp\n  protocols:")
    comandos.registrar(["firewall-cmd", "--info-service=dhcpv6-client"], stdout="dhcpv6-client\n  ports: 546/udp")
    comandos.registrar(["firewall-cmd", "--info-service=ssh"], stdout="ssh\n  ports: 22/tcp")
    r = ghostcheck.auditar_firewall()
    assert r.datos["puertos_abiertos"] == ["22/tcp", "546/udp", "9090/tcp"]
    assert r.datos["puertos_a_revisar"] == ["546/udp", "9090/tcp"]
    assert set(r.codigos()) == {"puertos_no_esenciales"}


def test_servicio_se_resuelve_con_mapa_si_info_service_falla(comandos):
    comandos.firewalld_activo(servicios="cockpit")
    r = ghostcheck.auditar_firewall()  # --info-service no registrado → falla
    assert r.datos["puertos_abiertos"] == ["9090/tcp"]


def test_servicio_desconocido_sin_resolver_se_marca_para_revision(comandos):
    comandos.firewalld_activo(servicios="raro")
    r = ghostcheck.auditar_firewall()
    assert r.codigos() == ["firewall_reglas_a_revisar"]


def test_se_auditan_todas_las_zonas_activas(comandos):
    comandos.firewalld_activo(zona="public", puertos="443/tcp",
                              zonas_activas="public\n  interfaces: eth0\ninternal\n  sources: 10.0.0.0/8")
    for tipo, valor in (("ports", "5432/tcp"), ("services", ""), ("rich-rules", ""), ("forward-ports", "")):
        comandos.registrar(["firewall-cmd", f"--list-{tipo}", "--zone=internal"], stdout=valor)
    r = ghostcheck.auditar_firewall()
    assert r.datos["zonas"] == ["public", "internal"]
    assert r.datos["puertos_a_revisar"] == ["5432/tcp"]


def test_se_conservan_protocolo_y_rangos(comandos):
    comandos.firewalld_activo(puertos="8000-8100/tcp 53/udp 443/tcp")
    r = ghostcheck.auditar_firewall()
    assert r.datos["puertos_abiertos"] == ["443/tcp", "53/udp", "8000-8100/tcp"]
    assert r.datos["puertos_a_revisar"] == ["53/udp", "8000-8100/tcp"]


def test_puerto_esencial_en_udp_se_revisa(comandos):
    comandos.firewalld_activo(puertos="443/udp")
    assert ghostcheck.auditar_firewall().datos["puertos_a_revisar"] == ["443/udp"]


def test_puerto_ssh_no_estandar_es_esencial(comandos):
    comandos.firewalld_activo(puertos="2222/tcp")
    assert ghostcheck.auditar_firewall(puertos_ssh=["2222"]).datos["puertos_a_revisar"] == []


def test_recomendaciones_usan_la_orden_correcta(comandos):
    comandos.firewalld_activo(puertos="8080/tcp", servicios="cockpit")
    salida = "\n".join(ghostcheck.auditar_firewall().recomendaciones)
    assert "firewall-cmd --permanent --zone=public --remove-port=8080/tcp" in salida
    assert "firewall-cmd --permanent --zone=public --remove-service=cockpit" in salida
    assert "--remove-port=9090" not in salida
    assert "firewall-cmd --reload" in salida


def test_rich_rules_y_forward_ports_se_marcan(comandos):
    comandos.firewalld_activo(rich='rule family="ipv4" source address="1.2.3.4" accept',
                              forward="port=80:proto=tcp:toport=8080:toaddr=")
    r = ghostcheck.auditar_firewall()
    assert r.codigos() == ["firewall_reglas_a_revisar"] * 2


def test_firewalld_inactivo(comandos):
    comandos.instalar("firewall-cmd")
    comandos.registrar(["systemctl", "is-active", "firewalld"], codigo=3, stdout="inactive")
    r = ghostcheck.auditar_firewall()
    assert r.codigos() == ["firewall_inactivo"]
    assert ghostcheck.calcular_nivel_riesgo({"firewall": r}) == "ALTO"


def test_zonas_no_disponibles_es_error_y_usa_public(comandos):
    comandos.registrar(["systemctl", "is-active", "firewalld"], stdout="active")
    for tipo in ("ports", "services", "rich-rules", "forward-ports"):
        comandos.registrar(["firewall-cmd", f"--list-{tipo}", "--zone=public"], stdout="")
    r = ghostcheck.auditar_firewall()
    assert r.datos["zonas"] == ["public"]
    assert r.errores


# ── UFW ───────────────────────────────────────────────────────────────────────

UFW = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
{reglas}
"""


def ufw(comandos, *reglas: str) -> dict:
    comandos.registrar(["ufw", "status", "verbose"], stdout=UFW.format(reglas="\n".join(reglas)))
    return ghostcheck.auditar_firewall()


def test_ufw_regla_por_ip_origen_no_es_un_puerto(comandos):
    r = ufw(comandos, "Anywhere                   ALLOW IN    10.0.0.5")
    assert r.datos["puertos_abiertos"] == []
    assert r.codigos() == ["firewall_reglas_a_revisar"]
    assert "10.0.0.5" in r.advertencias[0]


def test_ufw_rangos_listas_y_v6(comandos):
    r = ufw(comandos,
            "6000:6007/tcp              ALLOW IN    Anywhere",
            "80,443/tcp                 ALLOW IN    Anywhere",
            "22/tcp (v6)                ALLOW IN    Anywhere (v6)")
    assert r.datos["puertos_abiertos"] == ["22/tcp", "443/tcp", "6000-6007/tcp", "80/tcp"]
    assert r.datos["puertos_a_revisar"] == ["6000-6007/tcp"]


def test_ufw_ignora_reglas_de_salida_y_deny(comandos):
    r = ufw(comandos,
            "8080/tcp                   DENY IN     Anywhere",
            "53                         ALLOW OUT   Anywhere",
            "22/tcp                     LIMIT IN    Anywhere")
    assert r.datos["puertos_abiertos"] == ["22/tcp"]


def test_ufw_perfil_resuelto_con_app_info(comandos):
    comandos.registrar(["ufw", "app", "info", "Nginx Full"],
                       stdout="Profile: Nginx Full\nTitle: Web Server\n\nPorts:\n  80,443/tcp\n")
    r = ufw(comandos, "Nginx Full                 ALLOW IN    Anywhere")
    assert r.datos["puertos_abiertos"] == ["443/tcp", "80/tcp"]


def test_ufw_perfil_con_mapa_de_respaldo(comandos):
    r = ufw(comandos, "OpenSSH                    ALLOW IN    Anywhere")
    assert r.datos["puertos_abiertos"] == ["22/tcp"]


def test_ufw_interfaz(comandos):
    r = ufw(comandos, "8080/tcp on eth0           ALLOW IN    Anywhere")
    assert r.datos["puertos_abiertos"] == ["8080/tcp"]


def test_ufw_inactivo(comandos):
    comandos.registrar(["ufw", "status", "verbose"], stdout="Status: inactive")
    r = ghostcheck.auditar_firewall()
    assert r.codigos() == ["firewall_inactivo"]
