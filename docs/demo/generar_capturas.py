"""
Genera las capturas del README (docs/terminal.png y docs/informe.png).

    python docs/demo/generar_capturas.py

Ejecuta ghostcheck.main() contra un servidor SIMULADO: los ficheros de /etc
viven en un directorio temporal y cada comando del sistema devuelve una
respuesta fija de esta lista. Cualquier comando que no esté aquí o que no sea
de solo lectura para ghostcheck detiene el script. No se ejecuta nada real.

Las capturas se hacen con Chrome/Chromium en modo headless (variable CHROME
para indicar la ruta si no se encuentra solo).
"""

from __future__ import annotations

import html
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ))

import ghostcheck  # noqa: E402

HOST = "srv-web01.example.com"

PASSWD = """\
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
jaime:x:1000:1000:Jaime:/home/jaime:/bin/bash
backup:x:1001:1001:Copias:/home/backup:/bin/bash
"""
SHADOW = """\
root:$6$abc$hash:19800:0:99999:7:::
bin:*:19800:0:99999:7:::
jaime:$6$def$hash:19800:0:99999:7:::
backup::19800:0:99999:7:::
"""
SSHD_CONFIG = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nX11Forwarding yes\n"
SSHD_T = ("port 22\npermitrootlogin no\npasswordauthentication yes\n"
          "permitemptypasswords no\nx11forwarding yes\n")
DNF = """\
RHSA-2024:3306 Moderate/Sec.  kernel-5.14.0-427.18.1.el9_4.x86_64
RHSA-2024:4000 Important/Sec. openssl-libs-1:3.0.7-27.el9.x86_64
RHSA-2024:4001 Critical/Sec.  kernel-core-5.14.0-427.18.1.el9_4.x86_64
"""


def respuestas(sshd_config: str) -> dict[tuple[str, ...], tuple[int, str]]:
    r: dict[tuple[str, ...], tuple[int, str]] = {
        ("getenforce",): (0, "Enforcing"),
        ("sestatus",): (0, "SELinux status:                 enabled\n"
                           "Loaded policy name:             targeted\n"
                           "Current mode:                   enforcing"),
        ("systemctl", "is-active", "firewalld"): (0, "active"),
        ("firewall-cmd", "--get-default-zone"): (0, "public"),
        ("firewall-cmd", "--get-active-zones"): (0, "public\n  interfaces: eth0"),
        ("firewall-cmd", "--list-ports", "--zone=public"): (0, "8080/tcp"),
        ("firewall-cmd", "--list-services", "--zone=public"): (0, "cockpit dhcpv6-client ssh"),
        ("firewall-cmd", "--list-rich-rules", "--zone=public"): (0, ""),
        ("firewall-cmd", "--list-forward-ports", "--zone=public"): (0, ""),
        ("firewall-cmd", "--info-service=cockpit"): (0, "cockpit\n  ports: 9090/tcp"),
        ("firewall-cmd", "--info-service=dhcpv6-client"): (0, "dhcpv6-client\n  ports: 546/udp"),
        ("firewall-cmd", "--info-service=ssh"): (0, "ssh\n  ports: 22/tcp"),
        ("sshd", "-T", "-f", sshd_config): (0, SSHD_T),
        ("dnf", "-q", "-C", "updateinfo", "list", "--security"): (0, DNF),
        ("hostname", "-f"): (0, HOST),
    }
    return r


class SistemaSimulado:
    def __init__(self, tabla: dict[tuple[str, ...], tuple[int, str]]) -> None:
        self.tabla = tabla
        self.binarios = {c[0] for c in tabla}

    def which(self, nombre: str, *_, **__) -> str | None:
        return f"/usr/bin/{nombre}" if nombre in self.binarios else None

    def run(self, comando, *_, **__):
        comando = tuple(comando)
        if not ghostcheck.comando_permitido(list(comando)):
            raise SystemExit(f"Comando no permitido en la demo: {comando}")
        if comando not in self.tabla:
            raise FileNotFoundError(2, "No such file or directory", comando[0])
        codigo, salida = self.tabla[comando]
        return subprocess.CompletedProcess(list(comando), codigo, salida, "")


class TerminalSimulada(io.StringIO):
    def isatty(self) -> bool:  # colores ANSI, como en una terminal real
        return True


ANSI = {"1": "font-weight:700", "31": "color:#ff5f5f", "91": "color:#ff5f5f",
        "32": "color:#5fd75f", "92": "color:#5fd75f", "33": "color:#ffd75f",
        "93": "color:#ffd75f", "35": "color:#d787ff", "95": "color:#d787ff",
        "36": "color:#5fd7ff", "96": "color:#5fd7ff"}


def ansi_a_html(texto: str) -> str:
    partes, abiertas = [], 0
    for trozo in re.split(r"(\x1b\[[0-9;]*m)", texto):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", trozo)
        if not m:
            partes.append(html.escape(trozo))
            continue
        codigos = [c for c in m.group(1).split(";") if c]
        if not codigos or codigos == ["0"]:
            partes.append("</span>" * abiertas)
            abiertas = 0
            continue
        estilo = ";".join(ANSI[c] for c in codigos if c in ANSI)
        partes.append(f'<span style="{estilo}">')
        abiertas += 1
    partes.append("</span>" * abiertas)
    cuerpo = "".join(partes)
    return ("<!doctype html><meta charset='utf-8'><style>body{margin:0;background:#1e2127}"
            "pre{margin:0;padding:22px 26px;color:#d7dae0;font:15px/1.45 'DejaVu Sans Mono',"
            "Consolas,monospace}</style><pre>" + cuerpo + "</pre>")


def buscar_chrome() -> str:
    candidatos = [os.environ.get("CHROME", ""), "chromium", "chromium-browser", "google-chrome",
                  r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    for c in candidatos:
        if c and (shutil.which(c) or Path(c).exists()):
            return shutil.which(c) or c
    raise SystemExit("No encuentro Chrome/Chromium: indica la ruta con la variable CHROME.")


def capturar(chrome: str, pagina: Path, destino: Path, alto: int, ancho: int = 1100) -> None:
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    f"--screenshot={destino}", f"--window-size={ancho},{alto}",
                    "--force-device-scale-factor=2", pagina.resolve().as_uri()],
                   check=True, capture_output=True, timeout=60)


def main() -> None:
    reales = (subprocess.run, shutil.which, os.path.exists)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        etc = tmp_p / "etc"
        (etc / "ssh").mkdir(parents=True)
        (etc / "selinux").mkdir()
        (etc / "passwd").write_text(PASSWD, encoding="utf-8")
        (etc / "shadow").write_text(SHADOW, encoding="utf-8")
        (etc / "ssh" / "sshd_config").write_text(SSHD_CONFIG, encoding="utf-8")
        (etc / "selinux" / "config").write_text("SELINUX=enforcing\n", encoding="utf-8")
        # La demo usa las rutas de un servidor real; solo la LECTURA de esos
        # ficheros se redirige a las copias de prueba del directorio temporal.
        mapa = {"/etc/passwd": etc / "passwd", "/etc/shadow": etc / "shadow",
                "/etc/ssh/sshd_config": etc / "ssh" / "sshd_config",
                "/etc/selinux/config": etc / "selinux" / "config"}
        rutas = ghostcheck.Rutas(passwd="/etc/passwd", shadow="/etc/shadow",
                                 sshd_config="/etc/ssh/sshd_config",
                                 selinux_config="/etc/selinux/config")
        sistema = SistemaSimulado(respuestas(rutas.sshd_config))
        leer_real, existe_real, spinner_real = ghostcheck._leer_lineas, os.path.exists, ghostcheck.Spinner

        ghostcheck.RUTAS = rutas
        ghostcheck._leer_lineas = lambda ruta: leer_real(str(mapa.get(ruta, ruta)))
        ghostcheck.subprocess.run = sistema.run
        ghostcheck.shutil.which = sistema.which
        ghostcheck.os.path.exists = lambda ruta: existe_real(str(mapa.get(ruta, ruta)))
        ghostcheck.socket.gethostname = lambda: HOST
        ghostcheck.es_root = lambda: True
        # Sin animación de carga: en una captura fija solo dejaría restos.
        ghostcheck.Spinner = lambda mensaje, salida, activo=True: spinner_real(mensaje, salida, activo=False)
        salida_dir = tmp_p / "reportes"
        salida_dir.mkdir()
        terminal = TerminalSimulada()
        salida_real, sys.stdout = sys.stdout, terminal
        try:
            codigo = ghostcheck.main(["-o", str(salida_dir), "-f", "html", "--offline"])
        finally:
            sys.stdout = salida_real
            subprocess.run, shutil.which, os.path.exists = reales  # la captura usa lo real
            ghostcheck._leer_lineas, ghostcheck.Spinner = leer_real, spinner_real

        # Las rutas del directorio temporal se muestran como en el servidor.
        texto = terminal.getvalue().replace(str(salida_dir) + os.sep, "/root/")
        informe = next(salida_dir.glob("*.html"))
        (tmp_p / "terminal.html").write_text(ansi_a_html(texto), encoding="utf-8")

        chrome = buscar_chrome()
        docs = RAIZ / "docs"
        capturar(chrome, tmp_p / "terminal.html", docs / "terminal.png", 1560, ancho=1500)
        capturar(chrome, informe, docs / "informe.png", 1500)
        print(f"Nivel de riesgo de la demo: código {codigo}. Capturas en docs/terminal.png y docs/informe.png")


if __name__ == "__main__":
    main()
