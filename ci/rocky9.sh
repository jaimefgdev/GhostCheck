#!/usr/bin/env bash
# Prueba de integración en un contenedor Rocky Linux 9 (lo usa el CI).
#
#   1. Prepara el contenedor: pip, pytest y openssh-server (para que exista
#      un sshd_config real y `sshd -T` funcione).
#   2. Ejecuta los tests con el Python del sistema (3.9 en RHEL 9).
#   3. Toma una huella (contenido, permisos, propietario y mtime) de /etc,
#      /root, /home, /usr y /var/lib y ejecuta GhostCheck de verdad:
#        - con --offline: la huella debe quedar IDÉNTICA;
#        - online: solo puede cambiar el estado propio de dnf (/var/lib/dnf),
#          que dnf actualiza al consultar los repositorios. /var/cache no
#          forma parte de la huella.
#      En ambos casos se ignora el mtime de /var/lib/rpm/rpmdb.sqlite-shm:
#      es la memoria compartida de SQLite y cambia con cualquier lectura
#      de la base de datos RPM.
#   4. Valida los reportes (permisos 0600 y JSON).
#   5. Construye el RPM (packaging/ghostcheck.spec), lo instala y ejecuta
#      /usr/bin/ghostcheck.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "::group::Preparar contenedor"
dnf -q -y install python3-pip openssh-server diffutils
ssh-keygen -A
python3 --version
python3 -m pip install -q pytest
echo "::endgroup::"

echo "::group::Tests (Python del sistema)"
python3 -m pytest -q
echo "::endgroup::"

huella() {
    find /etc /root /home /usr /var/lib -xdev \( -type f -o -type l -o -type d \) \
        -printf '%p %m %u:%g %s %T@\n' 2>/dev/null | sort
    find /etc -xdev -type f -exec sha256sum {} + 2>/dev/null | sort
}

ejecutar() {   # ejecutar <directorio> [opciones...]
    local dir="$1"; shift
    mkdir -p "$dir"
    local rc=0
    python3 ghostcheck.py -o "$dir" -f txt,html,json --no-color "$@" || rc=$?
    echo "Código de salida: $rc"
    if [ "$rc" -gt 3 ]; then
        echo "ERROR: código de salida inesperado ($rc); 0–3 son niveles de riesgo" >&2
        exit 1
    fi
}

comparar() {   # comparar <antes> <después> [prefijo permitido...]
    python3 - "$@" <<'PY'
import sys
antes, despues, *permitidos = sys.argv[1:]
ignorar = ("/var/lib/rpm/rpmdb.sqlite-shm",)
def lineas(ruta):
    return {l for l in open(ruta) if not l.startswith(ignorar)}
a, b = lineas(antes), lineas(despues)
cambios = [("-", l) for l in sorted(a - b)] + [("+", l) for l in sorted(b - a)]
prohibidos = [(s, l) for s, l in cambios if not any(l.startswith(p) for p in permitidos)]
for s, l in cambios:
    print(f"  {'PERMITIDO' if (s, l) not in prohibidos else 'PROHIBIDO'} {s} {l.rstrip()}")
if prohibidos:
    sys.exit(f"ERROR: GhostCheck ha modificado el sistema ({len(prohibidos)} cambio(s) no permitidos)")
PY
}

SALIDA=$(mktemp -d)

huella > "$SALIDA/h0.txt"
echo "::group::GhostCheck --offline (sin cambios en el sistema)"
ejecutar "$SALIDA/offline" --offline
echo "::endgroup::"
huella > "$SALIDA/h1.txt"
comparar "$SALIDA/h0.txt" "$SALIDA/h1.txt"
echo "OK: --offline no ha modificado nada."

echo "::group::GhostCheck online"
ejecutar "$SALIDA/online"
echo "::endgroup::"
huella > "$SALIDA/h2.txt"
comparar "$SALIDA/h1.txt" "$SALIDA/h2.txt" "/var/lib/dnf"
echo "OK: online solo ha cambiado el estado propio de dnf."

echo "::group::Validar reportes"
python3 - "$SALIDA/online" <<'PY'
import json, os, pathlib, stat, sys

d = pathlib.Path(sys.argv[1])
ficheros = sorted(d.iterdir())
assert sorted(f.suffix for f in ficheros) == [".html", ".json", ".txt"], ficheros
for f in ficheros:
    modo = stat.S_IMODE(os.stat(f).st_mode)
    assert modo == 0o600, (f, oct(modo))

datos = json.loads(next(d.glob("*.json")).read_text())
assert datos["modo"] == "DRY-RUN"
assert datos["como_root"] is True
assert datos["nivel_riesgo"] in ("BAJO", "MEDIO", "ALTO", "CRÍTICO")
assert set(datos["modulos"]) == {"selinux", "firewall", "usuarios", "ssh", "actualizaciones"}
ssh = datos["modulos"]["ssh"]["datos"]
assert ssh["fuente"] == "sshd -T", ssh["fuente"]
print("Nivel de riesgo:", datos["nivel_riesgo"])
print("Auditoría completa:", datos["auditoria_completa"])
for nombre, m in datos["modulos"].items():
    print(f"  {nombre:16} hallazgos={[h['codigo'] for h in m['hallazgos']]} errores={len(m['errores'])}")
PY
echo "::endgroup::"

cat "$SALIDA"/online/*.txt

echo "::group::RPM"
dnf -q -y install rpm-build
rpmbuild -bb --define "_sourcedir $PWD" --define "_rpmdir $SALIDA/rpm" packaging/ghostcheck.spec
rpm -ivh "$SALIDA"/rpm/noarch/ghostcheck-*.noarch.rpm
head -1 /usr/bin/ghostcheck
ghostcheck --version
mkdir -p "$SALIDA/rpm-run"
rc=0; ghostcheck -q --offline -f json -o "$SALIDA/rpm-run" || rc=$?
echo "Código de salida: $rc"
[ "$rc" -le 3 ]
ls -l "$SALIDA/rpm-run"
echo "::endgroup::"
