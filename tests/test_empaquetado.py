"""Punto 19: coherencia del empaquetado."""

from __future__ import annotations

import os
import re
from pathlib import Path

import ghostcheck

RAIZ = Path(__file__).resolve().parent.parent


def test_version_del_spec_coincide_con_el_script():
    spec = (RAIZ / "packaging" / "ghostcheck.spec").read_text()
    assert re.search(r"^Version:\s*(\S+)$", spec, re.M).group(1) == ghostcheck.__version__


def test_version_del_changelog_del_spec():
    spec = (RAIZ / "packaging" / "ghostcheck.spec").read_text()
    entrada = spec.split("%changelog", 1)[1].strip().splitlines()[0]
    assert entrada.endswith(f"- {ghostcheck.__version__}-1")


def test_pyproject_define_el_comando_ghostcheck():
    pyproject = (RAIZ / "pyproject.toml").read_text()
    assert 'ghostcheck = "ghostcheck:main"' in pyproject
    assert 'requires-python = ">=3.9"' in pyproject


def test_script_ejecutable_con_shebang():
    script = RAIZ / "ghostcheck.py"
    assert script.read_text().startswith("#!/usr/bin/env python3\n")
    assert os.access(script, os.X_OK)
