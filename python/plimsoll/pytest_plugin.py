"""pytest integration for PLIMSOLL sealed evaluations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def sealed(seal_path: str):
    """Decorator: fail the test unless the attestation for seal_path is PASS."""

    def decorator(fn):
        fn.__plimsoll_seal_path__ = seal_path
        return fn

    return decorator


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "plimsoll_sealed(seal_path): require PASS attestation for seal_path",
    )


def _attestation_path(seal_path: Path) -> Path:
    data = json.loads(seal_path.read_text(encoding="utf-8"))
    subject = data["seal"]["seal"]["subject"]["name"].replace(" ", "_")
    return seal_path.parent / f"{subject}.attest.json"


def pytest_runtest_setup(item):
    seal_path = getattr(item.obj, "__plimsoll_seal_path__", None)
    if seal_path is None:
        marker = item.get_closest_marker("plimsoll_sealed")
        if marker and marker.args:
            seal_path = marker.args[0]
    if not seal_path:
        return

    seal_file = Path(seal_path)
    if not seal_file.is_file():
        pytest.fail(f"plimsoll: seal file not found: {seal_file}")

    att_file = _attestation_path(seal_file)
    if not att_file.is_file():
        pytest.fail(
            f"plimsoll: attestation not found: {att_file} (run plimsoll attest first)"
        )

    doc = json.loads(att_file.read_text(encoding="utf-8"))
    verdict = doc.get("verdict", "INVALID")
    if verdict != "PASS":
        pytest.fail(f"plimsoll: attestation verdict is {verdict}, expected PASS")
