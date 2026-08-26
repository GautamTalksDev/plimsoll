"""Tests for the plimsoll Python wrapper (requires PLIMSOLL_BINARY or wheel binary)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
E2E = ROOT / "testdata" / "e2e"


def _have_binary() -> bool:
    if os.environ.get("PLIMSOLL_BINARY"):
        return True
    pkg_bin = Path(__file__).resolve().parents[1] / "plimsoll" / "bin"
    name = "plimsoll.exe" if sys.platform == "win32" else "plimsoll"
    return (pkg_bin / name).is_file()


pytestmark = pytest.mark.skipif(not _have_binary(), reason="plimsoll binary not available")


@pytest.fixture
def plimsoll_binary(tmp_path):
    env_bin = os.environ.get("PLIMSOLL_BINARY")
    if env_bin:
        yield env_bin
        return
    built = tmp_path / "plimsoll"
    subprocess.run(
        ["go", "build", "-o", str(built), "./cmd/plimsoll"],
        cwd=ROOT,
        check=True,
    )
    os.environ["PLIMSOLL_BINARY"] = str(built)
    yield str(built)


def test_seal_and_attest(plimsoll_binary, tmp_path):
    import plimsoll

    work = tmp_path / "work"
    work.mkdir()
    for name in ("prereg.yaml", "dataset.jsonl", "results_pass.json"):
        (work / name).write_bytes((E2E / name).read_bytes())
    key = tmp_path / "key"
    subprocess.run(
        [plimsoll_binary, "seal", "--file", "prereg.yaml", "--key", str(key), "--json"],
        cwd=work,
        check=True,
    )
    seal = plimsoll.seal("prereg.yaml", key_path=str(key), cwd=work)
    assert seal.seal_hash.startswith("sha256:")
    verdict = plimsoll.attest(seal, "results_pass.json", key_path=str(key), cwd=work)
    assert verdict.result == "PASS"
    att = Path(verdict.attestation)
    assert att.is_file()
    doc = json.loads(att.read_text())
    assert doc["verdict"] == "PASS"


def test_sealed_decorator_passes(plimsoll_binary, tmp_path):
    import plimsoll

    work = tmp_path / "work"
    work.mkdir()
    for name in ("prereg.yaml", "dataset.jsonl", "results_pass.json"):
        (work / name).write_bytes((E2E / name).read_bytes())
    key = tmp_path / "key"
    seal = plimsoll.seal("prereg.yaml", key_path=str(key), cwd=work)
    plimsoll.attest(seal, "results_pass.json", key_path=str(key), cwd=work)

    @plimsoll.sealed(str(work / Path(seal.path).name))
    def test_ok():
        assert True

    test_ok()


def test_sealed_decorator_fails_on_fail(plimsoll_binary, tmp_path):
    import plimsoll

    work = tmp_path / "work"
    work.mkdir()
    for name in ("prereg.yaml", "dataset.jsonl", "results_fail.json"):
        (work / name).write_bytes((E2E / name).read_bytes())
    key = tmp_path / "key"
    seal = plimsoll.seal("prereg.yaml", key_path=str(key), cwd=work)
    plimsoll.attest(seal, "results_fail.json", key_path=str(key), cwd=work)

    @plimsoll.sealed(str(work / Path(seal.path).name))
    def test_bad():
        assert True

    from _pytest.outcomes import Failed

    with pytest.raises(Failed):
        import plimsoll.pytest_plugin as plugin

        class Item:
            obj = test_bad

        plugin.pytest_runtest_setup(Item())
