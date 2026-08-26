"""Locate and invoke the vendored plimsoll binary."""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path


class PlimsollNotFoundError(FileNotFoundError):
    """Raised when no plimsoll binary is available."""


def binary_path() -> Path:
    override = os.environ.get("PLIMSOLL_BINARY")
    if override:
        path = Path(override)
        if path.is_file():
            return path
        raise PlimsollNotFoundError(f"PLIMSOLL_BINARY not found: {override}")

    name = "plimsoll.exe" if sys.platform == "win32" else "plimsoll"
    pkg_bin = Path(__file__).resolve().parent / "bin" / name
    if pkg_bin.is_file():
        return pkg_bin

    found = shutil.which("plimsoll")
    if found:
        return Path(found)

    raise PlimsollNotFoundError(
        "plimsoll binary not found. Install a platform wheel or set PLIMSOLL_BINARY."
    )


def run_json(args: list[str], *, cwd: Path | None = None) -> tuple[dict, int]:
    exe = binary_path()
    if sys.platform != "win32":
        mode = exe.stat().st_mode
        if not mode & stat.S_IXUSR:
            exe.chmod(mode | stat.S_IXUSR)
    proc = subprocess.run(
        [str(exe), *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 3:
        raise RuntimeError(proc.stderr.strip() or "plimsoll operational error")
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError(proc.stderr.strip() or "plimsoll produced no JSON output")
    import json

    payload = stdout
    if not payload.startswith("{"):
        idx = payload.find("{")
        if idx < 0:
            raise RuntimeError(proc.stderr.strip() or "plimsoll produced no JSON output")
        payload = payload[idx:]
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON from plimsoll: {stdout[:200]}") from exc
    return data, proc.returncode


def platform_tag() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        machine = "amd64"
    elif machine in {"aarch64", "arm64"}:
        machine = "arm64"
    if system == "darwin":
        system = "darwin"
    elif system == "linux":
        system = "linux"
    elif system.startswith("win"):
        system = "windows"
        machine = "amd64"
    return f"{system}_{machine}"
