"""High-level API delegating to the plimsoll CLI."""

from __future__ import annotations

from pathlib import Path

from plimsoll._binary import run_json
from plimsoll._types import Seal, Verdict, VerificationReport, Term, Check, Disclosure


def seal(
    prereg_path: str | Path,
    *,
    publish: bool = False,
    key_path: str | None = None,
    log_path: str | None = None,
    log_url: str | None = None,
    cwd: str | Path | None = None,
) -> Seal:
    args = ["seal", "--file", str(prereg_path), "--json"]
    if publish:
        args.append("--publish")
    if key_path:
        args.extend(["--key", key_path])
    if log_path:
        args.extend(["--log", log_path])
    if log_url:
        args.extend(["--log-url", log_url])
    data, _ = run_json(args, cwd=Path(cwd) if cwd else None)
    return Seal(
        seal_hash=data["seal_hash"],
        path=data["path"],
        published=bool(data.get("published")),
    )


def attest(
    seal_obj: Seal | str | Path,
    results_path: str | Path,
    *,
    publish: bool = False,
    key_path: str | None = None,
    log_path: str | None = None,
    log_url: str | None = None,
    harness: str | None = None,
    cwd: str | Path | None = None,
) -> Verdict:
    seal_path = seal_obj.path if isinstance(seal_obj, Seal) else str(seal_obj)
    args = ["attest", "--seal", seal_path, "--results", str(results_path), "--json"]
    if publish:
        args.append("--publish")
    if key_path:
        args.extend(["--key", key_path])
    if log_path:
        args.extend(["--log", log_path])
    if log_url:
        args.extend(["--log-url", log_url])
    if harness:
        args.extend(["--harness", harness])
    data, exit_code = run_json(args, cwd=Path(cwd) if cwd else None)
    terms = [Term.from_dict(t) for t in data.get("terms") or []]
    return Verdict(
        result=data.get("verdict", "INVALID"),
        exit_code=int(data.get("exit_code", exit_code)),
        attestation=data.get("attestation", ""),
        expression=data.get("expression", ""),
        terms=terms,
        reasons=list(data.get("reasons") or []),
        attempt_no=data.get("attempt_no"),
        previous_verdicts=list(data.get("previous_verdicts") or []),
        published=bool(data.get("published")),
    )


def verify(
    attestation_path: str | Path,
    *,
    offline: bool = False,
    bundle_path: str | None = None,
    log_url: str | None = None,
    cwd: str | Path | None = None,
) -> VerificationReport:
    args = ["verify", str(attestation_path), "--json"]
    if offline:
        args.append("--offline")
    if bundle_path:
        args.extend(["--bundle", bundle_path])
    if log_url:
        args.extend(["--log", log_url])
    data, exit_code = run_json(args, cwd=Path(cwd) if cwd else None)
    checks = [Check(id=c["id"], pass_=c["pass"], reason=c["reason"]) for c in data.get("checks") or []]
    disc = data.get("disclosure")
    disclosure = None
    if disc:
        disclosure = Disclosure(
            attempt_no=int(disc.get("attempt_no", 0)),
            total_attempts=int(disc.get("total_attempts", 0)),
            attempts=[
                {"attempt_no": a["attempt_no"], "verdict": a["verdict"]}
                for a in disc.get("attempts") or []
            ],
            supersedes=disc.get("supersedes") or "",
            supersede_reason=disc.get("supersede_reason") or "",
        )
    return VerificationReport(
        verdict=data.get("verdict", "NOT VERIFIED"),
        checks=checks,
        disclosure=disclosure,
        exit_code=exit_code,
    )
