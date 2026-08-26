"""Data objects mirroring plimsoll CLI JSON output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Seal:
    seal_hash: str
    path: str
    published: bool


@dataclass
class Term:
    label: str = ""
    identifier: str = ""
    value: str = ""
    comparator: str = ""
    literal: str = ""
    outcome: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Term:
        return cls(
            label=d.get("label", ""),
            identifier=d.get("identifier", ""),
            value=d.get("value", ""),
            comparator=d.get("comparator", ""),
            literal=d.get("literal", ""),
            outcome=bool(d.get("outcome")),
        )


@dataclass
class Verdict:
    result: str
    exit_code: int
    attestation: str
    expression: str
    terms: list[Term] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    attempt_no: int | None = None
    previous_verdicts: list[str] = field(default_factory=list)
    published: bool = False

    @property
    def verdict(self) -> str:
        return self.result


@dataclass
class Check:
    id: str
    pass_: bool
    reason: str


@dataclass
class Disclosure:
    attempt_no: int
    total_attempts: int
    attempts: list[dict[str, Any]]
    supersedes: str = ""
    supersede_reason: str = ""


@dataclass
class VerificationReport:
    verdict: str
    checks: list[Check]
    disclosure: Disclosure | None = None
    exit_code: int = 0

    @property
    def verified(self) -> bool:
        return self.verdict in {"VERIFIED", "VERIFIED WITH DISCLOSURES"}
