"""PLIMSOLL — thin Python wrapper for the Go CLI."""

from plimsoll._types import Seal, Term, Verdict, Check, Disclosure, VerificationReport
from plimsoll._runner import seal, attest, verify
from plimsoll.pytest_plugin import sealed

__all__ = [
    "Seal",
    "Term",
    "Verdict",
    "Check",
    "Disclosure",
    "VerificationReport",
    "seal",
    "attest",
    "verify",
    "sealed",
]

__version__ = "0.1.0"
