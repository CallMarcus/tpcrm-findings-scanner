"""Native, best-effort TLS cipher-suite enumeration and weak-cipher classification.

Uses the offer-all-then-subtract technique on the stdlib ssl module. No third-party
deps, no exploit payloads. The technique and category facts are independently
implemented; no GPLv2 code from testssl.sh is reused.
"""

import socket
import ssl
from typing import Any, Dict, List, Optional

from ..config import ScanConfig


class CipherEnumerator:
    """Enumerate accepted TLS cipher suites and classify weak ones."""

    WEB_TLS_PORTS = (443, 8443)
    ENUMERABLE_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2")

    _TLS_VERSION = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    }

    CATEGORY_SEVERITY = {
        "rc4": "high",
        "export": "high",
        "null-cipher": "high",
        "anonymous": "high",
        "3des-sweet32": "medium",
        "weak-key": "medium",
        "cbc-tls10": "low",
        "no-forward-secrecy": "informational",
    }

    CATEGORY_RATIONALE = {
        "rc4": "RC4 stream cipher is cryptographically broken (CVE-2013-2566, CVE-2015-2808).",
        "export": "Export-grade cipher enables FREAK/LOGJAM downgrade attacks.",
        "null-cipher": "NULL cipher provides no encryption.",
        "anonymous": "Anonymous cipher provides no server authentication (MITM risk).",
        "3des-sweet32": "64-bit block cipher (3DES) is vulnerable to SWEET32 (CVE-2016-2183).",
        "weak-key": "Symmetric key strength is below 128 bits.",
        "cbc-tls10": "CBC cipher under TLS 1.0 is exposed to the BEAST attack.",
        "no-forward-secrecy": "Static key exchange does not provide forward secrecy.",
    }

    _SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}

    def __init__(self, config: ScanConfig):
        self.config = config

    @staticmethod
    def _has_forward_secrecy(upper_name: str) -> bool:
        return any(token in upper_name for token in ("ECDHE", "DHE", "EECDH", "EDH"))

    @staticmethod
    def classify_cipher(name: str, bits: Optional[int], protocol: str) -> List[str]:
        """Return the list of weak-cipher category tags for a negotiated suite."""
        upper = name.upper()
        categories: List[str] = []
        if "RC4" in upper:
            categories.append("rc4")
        # "EXP"/"EXPORT" is OpenSSL's export-grade naming convention
        if "EXP" in upper or "EXPORT" in upper:
            categories.append("export")
        if "NULL" in upper:
            categories.append("null-cipher")
        if "ADH" in upper or "AECDH" in upper or "ANON" in upper:
            categories.append("anonymous")
        # DES-CBC3 is OpenSSL's 3DES alias (e.g. DES-CBC3-SHA)
        if "3DES" in upper or "DES-CBC3" in upper or "DES_CBC3" in upper:
            categories.append("3des-sweet32")
        if isinstance(bits, int) and 0 <= bits < 128:
            categories.append("weak-key")
        if "CBC" in upper and protocol == "TLSv1":
            categories.append("cbc-tls10")
        if protocol != "TLSv1.3" and not CipherEnumerator._has_forward_secrecy(upper):
            categories.append("no-forward-secrecy")
        return categories
