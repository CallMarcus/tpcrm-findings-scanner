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

    def enumerate_target(
        self,
        ip: str,
        open_ports: Optional[List[int]] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enumerate ciphers on whichever of WEB_TLS_PORTS are open; aggregate findings."""
        open_ports = open_ports or []
        ports_to_test = [p for p in self.WEB_TLS_PORTS if p in open_ports]

        result: Dict[str, Any] = {
            "scanner_openssl": ssl.OPENSSL_VERSION,
            "ports": {},
            "weak_findings": [],
            "summary": {},
        }

        accepted_total = 0
        categories: List[str] = []
        tested: List[int] = []
        for port in ports_to_test:
            port_result = self.enumerate_port(ip, port, server_name)
            result["ports"][str(port)] = port_result
            tested.append(port)
            accepted_total += port_result.get("summary", {}).get("accepted_total", 0)
            for finding in port_result.get("weak_findings", []):
                tagged = dict(finding)
                tagged["port"] = port
                result["weak_findings"].append(tagged)
                categories.append(finding["category"])

        unique_categories = list(dict.fromkeys(categories))

        result["summary"] = {
            "ports_tested": tested,
            "accepted_total": accepted_total,
            "weak_count": len(result["weak_findings"]),
            "categories": unique_categories,
        }
        return result

    def enumerate_port(
        self,
        ip: str,
        port: int,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enumerate accepted cipher suites for a single port across TLS versions."""
        protocols: Dict[str, Any] = {
            "SSLv2": {"tested": False, "reason": "not offered by modern OpenSSL builds (SSLv2/SSLv3 disabled)"},
            "SSLv3": {"tested": False, "reason": "not offered by modern OpenSSL builds (SSLv2/SSLv3 disabled)"},
        }

        base = self._default_handshake(ip, port, server_name)
        if not base["ok"]:
            return {
                "ok": False,
                "error": base["error"],
                "scanner_openssl": ssl.OPENSSL_VERSION,
                "protocols": protocols,
                "weak_findings": [],
                "summary": {"accepted_total": 0, "weak_count": 0, "categories": []},
            }

        for version in self.ENUMERABLE_VERSIONS:
            protocols[version] = self._enumerate_version(ip, port, version, server_name)
        protocols["TLSv1.3"] = self._negotiated_tls13(ip, port, server_name)

        findings = self._build_weak_findings(protocols)
        accepted_total = sum(len(p.get("accepted", [])) for p in protocols.values())
        return {
            "ok": True,
            "error": None,
            "scanner_openssl": ssl.OPENSSL_VERSION,
            "protocols": protocols,
            "weak_findings": findings,
            "summary": {
                "accepted_total": accepted_total,
                "weak_count": len(findings),
                "categories": [f["category"] for f in findings],
            },
        }

    def _default_handshake(self, ip: str, port: int, server_name: Optional[str]) -> Dict[str, Any]:
        """Confirm the port speaks TLS at all before enumerating."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_name):
                    return {"ok": True, "error": None}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    def _enumerate_version(
        self,
        ip: str,
        port: int,
        version: str,
        server_name: Optional[str],
    ) -> Dict[str, Any]:
        """Offer-all-then-subtract for a single TLS version <= 1.2."""
        entry: Dict[str, Any] = {"tested": True, "accepted": [], "error": None}
        tls_version = self._TLS_VERSION[version]

        # One reusable context for all handshakes in this version. Pinning a
        # version the local OpenSSL cannot offer raises ValueError; check once.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
        except ValueError:
            return {"tested": False, "accepted": [],
                    "reason": f"{version} not supported by scanner's OpenSSL"}

        excluded: List[str] = []
        cap = max(1, int(self.config.cipher_max_per_protocol))

        while len(entry["accepted"]) < cap:
            cipher_str = "ALL:COMPLEMENTOFALL"
            if excluded:
                cipher_str += "".join(f":!{name}" for name in excluded)
            try:
                ctx.set_ciphers(cipher_str)
            except ssl.SSLError:
                break  # OpenSSL rejected the (fully-excluded) cipher string

            try:
                with socket.create_connection((ip, port), timeout=self.config.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                        negotiated = ssock.cipher()
            except OSError:
                # Normal exhaustion path: once every version-appropriate cipher
                # is excluded the server has nothing left to negotiate and the
                # handshake fails. set_ciphers may still succeed at that point
                # because TLS 1.3 suite names remain in the offer string, so this
                # OSError break — not the SSLError break above — is the usual loop
                # terminator. enumerate_port confirms reachability first, so this
                # is a fast handshake_failure alert, not a connection timeout.
                break

            if not negotiated:
                break
            name, _proto, bits = negotiated
            if name in excluded:
                break  # safety against non-terminating loops
            entry["accepted"].append({
                "name": name,
                "bits": bits,
                "categories": self.classify_cipher(name, bits, version),
            })
            excluded.append(name)

        return entry

    def _negotiated_tls13(self, ip: str, port: int, server_name: Optional[str]) -> Dict[str, Any]:
        """TLS 1.3: stdlib ssl cannot select individual suites; record the negotiated one."""
        entry: Dict[str, Any] = {
            "tested": True,
            "accepted": [],
            "error": None,
            "note": "TLS 1.3 suites are not individually selectable via stdlib ssl",
        }
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        except ValueError:
            entry["tested"] = False
            entry["error"] = "TLS 1.3 not supported by scanner's OpenSSL"
            return entry
        try:
            with socket.create_connection((ip, port), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                    negotiated = ssock.cipher()
                    if negotiated:
                        name, _proto, bits = negotiated
                        entry["accepted"].append({
                            "name": name,
                            "bits": bits,
                            "categories": self.classify_cipher(name, bits, "TLSv1.3"),
                        })
        except OSError:
            pass  # server does not offer TLS 1.3
        return entry

    def _build_weak_findings(self, protocols: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Group accepted weak ciphers by category across protocols."""
        by_category: Dict[str, Dict[str, set]] = {}
        for proto, data in protocols.items():
            for entry in data.get("accepted", []):
                for category in entry.get("categories", []):
                    slot = by_category.setdefault(category, {"protocols": set(), "ciphers": set()})
                    slot["protocols"].add(proto)
                    slot["ciphers"].add(entry["name"])

        findings = []
        for category, slot in by_category.items():
            findings.append({
                "category": category,
                "severity": self.CATEGORY_SEVERITY.get(category, "informational"),
                "protocols": sorted(slot["protocols"]),
                "ciphers": sorted(slot["ciphers"]),
                "rationale": self.CATEGORY_RATIONALE.get(category, ""),
            })
        findings.sort(key=lambda f: (self._SEVERITY_ORDER.get(f["severity"], 9), f["category"]))
        return findings
