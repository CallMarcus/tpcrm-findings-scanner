"""Origin discovery hints and forward DNS chain analysis."""

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..utils.dns_chain import build_chain_hops, resolve_forward_chain
from ..utils.network import is_valid_hostname, valid_ip
from .cloud_classifier import CloudGatewayClassifier


class OriginDiscoveryAnalyzer:
    """Collect origin hostname hints and annotate DNS/CNAME chains."""

    def __init__(self, timeout: float = 2.0, lookup_fn: Optional[Callable[..., Any]] = None):
        self.timeout = timeout
        self.lookup_fn = lookup_fn
        self._edge_suffixes = self._build_edge_suffix_map()

    @staticmethod
    def _build_edge_suffix_map() -> Dict[str, Dict[str, str]]:
        mapping: Dict[str, Dict[str, str]] = {}
        for suffix, (provider, role) in CloudGatewayClassifier.RDNS_SUFFIXES.items():
            mapping[suffix] = {"provider": provider, "role": role}
        for suffix, provider in CloudGatewayClassifier.SAN_SUFFIX_HINTS.items():
            mapping.setdefault(suffix, {"provider": provider, "role": "edge"})
        return mapping

    def analyze(
        self,
        scan_data: Dict[str, Any],
        hostname: Optional[str] = None,
        host: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build origin discovery block from scan data and optional hostname input."""
        metadata = scan_data.get("metadata", {}) or {}
        query_hostname = self._select_query_hostname(hostname, host, metadata)

        dns_chain = self._build_dns_chain(query_hostname)
        redirect_hosts = self._collect_redirect_hosts(scan_data)
        tls_hostnames = self._collect_tls_hostnames(scan_data)
        ptr_hostname = self._ptr_as_hostname(scan_data.get("reverse_dns"))

        annotated_hops = self._annotate_hops(dns_chain.get("hops", []))
        edge_hostnames = [
            hop["hostname"]
            for hop in annotated_hops
            if hop.get("is_edge")
        ]

        origin_hints = self._build_origin_hints(
            query_hostname=query_hostname,
            annotated_hops=annotated_hops,
            tls_hostnames=tls_hostnames,
            ptr_hostname=ptr_hostname,
            redirect_hosts=redirect_hosts,
            scan_ip=(metadata.get("target_ip") or ""),
        )

        summary = {
            "query_hostname": query_hostname,
            "has_dns_chain": bool(annotated_hops),
            "edge_detected_in_chain": any(hop.get("is_edge") for hop in annotated_hops),
            "hint_count": len(origin_hints),
            "top_hints": [hint["hostname"] for hint in origin_hints[:5]],
            "redirect_host_count": len(redirect_hosts),
        }

        return {
            "dns_chain": dns_chain,
            "origin_hints": origin_hints,
            "edge_hostnames": edge_hostnames,
            "redirect_hosts": redirect_hosts,
            "summary": summary,
        }

    def _select_query_hostname(
        self,
        hostname: Optional[str],
        host: Optional[str],
        metadata: Dict[str, Any],
    ) -> Optional[str]:
        for candidate in (hostname, host, metadata.get("host"), metadata.get("input_target")):
            if candidate and is_valid_hostname(candidate) and not valid_ip(candidate):
                return candidate.rstrip(".")
        return None

    def _build_dns_chain(self, query_hostname: Optional[str]) -> Dict[str, Any]:
        if not query_hostname:
            return {
                "query_hostname": None,
                "canonical_name": None,
                "aliases": [],
                "resolved_ips": [],
                "hops": [],
                "error": "No hostname input available for forward DNS lookup",
            }

        chain = resolve_forward_chain(
            query_hostname,
            timeout=self.timeout,
            lookup_fn=self.lookup_fn,
        )
        hops = build_chain_hops(chain)
        return {
            "query_hostname": chain.get("query_hostname"),
            "canonical_name": chain.get("canonical_name"),
            "aliases": chain.get("aliases", []),
            "resolved_ips": chain.get("resolved_ips", []),
            "hops": self._annotate_hops(
                [{"hostname": hop["hostname"], "position": hop["position"]} for hop in hops]
            ),
            "error": chain.get("error"),
        }

    def _annotate_hops(self, hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        annotated: List[Dict[str, Any]] = []
        for hop in hops:
            hostname = hop.get("hostname")
            if not hostname:
                continue
            edge = self._classify_hostname(hostname)
            entry = {
                "hostname": hostname,
                "position": hop.get("position"),
                "is_edge": edge.get("is_edge", False),
            }
            if edge.get("provider"):
                entry["provider"] = edge["provider"]
            if edge.get("role"):
                entry["role"] = edge["role"]
            if edge.get("matched_suffix"):
                entry["matched_suffix"] = edge["matched_suffix"]
            annotated.append(entry)
        return annotated

    def _classify_hostname(self, hostname: str) -> Dict[str, Any]:
        host = hostname.lower().rstrip(".")
        for suffix, info in sorted(self._edge_suffixes.items(), key=lambda item: -len(item[0])):
            if host == suffix or host.endswith("." + suffix):
                return {
                    "is_edge": True,
                    "provider": info["provider"],
                    "role": info["role"],
                    "matched_suffix": suffix,
                }
        return {"is_edge": False}

    def _build_origin_hints(
        self,
        query_hostname: Optional[str],
        annotated_hops: List[Dict[str, Any]],
        tls_hostnames: List[Tuple[str, str]],
        ptr_hostname: Optional[str],
        redirect_hosts: List[str],
        scan_ip: str,
    ) -> List[Dict[str, Any]]:
        hints: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def add_hint(
            hostname: str,
            source: str,
            confidence: str,
            notes: str = "",
        ) -> None:
            cleaned = hostname.strip().rstrip(".")
            if not cleaned or valid_ip(cleaned) or "*" in cleaned:
                return
            if not is_valid_hostname(cleaned):
                return

            edge = self._classify_hostname(cleaned)
            if edge.get("is_edge"):
                return

            norm = cleaned.lower()
            if norm == scan_ip.lower() or norm in seen:
                return

            seen.add(norm)
            hints.append(
                {
                    "hostname": cleaned,
                    "source": source,
                    "confidence": confidence,
                    "notes": notes,
                }
            )

        if query_hostname:
            add_hint(
                query_hostname,
                "input_hostname",
                "high",
                "Hostname supplied for the scan; often maps to the customer-facing asset.",
            )

        for hop in annotated_hops:
            if hop.get("is_edge"):
                break
            hostname = hop.get("hostname")
            if hostname and hostname != query_hostname:
                add_hint(
                    hostname,
                    "dns_chain",
                    "medium",
                    "Hostname observed before the first edge/CDN hop in the DNS chain.",
                )

        for hostname, source in tls_hostnames:
            add_hint(
                hostname,
                source,
                "medium",
                "Certificate name may indicate an origin or alternate service hostname.",
            )

        if ptr_hostname:
            add_hint(
                ptr_hostname,
                "reverse_dns",
                "low",
                "Reverse DNS can reflect origin naming, but edge nodes often use provider domains.",
            )

        for hostname in redirect_hosts:
            add_hint(
                hostname,
                "http_redirect",
                "medium",
                "Hostname observed in HTTP redirect chain during probing.",
            )

        return hints

    def _collect_tls_hostnames(self, scan_data: Dict[str, Any]) -> List[Tuple[str, str]]:
        hostnames: List[Tuple[str, str]] = []
        seen: Set[str] = set()

        cert = (
            (scan_data.get("tls_analysis", {}) or {})
            .get("default_handshake", {})
            .get("certificate")
        )
        if not cert:
            return hostnames

        cn = self._extract_cn(cert)
        if cn:
            norm = cn.lower()
            if norm not in seen:
                hostnames.append((cn, "tls_cn"))
                seen.add(norm)

        for san in self._extract_sans(cert):
            norm = san.lower()
            if norm in seen:
                continue
            hostnames.append((san, "tls_san"))
            seen.add(norm)

        return hostnames

    @staticmethod
    def _extract_cn(cert: Dict[str, Any]) -> Optional[str]:
        subject = cert.get("subject")
        if not subject:
            return None
        try:
            for rdn in subject:
                for attr_type, value in rdn:
                    if attr_type == "commonName":
                        return str(value).strip().strip(".")
        except (TypeError, AttributeError):
            return None
        return None

    @staticmethod
    def _extract_sans(cert: Dict[str, Any]) -> List[str]:
        sans: List[str] = []
        try:
            for name_type, name_value in cert.get("subjectAltName", []) or []:
                if name_type == "DNS":
                    cleaned = str(name_value).strip().strip(".")
                    if cleaned:
                        sans.append(cleaned)
        except (TypeError, AttributeError):
            pass
        return sans

    @staticmethod
    def _ptr_as_hostname(ptr_name: Optional[str]) -> Optional[str]:
        if not ptr_name:
            return None
        cleaned = ptr_name.strip().rstrip(".")
        if valid_ip(cleaned) or not is_valid_hostname(cleaned):
            return None
        return cleaned

    @staticmethod
    def _collect_redirect_hosts(scan_data: Dict[str, Any]) -> List[str]:
        hosts: List[str] = []
        seen: Set[str] = set()

        probes = (scan_data.get("http_analysis", {}) or {}).get("probes", []) or []
        for probe in probes:
            if not isinstance(probe, dict):
                continue
            result = probe.get("result") or {}
            for request in result.get("requests", []) or []:
                if not isinstance(request, dict):
                    continue
                host_header = request.get("host_header")
                if not host_header or valid_ip(host_header):
                    continue
                norm = host_header.lower()
                if norm in seen:
                    continue
                hosts.append(host_header)
                seen.add(norm)

        return hosts