"""Cloud/CDN/Load Balancer classifier

Heuristic classifier to distinguish origin servers from CDN edges and
cloud-managed gateways/load balancers, producing evidence suitable for
TPCRM finding dispute and remediation discussions.
"""

from typing import Dict, Any, List, Optional, Tuple


class CloudGatewayClassifier:
    """Classify environment role/provider from multiple signals."""

    # Known rDNS suffixes mapped to provider/role hints
    RDNS_SUFFIXES = {
        # CDNs
        "cloudfront.net": ("aws-cloudfront", "cdn-edge"),
        "akamai.net": ("akamai", "cdn-edge"),
        "akamaiedge.net": ("akamai", "cdn-edge"),
        "edgesuite.net": ("akamai", "cdn-edge"),
        "edgekey.net": ("akamai", "cdn-edge"),
        "fastly.net": ("fastly", "cdn-edge"),
        # Cloud WAF / LB / Edge
        "cloudflare.net": ("cloudflare", "cloud-waf"),
        "azureedge.net": ("azure-front-door", "cdn-edge"),
        "azurefd.net": ("azure-front-door", "cloud-waf"),
        "trafficmanager.net": ("azure", "lb"),
        "elb.amazonaws.com": ("aws-elb", "lb"),
        # Google
        "1e100.net": ("google", "edge"),
        "googleusercontent.com": ("google", "edge"),
    }

    # TLS Issuer/SAN hints
    CERT_ISSUER_HINTS = {
        "cloudflare": "cloudflare",
        "cloudfront": "aws-cloudfront",
        "amazon": "aws",
        "google trust services": "google",
        "fastly": "fastly",
        "microsoft azure": "azure",
        "let's encrypt": None,  # common; weak signal
        "lets encrypt": None,
    }

    SAN_SUFFIX_HINTS = {
        "cloudfront.net": "aws-cloudfront",
        "cloudflare.com": "cloudflare",
        "cloudflare.net": "cloudflare",
        "fastly.net": "fastly",
        "azureedge.net": "azure-front-door",
        "azurefd.net": "azure-front-door",
    }

    # HTTP header markers beyond WAF detector
    HEADER_MARKERS = {
        "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "aws-cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "via: 1.1 cloudfront"],
        "aws-elb": ["x-amzn-trace-id", "server: awselb"],
        "akamai": ["akamai", "akamai-ghost", "x-akamai", "x-akamai-transformed"],
        "fastly": ["x-served-by", "x-cache-hits", "x-timer", "x-fastly-request-id"],
        "azure-front-door": ["x-azure-ref", "x-azure-fdid"],
        "google": ["server: ESF", "x-guploader-uploadid", "x-goog-generation"],
    }

    ENTERPRISE_WAF_TOKENS = {"f5": "f5-big-ip", "citrix": "citrix-netscaler", "incapsula": "imperva-incapsula",
                              "fortiweb": "fortinet", "barracuda": "barracuda"}

    EDGE_INDICATORS = ["via", "x-cache", "x-served-by", "age", "server-timing"]

    def classify_from_probe(
        self,
        reverse_dns: Optional[str],
        tls_info: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, List[str]]],
        server_analysis: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Classify using single-probe signals.

        Returns a dict with keys: classification, provider, confidence, evidence, role
        """
        evidence: Dict[str, Any] = {
            "rdns_match": None,
            "issuer_match": None,
            "san_matches": [],
            "header_markers": {},
            "server_token": server_analysis.get("raw") if server_analysis else None,
            "edge_indicators": [],
        }

        scores: Dict[str, int] = {}
        role_hint: Optional[str] = None

        # rDNS suffix
        if reverse_dns:
            rdns_lower = reverse_dns.lower()
            for suffix, (provider, role) in self.RDNS_SUFFIXES.items():
                if rdns_lower.endswith(suffix):
                    scores[provider] = scores.get(provider, 0) + 2
                    evidence["rdns_match"] = suffix
                    role_hint = role_hint or role
                    break

        # TLS issuer/SANs
        cert = None
        if tls_info and isinstance(tls_info, dict):
            cert = tls_info.get("certificate") or tls_info

        if cert:
            issuer = cert.get("issuer")
            issuer_text = self._issuer_to_text(issuer)
            issuer_lower = issuer_text.lower()
            for hint, provider in self.CERT_ISSUER_HINTS.items():
                if hint in issuer_lower and provider:
                    scores[provider] = scores.get(provider, 0) + 1
                    evidence["issuer_match"] = hint
                    break

            sans = cert.get("subjectAltName", [])
            for entry in sans:
                try:
                    name_type, name_value = entry
                except (TypeError, ValueError):
                    continue
                if name_type == "DNS":
                    name_lower = name_value.lower()
                    for suffix, provider in self.SAN_SUFFIX_HINTS.items():
                        if name_lower.endswith(suffix):
                            scores[provider] = scores.get(provider, 0) + 2
                            evidence["san_matches"].append(name_value)

        # Headers
        header_blob = ""
        if headers:
            flattened: List[str] = []
            for k, vals in headers.items():
                for v in vals:
                    line = f"{k.lower()}: {str(v).lower()}"
                    flattened.append(line)
            header_blob = "\n".join(flattened)

            # Provider markers
            for provider, markers in self.HEADER_MARKERS.items():
                hits = [m for m in markers if m.lower() in header_blob]
                if hits:
                    scores[provider] = scores.get(provider, 0) + min(2, len(hits))
                    evidence["header_markers"][provider] = hits

            # Edge indicators
            for ind in self.EDGE_INDICATORS:
                if ind in header_blob:
                    evidence["edge_indicators"].append(ind)

        # Enterprise WAF tokens from server header
        if server_analysis and server_analysis.get("raw"):
            raw = server_analysis["raw"].lower()
            for token, provider in self.ENTERPRISE_WAF_TOKENS.items():
                if token in raw:
                    scores[provider] = scores.get(provider, 0) + 2

        # Decide provider and role
        provider, score = self._top_provider(scores)
        role = self._decide_role(provider, role_hint, evidence)

        classification = "origin"
        if role in ("cdn-edge", "cloud-waf", "lb", "edge"):
            classification = "managed_edge"

        confidence = self._confidence(score)

        return {
            "classification": classification,
            "provider": provider,
            "role": role,
            "confidence": confidence,
            "score": score,
            "evidence": evidence,
        }

    def classify_overall(self, probe_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate probe-level classifications into a final decision."""
        best: Optional[Dict[str, Any]] = None
        for pr in probe_results:
            cls = pr.get("classification") or {}
            if not best or (cls.get("score", 0) > best.get("score", 0)):
                best = cls
        return best or {"classification": "unknown", "confidence": "low", "provider": None, "role": None, "score": 0, "evidence": {}}

    def _top_provider(self, scores: Dict[str, int]) -> Tuple[Optional[str], int]:
        if not scores:
            return None, 0
        provider = max(scores, key=lambda k: scores[k])
        return provider, scores[provider]

    def _decide_role(self, provider: Optional[str], role_hint: Optional[str], evidence: Dict[str, Any]) -> Optional[str]:
        if role_hint:
            return role_hint
        if not provider:
            return None
        if provider in ("aws-cloudfront", "akamai", "fastly"):
            return "cdn-edge"
        if provider in ("cloudflare", "azure-front-door"):
            return "cloud-waf"
        if provider in ("aws-elb",):
            return "lb"
        # Fallback: if strong edge indicators -> edge
        if evidence.get("edge_indicators"):
            return "edge"
        return None

    def _confidence(self, score: int) -> str:
        if score >= 5:
            return "high"
        if score >= 3:
            return "medium"
        return "low"

    def _issuer_to_text(self, issuer_obj: Any) -> str:
        """Flatten OpenSSL-style issuer structures into a string safely."""
        if not issuer_obj:
            return ""
        if isinstance(issuer_obj, str):
            return issuer_obj
        parts: List[str] = []
        try:
            stack = [issuer_obj]
            while stack:
                item = stack.pop()
                if isinstance(item, (list, tuple)):
                    if len(item) == 2 and all(not isinstance(x, (list, tuple)) for x in item):
                        # Looks like (key, value)
                        parts.append(str(item[1]))
                    else:
                        # Recurse into contents
                        for sub in item:
                            stack.append(sub)
                else:
                    parts.append(str(item))
        except (TypeError, ValueError, IndexError):
            return str(issuer_obj)
        return " ".join(parts)
