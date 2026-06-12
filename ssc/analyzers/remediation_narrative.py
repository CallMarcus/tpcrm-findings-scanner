"""Remediation narrative generation for TPCRM platform finding responses."""

from typing import Any, Dict, List, Optional


class RemediationNarrativeGenerator:
    """Produce ticket-ready remediation language from scan results."""

    PROVIDER_LABELS = {
        "cloudflare": "Cloudflare",
        "aws-cloudfront": "AWS CloudFront",
        "aws-elb": "AWS Elastic Load Balancing",
        "aws": "AWS",
        "akamai": "Akamai",
        "fastly": "Fastly",
        "google": "Google",
        "azure-front-door": "Azure Front Door",
        "azure": "Microsoft Azure",
        "f5-big-ip": "F5 BIG-IP",
    }

    ROLE_LABELS = {
        "cdn-edge": "CDN edge",
        "cloud-waf": "cloud WAF",
        "lb": "load balancer",
        "edge": "edge node",
        "enterprise-waf": "enterprise WAF",
    }

    def generate(self, scan_data: Dict[str, Any], target_ip: str) -> Dict[str, Any]:
        """Build structured remediation narrative from scan data."""
        classification = (scan_data.get("security_analysis", {}) or {}).get("classification", {}) or {}
        waf_services = self._waf_services(scan_data)
        backport = scan_data.get("backport_analysis", {}) or {}
        evidence_assessment = (scan_data.get("evidence", {}) or {}).get("assessment", {}) or {}
        security_score = self._security_score(scan_data)

        environment_statement = self._environment_statement(target_ip, classification, waf_services)
        backport_statement = self._backport_statement(backport)
        security_controls_statement = self._security_controls_statement(
            waf_services, security_score, evidence_assessment
        )
        evidence_bullets = self._evidence_bullets(classification, scan_data, waf_services, backport)
        recommended_actions = self._recommended_actions(
            target_ip, classification, waf_services, backport, security_score, scan_data
        )

        paragraphs = [environment_statement]
        if security_controls_statement:
            paragraphs.append(security_controls_statement)
        if backport_statement:
            paragraphs.append(backport_statement)

        summary = " ".join(paragraph for paragraph in paragraphs if paragraph)

        return {
            "summary": summary,
            "environment_statement": environment_statement,
            "backport_statement": backport_statement,
            "security_controls_statement": security_controls_statement,
            "evidence_bullets": evidence_bullets,
            "recommended_actions": recommended_actions,
            "suitable_for_remediation_response": self._suitable_for_response(
                classification, backport, evidence_assessment, waf_services
            ),
        }

    def _waf_services(self, scan_data: Dict[str, Any]) -> List[str]:
        services = (scan_data.get("security_analysis", {}) or {}).get("waf_cdn", {}).get("services", [])
        return services if isinstance(services, list) else []

    def _security_score(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        security = scan_data.get("security_analysis", {}) or {}
        score = security.get("score") or (security.get("security_headers") or {}).get("score")
        return score if isinstance(score, dict) else {}

    def _provider_label(self, provider: Optional[str]) -> str:
        if not provider:
            return "an unidentified provider"
        return self.PROVIDER_LABELS.get(provider, provider.replace("-", " ").title())

    def _role_label(self, role: Optional[str]) -> str:
        if not role:
            return "managed gateway"
        return self.ROLE_LABELS.get(role, role.replace("-", " "))

    def _environment_statement(
        self,
        target_ip: str,
        classification: Dict[str, Any],
        waf_services: List[str],
    ) -> str:
        env_class = classification.get("classification")
        provider = classification.get("provider")
        role = classification.get("role")
        confidence = classification.get("confidence", "low")
        provider_label = self._provider_label(provider)
        role_label = self._role_label(role)

        if env_class == "managed_edge" and confidence in ("high", "medium"):
            statement = (
                f"Target {target_ip} presents as a {role_label} operated by {provider_label} "
                f"({confidence} confidence). Findings observed on this IP likely reflect edge or "
                f"gateway configuration rather than the origin application server."
            )
        elif env_class == "managed_edge" or waf_services:
            service_labels = ", ".join(self.PROVIDER_LABELS.get(s, s) for s in waf_services)
            lead = (
                f"Target {target_ip} shows indicators of edge or WAF protection"
                + (f" ({service_labels})" if waf_services else f" via {provider_label}")
            )
            statement = (
                f"{lead} ({confidence} confidence). Findings observed on this IP may reflect "
                f"protection-layer configuration rather than the origin application server."
            )
        elif env_class == "origin":
            statement = (
                f"Target {target_ip} appears to be a direct origin or application server "
                f"({confidence} confidence). Findings observed during this scan are likely applicable "
                f"to the asset under assessment."
            )
        else:
            statement = (
                f"Target {target_ip} could not be confidently classified as origin or managed edge "
                f"({confidence} confidence). Treat findings with caution and corroborate using DNS, "
                f"asset inventory, and origin validation."
            )

        if waf_services and "protection services detected" not in statement:
            service_labels = ", ".join(self.PROVIDER_LABELS.get(s, s) for s in waf_services)
            statement += f" Active protection services detected: {service_labels}."

        return statement

    def _backport_statement(self, backport: Dict[str, Any]) -> str:
        confidence = backport.get("confidence", "none")
        if confidence in ("none", "unknown"):
            return ""

        recommendation = backport.get("recommendation", "").strip()
        if recommendation:
            return recommendation

        if confidence == "high":
            return (
                "Strong evidence suggests backported security patches on this system. "
                "Version-based vulnerability findings may be false positives and should be "
                "validated against actual package patch levels."
            )
        if confidence == "medium":
            return (
                "Moderate evidence suggests backported packages may be in use. "
                "Verify patch status through the system package manager before remediating "
                "based on version strings alone."
            )
        return (
            "Limited backport indicators were observed. Critical version-based findings "
            "should still be verified against installed package versions."
        )

    def _security_controls_statement(
        self,
        waf_services: List[str],
        security_score: Dict[str, Any],
        evidence_assessment: Dict[str, Any],
    ) -> str:
        parts: List[str] = []

        if waf_services:
            parts.append(
                "Compensating controls appear to include edge or WAF protection in front of the service."
            )

        if security_score:
            grade = security_score.get("grade", "Unknown")
            percentage = security_score.get("percentage", 0)
            if percentage >= 60:
                parts.append(
                    f"HTTP security headers are partially implemented (score {grade}, {percentage:.1f}%), "
                    f"which may offset certain web-facing findings."
                )
            elif percentage > 0:
                parts.append(
                    f"HTTP security headers are only partially implemented (score {grade}, {percentage:.1f}%)."
                )

        overall = evidence_assessment.get("overall")
        if overall in ("strong", "moderate"):
            count = evidence_assessment.get("evidence_count", 0)
            parts.append(
                f"Collected compensating-controls evidence is {overall} ({count} supporting item(s))."
            )

        return " ".join(parts)

    def _evidence_bullets(
        self,
        classification: Dict[str, Any],
        scan_data: Dict[str, Any],
        waf_services: List[str],
        backport: Dict[str, Any],
    ) -> List[str]:
        bullets: List[str] = []
        evidence = classification.get("evidence", {}) or {}

        rdns = evidence.get("rdns_match") or scan_data.get("reverse_dns")
        if rdns:
            bullets.append(f"Reverse DNS: {rdns}")

        san_matches = evidence.get("san_matches") or []
        for san in san_matches[:3]:
            bullets.append(f"TLS certificate SAN: {san}")

        issuer = evidence.get("issuer_match")
        if issuer:
            bullets.append(f"TLS issuer indicator: {issuer}")

        header_markers = evidence.get("header_markers", {}) or {}
        for provider, markers in header_markers.items():
            if markers:
                label = self._provider_label(provider)
                bullets.append(f"HTTP headers indicate {label}: {', '.join(markers[:3])}")

        server_token = evidence.get("server_token")
        if server_token:
            bullets.append(f"Server banner/token: {server_token}")

        for service in waf_services[:3]:
            bullets.append(f"WAF/CDN service detected: {service}")

        for item in backport.get("backport_evidence", [])[:3]:
            indicator = item.get("indicator", "indicator present")
            distro = item.get("distribution", "unknown")
            bullets.append(f"Backport indicator ({distro}): {indicator}")

        origin_discovery = scan_data.get("origin_discovery", {}) or {}
        for hint in origin_discovery.get("origin_hints", [])[:3]:
            hostname = hint.get("hostname")
            source = hint.get("source", "unknown")
            if hostname:
                bullets.append(f"Origin hostname hint ({source}): {hostname}")

        dns_chain = origin_discovery.get("dns_chain", {}) or {}
        for hop in dns_chain.get("hops", [])[:3]:
            if hop.get("is_edge"):
                provider = self._provider_label(hop.get("provider"))
                bullets.append(f"DNS chain edge hop: {hop.get('hostname')} ({provider})")

        return bullets

    def _recommended_actions(
        self,
        target_ip: str,
        classification: Dict[str, Any],
        waf_services: List[str],
        backport: Dict[str, Any],
        security_score: Dict[str, Any],
        scan_data: Dict[str, Any],
    ) -> List[str]:
        actions: List[str] = []
        env_class = classification.get("classification")
        confidence = classification.get("confidence", "low")

        origin_discovery = scan_data.get("origin_discovery", {}) or {}
        top_hints = (origin_discovery.get("summary", {}) or {}).get("top_hints", [])

        if env_class == "managed_edge" or waf_services:
            actions.append(
                "Do not remediate against this IP alone; validate the finding on the origin hostname "
                "or origin server behind the edge/CDN/WAF."
            )
            if top_hints:
                actions.append(
                    "Investigate the reported origin hostname hint(s): "
                    + ", ".join(top_hints[:3])
                    + "."
                )
            actions.append(
                "Request or identify the origin asset from DNS CNAME/A records, asset inventory, "
                "or application owner confirmation."
            )
        elif env_class != "origin":
            actions.append(
                f"Corroborate the role of {target_ip} using DNS, TLS certificate SANs, and asset inventory "
                "before accepting scan findings as origin issues."
            )

        if waf_services:
            actions.append(
                "Review whether the reported issue is introduced by the protection layer rather than "
                "the application configuration."
            )

        backport_confidence = backport.get("confidence", "none")
        if backport_confidence in ("high", "medium"):
            actions.append(
                "Verify installed package versions and vendor patch backports before treating "
                "version-string findings as exploitable vulnerabilities."
            )
        elif backport_confidence == "low":
            actions.append(
                "For critical version-based findings, confirm patch levels with package manager output "
                "or vendor maintenance records."
            )

        if security_score and security_score.get("percentage", 0) < 60:
            actions.append(
                "Consider implementing missing HTTP security headers on the applicable origin service "
                "if the finding relates to browser-side protections."
            )

        if not actions:
            actions.append(
                "Review the technical evidence in this report and confirm the finding applies to the "
                "intended production asset before remediation."
            )

        return actions

    def _suitable_for_response(
        self,
        classification: Dict[str, Any],
        backport: Dict[str, Any],
        evidence_assessment: Dict[str, Any],
        waf_services: List[str],
    ) -> bool:
        if classification.get("classification") == "managed_edge":
            return True
        if backport.get("confidence") in ("high", "medium"):
            return True
        if waf_services:
            return True
        if evidence_assessment.get("overall") in ("strong", "moderate"):
            return True
        return False