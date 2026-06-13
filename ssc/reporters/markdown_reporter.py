"""Markdown report generation"""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from ..utils.files import open_unique

class MarkdownReporter:
    """Generate human-readable Markdown reports"""
    
    def __init__(self, output_dir: str = "outputs/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, scan_data: Dict[str, Any], target_ip: str) -> str:
        """Generate comprehensive Markdown scan report"""
        timestamp = int(time.time())
        lines = []
        
        # Header
        lines.extend([
            f"# Security Scan Report for {target_ip}",
            "",
            f"- **Timestamp (UTC)**: {datetime.now(timezone.utc).isoformat()}",
            f"- **Scanner**: TPCRM Findings Scanner v2.0",
            f"- **Target**: {target_ip}",
            ""
        ])
        
        # Executive Summary
        lines.extend(self._generate_summary_section(scan_data))

        # Remediation narrative
        lines.extend(self._generate_narrative_section(scan_data))

        # Origin discovery
        lines.extend(self._generate_origin_discovery_section(scan_data))
        
        # Port Scan Results
        if "port_scan" in scan_data:
            lines.extend(self._generate_port_section(scan_data["port_scan"]))
        
        # TLS Analysis
        if "tls_analysis" in scan_data:
            lines.extend(self._generate_tls_section(scan_data["tls_analysis"]))

        # TLS Cipher Suites
        if "cipher_enumeration" in scan_data:
            lines.extend(self._generate_cipher_section(scan_data["cipher_enumeration"]))

        # HTTP Analysis
        if "http_analysis" in scan_data:
            lines.extend(self._generate_http_section(scan_data["http_analysis"]))
        
        # Security Analysis
        if "security_analysis" in scan_data:
            lines.extend(self._generate_security_section(scan_data["security_analysis"]))
        
        # Evidence and Recommendations
        lines.extend(self._generate_recommendations_section(scan_data))
        
        # Technical Details
        lines.extend(self._generate_technical_details(scan_data))
        
        # Write report
        content = "\n".join(lines)
        filename = f"scan_{target_ip.replace(':', '_')}_{timestamp}.md"
        handle, filepath = open_unique(str(self.output_dir / filename))
        with handle as f:
            f.write(content)

        return filepath
    
    def _generate_summary_section(self, scan_data: Dict[str, Any]) -> List[str]:
        """Generate executive summary section"""
        lines = [
            "## Executive Summary",
            ""
        ]
        
        # Port summary
        if "port_scan" in scan_data:
            open_ports = scan_data["port_scan"].get("open_ports", [])
            lines.append(f"- **Open Ports**: {len(open_ports)} ports found: {', '.join(map(str, open_ports)) if open_ports else 'None'}")
        
        # Service summary
        services = []
        if "http_analysis" in scan_data:
            for probe in scan_data["http_analysis"].get("probes", []):
                if not isinstance(probe, dict):
                    continue

                result = probe.get("result") or {}
                final = result.get("final") or {}

                if final.get("status_code"):
                    services.append(
                        f"HTTP{'S' if probe.get('use_tls') else ''} on port {probe.get('port')}"
                    )
        
        if services:
            lines.append(f"- **Web Services**: {', '.join(services)}")

        # Environment classification
        classification = scan_data.get("security_analysis", {}).get("classification", {})
        if classification:
            role = classification.get("role") or classification.get("classification")
            provider = classification.get("provider") or "unknown"
            conf = classification.get("confidence", "unknown")
            role_display = role.replace('-', ' ') if isinstance(role, str) else role
            lines.append(f"- **Environment**: {role_display} via {provider} ({conf} confidence)")

        # Security posture
        if "security_analysis" in scan_data:
            security = scan_data["security_analysis"]
            score = security.get("score") or (security.get("security_headers") or {}).get("score")
            if score:
                lines.append(
                    f"- **Security Headers Score**: {score.get('grade', 'Unknown')} "
                    f"({score.get('percentage', 0):.1f}%)"
                )
            if "waf_cdn" in security and security["waf_cdn"].get("services"):
                lines.append(f"- **Protection**: {', '.join(security['waf_cdn']['services'])}")

        if "backport_analysis" in scan_data:
            backport = scan_data["backport_analysis"]
            lines.append(f"- **Backport Evidence**: {backport.get('confidence', 'unknown')} confidence")

        if "evidence" in scan_data:
            assessment = scan_data["evidence"].get("assessment", {})
            lines.append(
                f"- **Compensating Controls Evidence**: {assessment.get('overall', 'unknown')} "
                f"({assessment.get('evidence_count', 0)} items)"
            )

        if "cipher_enumeration" in scan_data:
            cipher_sum = scan_data["cipher_enumeration"].get("summary", {})
            cats = ", ".join(cipher_sum.get("categories", [])) or "none"
            lines.append(
                f"- **TLS Cipher Findings**: {cipher_sum.get('weak_count', 0)} weak ({cats})"
            )

        lines.extend(["", "---", ""])
        return lines

    def _generate_narrative_section(self, scan_data: Dict[str, Any]) -> List[str]:
        """Generate remediation narrative for TPCRM platform finding responses."""
        narrative = scan_data.get("remediation_narrative", {})
        if not narrative:
            return []

        lines = [
            "## Remediation Narrative",
            "",
            narrative.get("summary", ""),
            "",
        ]

        evidence_bullets = narrative.get("evidence_bullets", [])
        if evidence_bullets:
            lines.append("**Supporting evidence:**")
            for bullet in evidence_bullets:
                lines.append(f"- {bullet}")
            lines.append("")

        actions = narrative.get("recommended_actions", [])
        if actions:
            lines.append("**Recommended actions:**")
            for index, action in enumerate(actions, 1):
                lines.append(f"{index}. {action}")
            lines.append("")

        if narrative.get("suitable_for_remediation_response"):
            lines.append(
                "_This scan produced sufficient context for a compensating-controls or "
                "false-positive remediation response._"
            )
            lines.append("")

        lines.extend(["---", ""])
        return lines

    def _generate_origin_discovery_section(self, scan_data: Dict[str, Any]) -> List[str]:
        """Generate origin discovery hints and DNS chain section."""
        discovery = scan_data.get("origin_discovery", {}) or {}
        if not discovery:
            return []

        lines = [
            "## Origin Discovery",
            "",
        ]

        summary = discovery.get("summary", {}) or {}
        query_hostname = summary.get("query_hostname")
        if query_hostname:
            lines.append(f"- **Query hostname**: {query_hostname}")

        dns_chain = discovery.get("dns_chain", {}) or {}
        if dns_chain.get("error"):
            lines.append(f"- **DNS chain**: lookup failed ({dns_chain['error']})")
        elif dns_chain.get("hops"):
            lines.append("- **DNS / CNAME chain**:")
            for hop in dns_chain.get("hops", []):
                hostname = hop.get("hostname", "unknown")
                position = hop.get("position", "hop")
                if hop.get("is_edge"):
                    provider = hop.get("provider", "edge")
                    lines.append(f"  - `{hostname}` ({position}) → edge via {provider}")
                else:
                    lines.append(f"  - `{hostname}` ({position})")
            resolved_ips = dns_chain.get("resolved_ips", [])
            if resolved_ips:
                lines.append(f"- **Resolved IPs**: {', '.join(resolved_ips)}")
        else:
            lines.append("- **DNS chain**: no hostname input available for forward lookup")

        origin_hints = discovery.get("origin_hints", []) or []
        if origin_hints:
            lines.append("- **Origin hostname hints**:")
            for hint in origin_hints[:8]:
                hostname = hint.get("hostname", "unknown")
                source = hint.get("source", "unknown")
                confidence = hint.get("confidence", "unknown")
                lines.append(f"  - `{hostname}` ({source}, {confidence} confidence)")
        else:
            lines.append("- **Origin hostname hints**: none identified")

        redirect_hosts = discovery.get("redirect_hosts", []) or []
        if redirect_hosts:
            lines.append(f"- **Redirect hosts observed**: {', '.join(redirect_hosts[:5])}")

        lines.extend(["", "---", ""])
        return lines
    
    def _generate_port_section(self, port_data: Dict[str, Any]) -> List[str]:
        """Generate port scan section"""
        lines = [
            "## Port Scan Results",
            ""
        ]
        
        open_ports = port_data.get("open_ports", [])
        if open_ports:
            lines.append(f"**{len(open_ports)} open ports found:**")
            lines.append("")
            for port in open_ports:
                lines.append(f"- Port **{port}**/tcp")
            lines.append("")
        
        # Banners
        banners = port_data.get("banners", {})
        if banners:
            lines.extend([
                "### Service Banners",
                ""
            ])
            for port, banner in banners.items():
                lines.extend([
                    f"**Port {port}:**",
                    "```",
                    banner[:500] + ("..." if len(banner) > 500 else ""),
                    "```",
                    ""
                ])
        
        return lines
    
    def _generate_tls_section(self, tls_data: Dict[str, Any]) -> List[str]:
        """Generate TLS analysis section"""
        lines = [
            "## TLS/SSL Analysis",
            ""
        ]
        
        default_handshake = tls_data.get("default_handshake", {})
        if default_handshake.get("ok"):
            cert = default_handshake.get("certificate") or {}
            lines.extend([
                "### Certificate Information",
                f"- **TLS Version**: {default_handshake.get('tls_version', 'Unknown')}",
                f"- **Cipher Suite**: {default_handshake.get('cipher', ['Unknown'])[0] if default_handshake.get('cipher') else 'Unknown'}",
                f"- **Subject**: {cert.get('subject', 'Unknown')}",
                f"- **Issuer**: {cert.get('issuer', 'Unknown')}",
                f"- **Expires**: {cert.get('notAfter', 'Unknown')}",
                ""
            ])
            
            # Certificate expiry warning
            if "days_until_expiry" in tls_data:
                days = tls_data["days_until_expiry"]
                if days < 30:
                    lines.append(f"⚠️  **Warning**: Certificate expires in {days} days")
                    lines.append("")
        
        # TLS version support
        versions = tls_data.get("versions", {})
        if versions:
            lines.extend([
                "### TLS Version Support",
                ""
            ])
            for version, result in versions.items():
                status = "✅" if result.get("ok") else "❌"
                lines.append(f"- {version}: {status}")
            lines.append("")
        
        return lines
    
    def _generate_cipher_section(self, cipher_data: Dict[str, Any]) -> List[str]:
        """Render the TLS cipher-suite enumeration section."""
        lines = ["## TLS Cipher Suites", ""]
        scanner = cipher_data.get("scanner_openssl")
        if scanner:
            lines.append(f"- **Scanner OpenSSL**: {scanner}")
            lines.append("")

        ports = cipher_data.get("ports", {}) or {}
        for port, port_data in ports.items():
            lines.append(f"### Port {port}")
            if not port_data.get("ok", False):
                lines.append(f"- TLS handshake failed: {port_data.get('error', 'unknown error')}")
                lines.append("")
                continue
            for proto, proto_data in (port_data.get("protocols", {}) or {}).items():
                if not proto_data.get("tested", False):
                    reason = proto_data.get("reason", "not tested")
                    lines.append(f"- **{proto}**: not tested ({reason})")
                    continue
                accepted = proto_data.get("accepted", [])
                note = proto_data.get("note")
                if not accepted:
                    lines.append(f"- **{proto}**: no accepted ciphers")
                    if note:
                        lines.append(f"  - _{note}_")
                    continue
                lines.append(f"- **{proto}**:")
                for entry in accepted:
                    cats = ", ".join(entry.get("categories", [])) or "ok"
                    lines.append(f"  - `{entry.get('name', 'unknown')}` ({entry.get('bits', '?')}-bit) — {cats}")
                if note:
                    lines.append(f"  - _{note}_")
            lines.append("")

        weak_findings = cipher_data.get("weak_findings", [])
        if weak_findings:
            lines.append("### Weak cipher findings")
            lines.append("")
            for finding in weak_findings:
                port = finding.get("port", "")
                ciphers = ", ".join(finding.get("ciphers", []))
                lines.append(
                    f"- **{finding.get('category')}** ({finding.get('severity')}) on port {port}: "
                    f"{ciphers}"
                )
                rationale = finding.get("rationale")
                if rationale:
                    lines.append(f"  - {rationale}")
            lines.append("")

        lines.extend(["---", ""])
        return lines

    def _generate_http_section(self, http_data: Dict[str, Any]) -> List[str]:
        """Generate HTTP analysis section"""
        lines = [
            "## HTTP/HTTPS Analysis",
            ""
        ]
        
        probes = http_data.get("probes", [])
        for probe in probes:
            if not isinstance(probe, dict):
                continue

            host = probe.get("host", "unknown")
            port = probe.get("port", "unknown")
            protocol = "HTTPS" if probe.get("use_tls") else "HTTP"
            
            lines.append(f"### {protocol} on {host}:{port}")
            
            if probe.get("error"):
                lines.extend([
                    f"❌ **Error**: {probe['error']}",
                    ""
                ])
                continue
            
            result = probe.get("result") or {}
            final = result.get("final") or {}
            
            if final:
                status = final.get("status_code", "Unknown")
                lines.append(f"- **Final Status**: {status}")

                # Classification per probe
                cls = probe.get("classification", {})
                if cls:
                    role = cls.get("role") or cls.get("classification")
                    provider = cls.get("provider") or "unknown"
                    conf = cls.get("confidence", "unknown")
                    role_display = role.replace('-', ' ') if isinstance(role, str) else role
                    lines.append(f"- **Environment**: {role_display} via {provider} ({conf})")
                
                # Security headers
                if "security_headers" in probe:
                    sec_headers = probe["security_headers"]
                    present = sec_headers.get("present", [])
                    missing = sec_headers.get("missing", [])
                    
                    lines.extend([
                        f"- **Security Headers Present**: {len(present)}/{len(present) + len(missing)}",
                        f"  - Present: {', '.join(present) if present else 'None'}",
                        f"  - Missing: {', '.join(missing) if missing else 'None'}"
                    ])
                
                # WAF/CDN detection
                if "waf_cdn" in probe:
                    waf_services = probe["waf_cdn"].get("services", [])
                    if waf_services:
                        lines.append(f"- **WAF/CDN**: {', '.join(waf_services)}")

                # Title/body fingerprint (if present)
                if "title" in final:
                    lines.append(f"- **Title**: {final['title']}")
                if "body_sha256" in final:
                    lines.append(f"- **Body Hash**: {final['body_sha256']}")

            lines.append("")
        
        return lines
    
    def _generate_security_section(self, security_data: Dict[str, Any]) -> List[str]:
        """Generate security analysis section"""
        lines = [
            "## Security Analysis",
            ""
        ]
        
        score = security_data.get("score") or (security_data.get("security_headers") or {}).get("score")
        if score:
            lines.extend([
                f"### Overall Security Score: {score.get('grade', 'Unknown')} ({score.get('percentage', 0):.1f}%)",
                ""
            ])

        headers = security_data.get("security_headers", {})
        present = headers.get("present", [])
        missing = headers.get("missing", [])
        if present:
            lines.append(f"- **Present Headers**: {', '.join(present)}")
        if missing:
            lines.append(f"- **Missing Headers**: {', '.join(missing)}")
        if present or missing:
            lines.append("")

        if "waf_cdn" in security_data and security_data["waf_cdn"].get("services"):
            lines.append(f"- **Detected Protection Services**: {', '.join(security_data['waf_cdn']['services'])}")
            lines.append("")
        
        return lines
    
    def _generate_recommendations_section(self, scan_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations section"""
        lines = [
            "## Recommendations",
            ""
        ]
        
        recommendations = []
        
        if "backport_analysis" in scan_data:
            backport_rec = scan_data["backport_analysis"].get("recommendation")
            if backport_rec:
                recommendations.append(backport_rec)

        # Collect recommendations from various analyses
        if "security_analysis" in scan_data:
            for analysis_type, analysis in scan_data["security_analysis"].items():
                if isinstance(analysis, dict) and "recommendations" in analysis:
                    recommendations.extend(analysis["recommendations"])
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        else:
            lines.extend([
                "No specific recommendations available.",
                ""
            ])
        
        return lines
    
    def _generate_technical_details(self, scan_data: Dict[str, Any]) -> List[str]:
        """Generate technical details section"""
        lines = [
            "## Technical Details",
            "",
            "<details><summary>Click to expand raw scan data</summary>",
            "",
            "```json",
        ]
        
        # Add relevant technical details (but not the full scan data)
        import json
        technical_data = {
            "scan_metadata": scan_data.get("metadata", {}),
            "signature_info": scan_data.get("signature_info", {})
        }
        
        lines.append(json.dumps(technical_data, indent=2))
        lines.extend([
            "```",
            "",
            "</details>",
            ""
        ])
        
        return lines
