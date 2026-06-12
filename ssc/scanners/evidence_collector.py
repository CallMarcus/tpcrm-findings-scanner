"""Evidence collection for compensating controls"""

from typing import Dict, Any, List, Optional
from ..analyzers import SecurityHeaderAnalyzer, WAFCDNDetector, ServerTokenAnalyzer

class EvidenceCollector:
    """Collect and organize evidence for security assessments"""
    
    def __init__(self):
        self.security_analyzer = SecurityHeaderAnalyzer()
        self.waf_detector = WAFCDNDetector()
        self.token_analyzer = ServerTokenAnalyzer()
    
    def collect_comprehensive_evidence(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Collect all available evidence from scan data"""
        evidence = {
            "security_controls": [],
            "backport_indicators": [],
            "protection_services": [],
            "certificate_info": [],
            "service_versions": []
        }
        
        # Collect HTTP security evidence
        http_analysis = scan_data.get("http_analysis", {})
        for probe in http_analysis.get("probes", []):
            evidence["security_controls"].extend(
                self._extract_security_evidence(probe)
            )
            evidence["protection_services"].extend(
                self._extract_protection_evidence(probe)
            )
        
        # Collect TLS certificate evidence
        tls_analysis = scan_data.get("tls_analysis", {})
        if tls_analysis.get("default_handshake", {}).get("ok"):
            evidence["certificate_info"].extend(
                self._extract_certificate_evidence(tls_analysis)
            )
        
        # Collect server version and backport evidence
        for probe in http_analysis.get("probes", []):
            final_headers = probe.get("result", {}).get("final", {}).get("headers", {})
            server_header = self._get_server_header(final_headers)
            if server_header:
                server_analysis = self.token_analyzer.analyze_server_header(server_header)
                evidence["backport_indicators"].extend(
                    self._extract_backport_evidence(server_analysis)
                )
                evidence["service_versions"].extend(
                    self._extract_version_evidence(server_analysis)
                )
        
        return evidence
    
    def _extract_security_evidence(self, probe_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract security control evidence from HTTP probe"""
        evidence = []
        
        security_headers = probe_data.get("security_headers", {})
        present_headers = security_headers.get("present", [])
        
        for header in present_headers:
            values = security_headers.get("values", {}).get(header, ["present"])
            evidence.append({
                "type": "security_header",
                "control": header,
                "value": "; ".join(values),
                "strength": "implemented",
                "description": f"Security header '{header}' is properly configured"
            })
        
        return evidence
    
    def _extract_protection_evidence(self, probe_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract WAF/CDN protection evidence"""
        evidence = []
        
        waf_cdn = probe_data.get("waf_cdn", {})
        services = waf_cdn.get("services", [])
        
        for service in services:
            evidence_markers = waf_cdn.get("evidence", {}).get(service, [])
            evidence.append({
                "type": "protection_service",
                "service": service,
                "markers": evidence_markers,
                "strength": "active",
                "description": f"WAF/CDN service '{service}' detected and active"
            })
        
        return evidence
    
    def _extract_certificate_evidence(self, tls_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract TLS certificate evidence"""
        evidence = []
        
        default_handshake = tls_data.get("default_handshake", {})
        certificate = default_handshake.get("certificate", {})
        
        if certificate:
            evidence.append({
                "type": "tls_certificate",
                "issuer": str(certificate.get("issuer", "unknown")),
                "subject": str(certificate.get("subject", "unknown")),
                "expires": certificate.get("notAfter", "unknown"),
                "strength": "valid",
                "description": "Valid TLS certificate installed"
            })
        
        # TLS version support
        tls_version = default_handshake.get("tls_version")
        if tls_version:
            evidence.append({
                "type": "tls_version",
                "version": tls_version,
                "cipher": str(default_handshake.get("cipher", ["unknown"])[0]),
                "strength": "modern" if tls_version in ["TLSv1.2", "TLSv1.3"] else "legacy",
                "description": f"TLS {tls_version} support confirmed"
            })
        
        return evidence
    
    def _extract_backport_evidence(self, server_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract backport evidence from server analysis"""
        evidence = []
        
        backports = server_analysis.get("backports", [])
        for backport in backports:
            evidence.append({
                "type": "backport_indicator", 
                "distribution": backport["distribution"],
                "indicator": backport["indicator"],
                "pattern": backport["pattern"],
                "strength": "strong" if backport["distribution"] in ["debian", "redhat"] else "moderate",
                "description": f"Backport indicator for {backport['distribution']} detected"
            })
        
        return evidence
    
    def _extract_version_evidence(self, server_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract software version evidence"""
        evidence = []
        
        software = server_analysis.get("software", [])
        for sw in software:
            evidence.append({
                "type": "software_version",
                "software": sw["name"],
                "version": sw["version"],
                "raw_match": sw["raw_match"],
                "strength": "confirmed" if sw["version"] != "unknown" else "partial",
                "description": f"{sw['name']} version {sw['version']} identified"
            })
        
        return evidence
    
    def _get_server_header(self, headers: Dict[str, List[str]]) -> Optional[str]:
        """Extract Server header value"""
        for key, values in headers.items():
            if key.lower() == "server" and values:
                return values[0]
        return None
    
    def assess_evidence_strength(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall strength of collected evidence"""
        strength_scores = {
            "strong": 3,
            "active": 3,
            "implemented": 3,
            "valid": 3,
            "confirmed": 3,
            "modern": 2,
            "moderate": 2,
            "partial": 1,
            "legacy": 1
        }
        
        total_score = 0
        evidence_count = 0
        
        for category, items in evidence.items():
            for item in items:
                strength = item.get("strength", "unknown")
                total_score += strength_scores.get(strength, 0)
                evidence_count += 1
        
        if evidence_count == 0:
            return {"overall": "none", "score": 0, "confidence": "low"}
        
        average_score = total_score / evidence_count
        
        if average_score >= 2.5:
            overall = "strong"
            confidence = "high"
        elif average_score >= 1.5:
            overall = "moderate"
            confidence = "medium"
        else:
            overall = "weak"
            confidence = "low"
        
        return {
            "overall": overall,
            "score": round(average_score, 2),
            "confidence": confidence,
            "evidence_count": evidence_count
        }