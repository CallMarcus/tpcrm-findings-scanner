"""Server token and banner analysis"""

import re
from typing import Dict, List, Any, Optional

class ServerTokenAnalyzer:
    """Analyzer for server tokens and banners to identify systems and detect backports"""
    
    # Common Linux distributions with backported packages
    BACKPORT_INDICATORS = {
        "debian": [
            r"debian", r"deb\d+", r"ubuntu", r"~deb\d+", r"\+deb\d+",
            r"bpo\d+", r"~bpo\d+\+\d+"
        ],
        "redhat": [
            r"el\d+", r"rhel\d+", r"centos", r"\.el\d+_\d+",
            r"fc\d+", r"fedora", r"\.fc\d+\."
        ],
        "suse": [
            r"suse", r"sles\d+", r"opensuse", r"\.suse\.",
            r"leap", r"tumbleweed"
        ]
    }
    
    # Server software patterns
    SERVER_PATTERNS = {
        "apache": r"apache[/\s]?([\d\.]+)?",
        "nginx": r"nginx[/\s]?([\d\.]+)?", 
        "iis": r"microsoft-iis[/\s]?([\d\.]+)?",
        "tomcat": r"tomcat[/\s]?([\d\.]+)?",
        "jetty": r"jetty[/\s]?([\d\.]+)?",
        "nodejs": r"node\.js[/\s]?([\d\.]+)?",
        "python": r"python[/\s]?([\d\.]+)?",
        "php": r"php[/\s]?([\d\.]+)?",
        "openssl": r"openssl[/\s]?([\d\.]+)?",
        "mod_ssl": r"mod_ssl[/\s]?([\d\.]+)?"
    }
    
    def analyze_server_header(self, server_header: str) -> Dict[str, Any]:
        """Analyze Server header for software versions and backport indicators"""
        if not server_header:
            return {"software": [], "backports": [], "raw": "", "analysis": "no_server_header"}
        
        server_lower = server_header.lower()
        
        # Extract software components
        software = self._extract_software(server_lower)
        
        # Check for backport indicators
        backports = self._detect_backports(server_lower)
        
        # Determine analysis type
        analysis_type = self._determine_analysis_type(software, backports, server_lower)
        
        return {
            "software": software,
            "backports": backports,
            "raw": server_header,
            "analysis": analysis_type,
            "recommendations": self._get_recommendations(software, backports, analysis_type)
        }
    
    def _extract_software(self, server_header: str) -> List[Dict[str, Any]]:
        """Extract software names and versions from server header"""
        software = []
        
        for name, pattern in self.SERVER_PATTERNS.items():
            matches = re.finditer(pattern, server_header, re.IGNORECASE)
            for match in matches:
                version = match.group(1) if match.group(1) else "unknown"
                software.append({
                    "name": name,
                    "version": version,
                    "raw_match": match.group(0)
                })
        
        return software
    
    def _detect_backports(self, server_header: str) -> List[Dict[str, Any]]:
        """Detect backport indicators in server header"""
        backports = []
        
        for distro, patterns in self.BACKPORT_INDICATORS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, server_header, re.IGNORECASE)
                for match in matches:
                    backports.append({
                        "distribution": distro,
                        "indicator": match.group(0),
                        "pattern": pattern,
                        "position": match.span()
                    })
        
        return backports
    
    def _determine_analysis_type(self, software: List[Dict], backports: List[Dict], 
                                server_header: str) -> str:
        """Determine the type of analysis result"""
        if not server_header.strip():
            return "no_server_header"
        elif backports:
            return "backported_packages"
        elif software:
            return "standard_software"
        elif any(keyword in server_header for keyword in ["cloudflare", "cloudfront", "akamai"]):
            return "edge_service"
        else:
            return "unknown_server"
    
    def _get_recommendations(self, software: List[Dict], backports: List[Dict], 
                           analysis_type: str) -> List[str]:
        """Get recommendations based on server analysis"""
        recommendations = []
        
        if analysis_type == "backported_packages":
            recommendations.extend([
                "Server appears to use backported security patches",
                "Version numbers may not reflect actual security patch level",
                "Verify patch status through package manager or vendor documentation",
                "Consider this evidence for compensating controls in vulnerability reports"
            ])
        elif analysis_type == "standard_software":
            recommendations.extend([
                "Verify software versions against current security advisories",
                "Check for available security updates",
                "Consider hiding detailed version information in Server headers"
            ])
        elif analysis_type == "edge_service":
            recommendations.extend([
                "Server appears to be behind CDN/WAF service",
                "Origin server details may be obscured",
                "Focus security assessment on origin server if accessible"
            ])
        elif analysis_type == "no_server_header":
            recommendations.extend([
                "Server header is missing or empty",
                "This may indicate security hardening or proxy/WAF filtering",
                "Additional reconnaissance may be needed to identify server software"
            ])
        
        return recommendations
    
    def generate_evidence_summary(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate evidence summary for compensating controls documentation"""
        return {
            "finding_type": "server_identification",
            "analysis_type": analysis_result.get("analysis", "unknown"),
            "has_backport_indicators": len(analysis_result.get("backports", [])) > 0,
            "identified_software": [s["name"] for s in analysis_result.get("software", [])],
            "backport_distributions": list(set(b["distribution"] for b in analysis_result.get("backports", []))),
            "evidence_strength": self._assess_evidence_strength(analysis_result),
            "raw_server_header": analysis_result.get("raw", "")
        }
    
    def _assess_evidence_strength(self, analysis_result: Dict[str, Any]) -> str:
        """Assess the strength of backport evidence"""
        backports = analysis_result.get("backports", [])
        software = analysis_result.get("software", [])
        
        if len(backports) >= 2:
            return "strong"
        elif len(backports) == 1 and len(software) >= 1:
            return "moderate" 
        elif len(backports) == 1:
            return "weak"
        else:
            return "none"