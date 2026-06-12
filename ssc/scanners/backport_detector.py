"""Backport detection for Linux systems with static version numbers"""

import re
from typing import Dict, Any, List, Optional, Tuple
from ..analyzers.server_tokens import ServerTokenAnalyzer

class BackportDetector:
    """Specialized detector for systems with backported security patches"""
    
    def __init__(self):
        self.token_analyzer = ServerTokenAnalyzer()
    
    def analyze_target(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive backport analysis of scan target"""
        results = {
            "backport_evidence": [],
            "software_versions": [],
            "distribution_indicators": [],
            "confidence": "unknown",
            "recommendation": ""
        }
        
        # Analyze HTTP server headers
        http_analysis = scan_data.get("http_analysis", {})
        for probe in http_analysis.get("probes", []):
            if not isinstance(probe, dict):
                continue

            server_header = self._extract_server_header(probe)
            if server_header:
                server_analysis = self.token_analyzer.analyze_server_header(server_header)
                self._merge_server_analysis(results, server_analysis, probe.get("port"))
        
        # Analyze service banners
        port_data = scan_data.get("port_scan", {})
        banners = port_data.get("banners", {})
        for port, banner in banners.items():
            banner_analysis = self._analyze_banner_for_backports(banner, port)
            if banner_analysis:
                results["backport_evidence"].extend(banner_analysis)
        
        # Assess overall confidence
        results["confidence"] = self._assess_backport_confidence(results)
        results["recommendation"] = self._generate_recommendation(results)
        
        return results
    
    def _extract_server_header(self, probe_data: Optional[Dict[str, Any]]) -> Optional[str]:
        """Extract Server header from HTTP probe"""
        if not isinstance(probe_data, dict):
            return None

        result = probe_data.get("result") or {}
        final_response = result.get("final") or {}
        headers = final_response.get("headers", {})

        for key, values in headers.items():
            if key.lower() == "server" and values:
                return values[0]
        return None
    
    def _merge_server_analysis(self, results: Dict[str, Any], 
                             server_analysis: Dict[str, Any], port: int):
        """Merge server analysis results into main results"""
        
        # Add backport evidence
        for backport in server_analysis.get("backports", []):
            results["backport_evidence"].append({
                **backport,
                "source": f"http_server_header_port_{port}",
                "type": "server_header"
            })
        
        # Add software versions
        for software in server_analysis.get("software", []):
            results["software_versions"].append({
                **software,
                "source": f"http_server_header_port_{port}",
                "type": "server_header"
            })
        
        # Add distribution indicators
        analysis_type = server_analysis.get("analysis", "unknown")
        if analysis_type == "backported_packages":
            distros = list(set(b["distribution"] for b in server_analysis.get("backports", [])))
            for distro in distros:
                if distro not in [d["distribution"] for d in results["distribution_indicators"]]:
                    results["distribution_indicators"].append({
                        "distribution": distro,
                        "source": f"http_server_header_port_{port}",
                        "confidence": "high"
                    })
    
    def _analyze_banner_for_backports(self, banner: str, port: int) -> List[Dict[str, Any]]:
        """Analyze service banner for backport indicators"""
        backport_evidence = []
        
        # SSH version patterns (common on port 22)
        if port == 22:
            ssh_patterns = [
                (r"OpenSSH_[\d\.]+p\d+\s+Ubuntu", "ubuntu"),
                (r"OpenSSH_[\d\.]+\s+Debian", "debian"),
                (r"OpenSSH_[\d\.]+p\d+\s+Debian", "debian"),
                (r"protocol\s+2\.0", "ssh_protocol"),
            ]
            
            for pattern, distro_hint in ssh_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    backport_evidence.append({
                        "distribution": distro_hint if distro_hint != "ssh_protocol" else "unknown",
                        "indicator": re.search(pattern, banner, re.IGNORECASE).group(0),
                        "pattern": pattern,
                        "source": f"ssh_banner_port_{port}",
                        "type": "service_banner"
                    })
        
        # SMTP patterns (ports 25, 587, etc.)
        elif port in [25, 587, 465]:
            smtp_patterns = [
                (r"Postfix.*Ubuntu", "ubuntu"),
                (r"Postfix.*Debian", "debian"),
                (r"Exim.*Debian", "debian"),
                (r"Sendmail.*Red.*Hat", "redhat"),
            ]
            
            for pattern, distro in smtp_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    match = re.search(pattern, banner, re.IGNORECASE)
                    backport_evidence.append({
                        "distribution": distro,
                        "indicator": match.group(0),
                        "pattern": pattern,
                        "source": f"smtp_banner_port_{port}",
                        "type": "service_banner"
                    })
        
        # FTP patterns (port 21)
        elif port == 21:
            ftp_patterns = [
                (r"vsftpd.*Ubuntu", "ubuntu"),
                (r"ProFTPD.*Debian", "debian"),
                (r"Pure-FTPd.*deb", "debian"),
            ]
            
            for pattern, distro in ftp_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    match = re.search(pattern, banner, re.IGNORECASE)
                    backport_evidence.append({
                        "distribution": distro,
                        "indicator": match.group(0),
                        "pattern": pattern,
                        "source": f"ftp_banner_port_{port}",
                        "type": "service_banner"
                    })
        
        return backport_evidence
    
    def _assess_backport_confidence(self, results: Dict[str, Any]) -> str:
        """Assess confidence level of backport detection"""
        evidence_count = len(results["backport_evidence"])
        distro_count = len(results["distribution_indicators"])
        
        if evidence_count >= 3 and distro_count >= 1:
            return "high"
        elif evidence_count >= 2 or distro_count >= 1:
            return "medium"
        elif evidence_count >= 1:
            return "low"
        else:
            return "none"
    
    def _generate_recommendation(self, results: Dict[str, Any]) -> str:
        """Generate recommendation based on backport analysis"""
        confidence = results["confidence"]
        
        if confidence == "high":
            return ("Strong evidence of backported packages detected. This system likely receives "
                   "security patches without version number changes. Version-based vulnerability "
                   "scanning may produce false positives. Recommend manual verification of patch "
                   "levels through package manager or vendor advisories.")
        
        elif confidence == "medium":
            return ("Moderate evidence of backported packages detected. Consider investigating "
                   "patch management practices and verify security update status through system "
                   "package manager. Some version-based vulnerability findings may be false positives.")
        
        elif confidence == "low":
            return ("Limited evidence of backported packages. Standard version-based vulnerability "
                   "assessment may be appropriate, but consider verifying patch levels for critical "
                   "findings.")
        
        else:
            return ("No clear evidence of backported packages detected. Standard vulnerability "
                   "assessment based on version numbers should be reliable for this system.")
    
    def generate_evidence_report(self, results: Dict[str, Any], target_ip: str) -> Dict[str, Any]:
        """Generate structured evidence report for compensating controls"""
        return {
            "target": target_ip,
            "finding_type": "backport_detection",
            "confidence": results["confidence"],
            "evidence_summary": {
                "backport_indicators": len(results["backport_evidence"]),
                "software_versions": len(results["software_versions"]),
                "distributions_detected": len(results["distribution_indicators"])
            },
            "distributions": [d["distribution"] for d in results["distribution_indicators"]],
            "detailed_evidence": results["backport_evidence"],
            "recommendation": results["recommendation"],
            "suitable_for_compensating_controls": results["confidence"] in ["high", "medium"]
        }