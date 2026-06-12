"""CSV evidence report generation"""

import csv
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from ..utils.files import open_unique

class CSVReporter:
    """Generate CSV evidence reports for compensating controls"""
    
    def __init__(self, output_dir: str = "outputs/evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_evidence_report(self, evidence_data: List[Dict[str, Any]], 
                               target_ip: str, finding_type: str = "general") -> str:
        """Generate CSV evidence report"""
        timestamp = int(time.time())
        
        filename = f"evidence_{finding_type}_{target_ip.replace(':', '_')}_{timestamp}.csv"
        handle, filepath = open_unique(str(self.output_dir / filename), newline='')

        if not evidence_data:
            # Create empty report with headers
            with handle as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "target_ip", "finding_type", "evidence_type",
                    "description", "value", "confidence", "notes"
                ])
            return filepath

        # Write evidence data
        with handle as f:
            fieldnames = self._get_fieldnames(evidence_data)
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for evidence in evidence_data:
                # Add metadata to each row
                evidence.update({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "target_ip": target_ip,
                    "finding_type": finding_type
                })
                writer.writerow(evidence)

        return filepath

    def generate_backport_evidence(self, backport_results: Dict[str, Any],
                                 target_ip: str) -> str:
        """Generate CSV evidence report specifically for backport detection"""
        evidence_data = []

        for backport in backport_results.get("backport_evidence", []):
            evidence_data.append({
                "evidence_type": "backport_indicator",
                "description": f"Backport indicator found for {backport.get('distribution', 'unknown')}",
                "value": backport.get("indicator", ""),
                "confidence": "high" if backport.get("distribution") in ["debian", "redhat"] else "medium",
                "notes": f"Source: {backport.get('source', 'unknown')}; Pattern: {backport.get('pattern', '')}"
            })

        for sw in backport_results.get("software_versions", []):
            evidence_data.append({
                "evidence_type": "software_version",
                "description": f"{sw.get('name', 'software')} version detected",
                "value": f"{sw.get('name', 'unknown')} {sw.get('version', 'unknown')}",
                "confidence": "high" if sw.get("version") != "unknown" else "low",
                "notes": f"Source: {sw.get('source', 'unknown')}; Raw match: {sw.get('raw_match', '')}"
            })

        confidence = backport_results.get("confidence", "unknown")
        if backport_results.get("recommendation"):
            evidence_data.append({
                "evidence_type": "recommendation",
                "description": "Backport analysis recommendation",
                "value": backport_results["recommendation"],
                "confidence": confidence,
                "notes": f"Overall confidence: {confidence}"
            })

        return self.generate_evidence_report(evidence_data, target_ip, "backport_detection")
    
    def generate_security_evidence(self, security_analysis: Dict[str, Any], 
                                 target_ip: str) -> str:
        """Generate CSV evidence report for security controls"""
        evidence_data = []
        
        # Security headers evidence
        if "security_headers" in security_analysis:
            headers = security_analysis["security_headers"]
            for header in headers.get("present", []):
                values = headers.get("values", {}).get(header, ["present"])
                evidence_data.append({
                    "evidence_type": "security_header",
                    "description": f"Security header present: {header}",
                    "value": "; ".join(values),
                    "confidence": "high",
                    "notes": "Security header properly configured"
                })
        
        # WAF/CDN evidence
        if "waf_cdn" in security_analysis:
            waf = security_analysis["waf_cdn"]
            for service in waf.get("services", []):
                evidence_list = waf.get("evidence", {}).get(service, [])
                evidence_data.append({
                    "evidence_type": "waf_cdn_service",
                    "description": f"WAF/CDN service detected: {service}",
                    "value": service,
                    "confidence": "high",
                    "notes": f"Evidence: {'; '.join(evidence_list)}"
                })
        
        return self.generate_evidence_report(evidence_data, target_ip, "security_controls")
    
    def generate_batch_summary_csv(self, batch_results: Dict[str, Any], 
                                 batch_name: str = "batch") -> str:
        """Generate CSV summary for batch scan results"""
        timestamp = int(time.time())
        
        filename = f"batch_summary_{batch_name}_{timestamp}.csv"

        results = batch_results.get("results", [])
        if not results:
            return str(self.output_dir / filename)

        handle, filepath = open_unique(str(self.output_dir / filename), newline='')
        with handle as f:
            fieldnames = [
                "target_ip", "scan_success", "open_port_count", "web_services",
                "tls_enabled", "security_score", "waf_cdn_services", "backport_indicators",
                "scan_timestamp", "notes"
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Extract summary data for each target
                summary_row = self._extract_summary_row(result)
                writer.writerow(summary_row)

        return filepath
    
    def _get_fieldnames(self, evidence_data: List[Dict[str, Any]]) -> List[str]:
        """Get CSV fieldnames from evidence data"""
        base_fields = ["timestamp", "target_ip", "finding_type"]
        
        if not evidence_data:
            return base_fields + ["evidence_type", "description", "value", "confidence", "notes"]
        
        # Collect all unique fields from evidence data
        all_fields = set(base_fields)
        for evidence in evidence_data:
            all_fields.update(evidence.keys())
        
        # Order fields logically
        ordered_fields = base_fields.copy()
        for field in ["evidence_type", "description", "value", "confidence", "notes"]:
            if field in all_fields and field not in ordered_fields:
                ordered_fields.append(field)
        
        # Add remaining fields
        for field in sorted(all_fields - set(ordered_fields)):
            ordered_fields.append(field)
        
        return ordered_fields
    
    def _extract_summary_row(self, scan_result: Dict[str, Any]) -> Dict[str, str]:
        """Extract summary data for CSV row from scan result"""
        target_ip = scan_result.get("target_ip", "unknown")
        success = scan_result.get("success", False)
        
        # Port information
        open_ports = scan_result.get("port_scan", {}).get("open_ports", [])
        open_port_count = len(open_ports)
        
        # Web services
        web_services = []
        http_analysis = scan_result.get("http_analysis", {})
        for probe in http_analysis.get("probes", []):
            if probe.get("result", {}).get("final", {}).get("status_code"):
                port = probe.get("port", "unknown")
                protocol = "HTTPS" if probe.get("use_tls") else "HTTP"
                web_services.append(f"{protocol}:{port}")
        
        # TLS
        tls_enabled = "yes" if scan_result.get("tls_analysis", {}).get("default_handshake", {}).get("ok") else "no"
        
        # Security score
        security_score = scan_result.get("security_analysis", {}).get("score", {}).get("percentage", 0)
        
        # WAF/CDN
        waf_services = scan_result.get("security_analysis", {}).get("waf_cdn", {}).get("services", [])
        
        # Backport indicators
        backport_analysis = scan_result.get("backport_analysis", {}) or {}
        backport_distros = list({
            item.get("distribution", "unknown")
            for item in backport_analysis.get("distribution_indicators", [])
        })
        if not backport_distros:
            backport_distros = list({
                item.get("distribution", "unknown")
                for item in backport_analysis.get("backport_evidence", [])
            })
        
        return {
            "target_ip": target_ip,
            "scan_success": "yes" if success else "no",
            "open_port_count": str(open_port_count),
            "web_services": "; ".join(web_services),
            "tls_enabled": tls_enabled,
            "security_score": f"{security_score:.1f}%",
            "waf_cdn_services": "; ".join(waf_services),
            "backport_indicators": "; ".join(backport_distros),
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "notes": scan_result.get("notes", "")
        }