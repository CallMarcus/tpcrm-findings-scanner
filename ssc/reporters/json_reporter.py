"""JSON report generation"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from ..utils.files import open_unique

class JSONReporter:
    """Generate structured JSON reports"""
    
    def __init__(self, output_dir: str = "outputs/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, scan_data: Dict[str, Any], target_ip: str) -> str:
        """Generate comprehensive JSON scan report"""
        timestamp = int(time.time())
        
        # Build base report
        report = {
            "metadata": {
                "target_ip": target_ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "timestamp_unix": timestamp,
                "report_version": "2.0",
                "scanner": "tpcrm-findings-scanner"
            },
            "scan_results": scan_data
        }

        # Add compact summary for downstream parsing
        try:
            summary: Dict[str, Any] = {}
            # Environment classification
            classification = (scan_data.get("security_analysis", {}) or {}).get("classification", {}) or {}
            if classification:
                summary["environment"] = {
                    "classification": classification.get("classification"),
                    "provider": classification.get("provider"),
                    "role": classification.get("role"),
                    "confidence": classification.get("confidence"),
                }
            # Open ports
            open_ports = (scan_data.get("port_scan", {}) or {}).get("open_ports", []) or []
            summary["open_port_count"] = len(open_ports)
            summary["open_ports"] = open_ports
            # Web services detected
            web_services = []
            probes = (scan_data.get("http_analysis", {}) or {}).get("probes", []) or []
            for p in probes:
                final = (p.get("result", {}) or {}).get("final", {}) or {}
                if final.get("status_code") is not None:
                    web_services.append(f"HTTP{'S' if p.get('use_tls') else ''} {p.get('port')}")
            # Deduplicate while preserving order
            seen = set()
            web_services_unique = []
            for s in web_services:
                if s not in seen:
                    seen.add(s)
                    web_services_unique.append(s)
            summary["web_services"] = web_services_unique

            header_score = (scan_data.get("security_analysis", {}) or {}).get("score")
            if not header_score:
                header_score = (
                    (scan_data.get("security_analysis", {}) or {})
                    .get("security_headers", {})
                    .get("score")
                )
            if header_score:
                summary["security_score"] = {
                    "grade": header_score.get("grade"),
                    "percentage": header_score.get("percentage"),
                }

            backport = scan_data.get("backport_analysis", {}) or {}
            if backport:
                summary["backport_confidence"] = backport.get("confidence")

            evidence = scan_data.get("evidence", {}) or {}
            assessment = evidence.get("assessment", {}) or {}
            if assessment:
                summary["evidence_assessment"] = {
                    "overall": assessment.get("overall"),
                    "confidence": assessment.get("confidence"),
                    "evidence_count": assessment.get("evidence_count"),
                }

            narrative = scan_data.get("remediation_narrative", {}) or {}
            if narrative:
                summary["remediation_narrative"] = {
                    "summary": narrative.get("summary"),
                    "recommended_actions": narrative.get("recommended_actions", []),
                    "evidence_bullets": narrative.get("evidence_bullets", []),
                    "suitable_for_remediation_response": narrative.get(
                        "suitable_for_remediation_response", False
                    ),
                }

            origin_discovery = scan_data.get("origin_discovery", {}) or {}
            if origin_discovery:
                discovery_summary = origin_discovery.get("summary", {}) or {}
                summary["origin_discovery"] = {
                    "query_hostname": discovery_summary.get("query_hostname"),
                    "has_dns_chain": discovery_summary.get("has_dns_chain", False),
                    "edge_detected_in_chain": discovery_summary.get("edge_detected_in_chain", False),
                    "hint_count": discovery_summary.get("hint_count", 0),
                    "top_hints": discovery_summary.get("top_hints", []),
                    "redirect_host_count": discovery_summary.get("redirect_host_count", 0),
                }

            cipher_enum = scan_data.get("cipher_enumeration", {}) or {}
            if cipher_enum:
                cipher_sum = cipher_enum.get("summary", {}) or {}
                summary["cipher_summary"] = {
                    "accepted_total": cipher_sum.get("accepted_total", 0),
                    "weak_count": cipher_sum.get("weak_count", 0),
                    "categories": cipher_sum.get("categories", []),
                }

            report["summary"] = summary
        except Exception as exc:
            # Deliberately broad: summary derivation walks arbitrary scan data
            # shapes and must never break report generation. Record the
            # failure instead of hiding it.
            report["summary_error"] = f"{type(exc).__name__}: {exc}"
        
        # Generate filename and write report
        filename = f"scan_{target_ip.replace(':', '_')}_{timestamp}.json"
        handle, filepath = open_unique(str(self.output_dir / filename))
        with handle as f:
            json.dump(report, f, indent=2, default=str)

        return filepath

    def generate_evidence_report(self, evidence_data: Dict[str, Any],
                               target_ip: str, finding_type: str = "general") -> str:
        """Generate evidence report for compensating controls"""
        timestamp = int(time.time())
        
        report = {
            "metadata": {
                "target_ip": target_ip,
                "finding_type": finding_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "timestamp_unix": timestamp,
                "report_version": "2.0",
                "report_type": "evidence"
            },
            "evidence": evidence_data,
            "summary": {
                "evidence_count": len(evidence_data.get("items", [])),
                "strength": evidence_data.get("strength", "unknown"),
                "recommendations": evidence_data.get("recommendations", [])
            }
        }
        
        filename = f"evidence_{finding_type}_{target_ip.replace(':', '_')}_{timestamp}.json"
        handle, filepath = open_unique(str(self.output_dir / filename))
        with handle as f:
            json.dump(report, f, indent=2, default=str)

        return filepath
    
    def generate_batch_summary(self, batch_results: Dict[str, Any], 
                             batch_name: str = "batch") -> str:
        """Generate summary report for batch scans"""
        timestamp = int(time.time())
        
        summary = {
            "metadata": {
                "batch_name": batch_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "timestamp_unix": timestamp,
                "report_version": "2.0",
                "report_type": "batch_summary"
            },
            "summary": {
                "total_targets": len(batch_results.get("targets", [])),
                "successful_scans": len([r for r in batch_results.get("results", []) if r.get("success")]),
                "failed_scans": len([r for r in batch_results.get("results", []) if not r.get("success")]),
                "total_open_ports": sum(
                    len((r.get("port_scan") or {}).get("open_ports") or [])
                    for r in batch_results.get("results", [])
                ),
                "unique_services": len(set(
                    service for r in batch_results.get("results", [])
                    for service in ((r.get("security_analysis") or {}).get("waf_cdn") or {}).get("services", [])
                ))
            },
            "results": batch_results
        }
        
        filename = f"batch_summary_{batch_name}_{timestamp}.json"
        handle, filepath = open_unique(str(self.output_dir / filename))
        with handle as f:
            json.dump(summary, f, indent=2, default=str)

        return filepath
