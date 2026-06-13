#!/usr/bin/env python3
"""
TPCRM Findings Scanner - CLI for investigating TPCRM platform findings and evidence collection
"""

import argparse
import json
import sys

import yaml
import time
import datetime
from datetime import timezone
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the package to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssc.config import Config
from ssc.scanners import PortScanner, TLSScanner, HTTPScanner, EvidenceCollector, BackportDetector, CipherEnumerator
from ssc.analyzers import (
    SecurityHeaderAnalyzer,
    WAFCDNDetector,
    ServerTokenAnalyzer,
    CloudGatewayClassifier,
    RemediationNarrativeGenerator,
    OriginDiscoveryAnalyzer,
    compare_scan_reports,
    format_scan_diff_text,
)
from ssc.analyzers.waf_cdn import DETECTION_PRIORITY, MANUFACTURERS
from ssc.reporters import JSONReporter, MarkdownReporter, CSVReporter
from ssc.scan_profiles import resolve_scan_options, list_profiles
from ssc.utils import (
    ScanTarget,
    parse_target_input,
    reverse_dns,
    scan_log,
    scan_log_session,
    begin_scan_session,
    record_scan_signature_session,
)

class SSCToolkit:
    """Main TPCRM Findings Scanner orchestrator (internal class name retained for compatibility)"""
    
    def __init__(self, config: Config):
        self.config = config
        self.port_scanner = PortScanner(config.scan)
        self.tls_scanner = TLSScanner(config.scan)
        self.cipher_enumerator = CipherEnumerator(config.scan)
        self.http_scanner = HTTPScanner(config.scan, config.signature)
        self.evidence_collector = EvidenceCollector()
        self.backport_detector = BackportDetector()
        
        # Analyzers
        self.security_analyzer = SecurityHeaderAnalyzer()
        self.waf_detector = WAFCDNDetector()
        self.token_analyzer = ServerTokenAnalyzer()
        self.classifier = CloudGatewayClassifier()
        self.narrative_generator = RemediationNarrativeGenerator()
        self.origin_discovery_analyzer = OriginDiscoveryAnalyzer(timeout=config.scan.timeout)
        
        # Reporters
        self.json_reporter = JSONReporter(os.path.join(config.output.base_dir, config.output.reports_dir))
        self.md_reporter = MarkdownReporter(os.path.join(config.output.base_dir, config.output.reports_dir))
        self.csv_reporter = CSVReporter(os.path.join(config.output.base_dir, config.output.evidence_dir))
    
    def scan_target(
        self,
        target_ip: str,
        host: Optional[str] = None,
        stealth: bool = False,
        ports: Optional[List[int]] = None,
        only_web: bool = False,
        skip_port_scan: bool = False,
        profile: str = "full",
        input_target: Optional[str] = None,
        cipher: bool = False,
    ) -> Dict[str, Any]:
        """Perform comprehensive scan of target"""
        display_target = input_target or target_ip
        scan_log(f"[+] Starting comprehensive scan of {display_target} ({target_ip})")

        scan_data = {
            "metadata": {
                "target_ip": target_ip,
                "input_target": input_target or target_ip,
                "host": host,
                "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
                "stealth_mode": stealth,
                "scanner_version": "2.0",
                "scan_profile": profile,
            },
            "signature_info": {
                "enabled": not stealth and self.config.signature.enabled,
                "user_agent": self.config.signature.stealth_user_agent if stealth else self.config.signature.user_agent,
                "contact": self.config.signature.contact_value if not stealth else None
            }
        }
        
        try:
            # Reverse DNS lookup
            scan_log("[*] Performing reverse DNS lookup...")
            ptr_name = reverse_dns(target_ip, timeout=self.config.scan.timeout)
            if ptr_name:
                scan_log(f"[+] Reverse DNS: {ptr_name}")
                scan_data["reverse_dns"] = ptr_name
            
            # Port scanning (optional)
            if skip_port_scan:
                # Synthesize port results based on provided list or common web ports
                assumed_ports = ports if ports else [80, 443, 8080, 8443]
                port_results = {"open_ports": assumed_ports, "banners": {}}
                scan_data["port_scan"] = port_results
                scan_log(f"[*] Skipping port scan. Assuming ports: {', '.join(map(str, assumed_ports))}")
            else:
                scan_log("[*] Scanning ports...")
                port_results = self.port_scanner.scan_with_banners(target_ip, ports)
                scan_data["port_scan"] = port_results
                scan_log(f"[+] Found {len(port_results['open_ports'])} open ports")
            
            # TLS analysis (if HTTPS likely available)
            https_candidate = 443 in port_results.get("open_ports", []) or (skip_port_scan and 443 in port_results.get("open_ports", []))
            if https_candidate:
                scan_log("[*] Analyzing TLS configuration...")
                tls_results = {}
                tls_results["default_handshake"] = self.tls_scanner.analyze_certificate(
                    target_ip, 443, server_name=host
                )
                tls_results["versions"] = self.tls_scanner.test_tls_versions(
                    target_ip, 443, server_name=host
                )
                
                # Calculate certificate expiry
                if tls_results["default_handshake"].get("ok"):
                    days_left = self.tls_scanner.get_certificate_expiry_days(tls_results["default_handshake"])
                    if days_left is not None:
                        tls_results["days_until_expiry"] = days_left
                
                scan_data["tls_analysis"] = tls_results
                scan_log("[+] TLS analysis complete")

            # Cipher-suite enumeration (optional, --cipher)
            if cipher:
                open_now = port_results.get("open_ports", [])
                tls_web_ports = [p for p in self.cipher_enumerator.WEB_TLS_PORTS if p in open_now]
                if tls_web_ports:
                    scan_log("[*] Enumerating TLS cipher suites...")
                    scan_data["cipher_enumeration"] = self.cipher_enumerator.enumerate_target(
                        target_ip, open_now, server_name=host
                    )
                    weak = scan_data["cipher_enumeration"].get("summary", {}).get("weak_count", 0)
                    scan_log(f"[+] Cipher enumeration complete: {weak} weak finding(s)")

            # HTTP/HTTPS analysis
            candidate_ports = port_results.get("open_ports", [])
            web_ports = [p for p in candidate_ports if p in (80, 443, 8080, 8443)] if only_web or candidate_ports else []
            if not only_web:
                # When not restricted, still prioritize web ports for HTTP analysis
                web_ports = [p for p in candidate_ports if p in (80, 443, 8080, 8443)]
            if web_ports:
                http_results = self._probe_web_services(
                    target_ip, host, scan_data, web_ports, stealth=stealth
                )
                scan_data["http_analysis"] = http_results
            
            # Comprehensive security analysis
            scan_log("[*] Performing security analysis...")
            security_analysis = {}
            
            # Aggregate security findings
            if "http_analysis" in scan_data:
                all_security_headers = []
                all_waf_detections = []
                
                for probe in scan_data["http_analysis"]["probes"]:
                    if probe.get("security_headers"):
                        all_security_headers.append(probe["security_headers"])
                    if probe.get("waf_cdn"):
                        all_waf_detections.append(probe["waf_cdn"])
                
                # Best security headers found
                if all_security_headers:
                    # Filter out None values and get best headers
                    valid_headers = [h for h in all_security_headers if h is not None]
                    if valid_headers:
                        best_headers = max(valid_headers, key=lambda x: len(x.get("present", [])))
                        security_analysis["security_headers"] = best_headers
                
                # Aggregate WAF/CDN detections (prefer highest-priority primary per probe)
                if all_waf_detections:
                    unique_services = set()
                    primary_candidates = []
                    for detection in all_waf_detections:
                        if not detection:
                            continue
                        unique_services.update(detection.get("services", []))
                        primary = detection.get("primary_service")
                        if primary:
                            primary_candidates.append(primary)
                    if unique_services:
                        waf_cdn = {"services": sorted(unique_services)}
                        if primary_candidates:
                            best_primary = max(
                                set(primary_candidates),
                                key=lambda vendor: (
                                    DETECTION_PRIORITY.get(vendor, 0),
                                    vendor,
                                ),
                            )
                            waf_cdn["primary_service"] = best_primary
                            manufacturer = MANUFACTURERS.get(best_primary)
                            if manufacturer:
                                waf_cdn["manufacturer"] = manufacturer
                        security_analysis["waf_cdn"] = waf_cdn

                self._apply_security_score(security_analysis)
            
            scan_data["security_analysis"] = security_analysis
            
            # Environment classification (aggregate)
            try:
                if "http_analysis" in scan_data:
                    overall = self.classifier.classify_overall(scan_data["http_analysis"].get("probes", []))
                    if overall:
                        scan_data["security_analysis"]["classification"] = overall
            except Exception as exc:
                # Broad on purpose (classifier walks arbitrary probe data),
                # but never silent.
                scan_log(f"[-] Classification aggregation error: {exc}")
            
            scan_log("[+] Scan completed successfully")
            return scan_data
            
        except Exception as e:
            scan_log(f"[-] Scan failed: {str(e)}")
            scan_data["error"] = str(e)
            return scan_data
    
    def _apply_security_score(self, security_analysis: Dict[str, Any]) -> None:
        """Promote nested header score to top-level security_analysis.score."""
        header_score = (security_analysis.get("security_headers") or {}).get("score")
        if header_score:
            security_analysis["score"] = header_score

    def attach_origin_discovery(
        self,
        scan_data: Dict[str, Any],
        host: Optional[str] = None,
        input_target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Attach origin discovery hints and DNS chain analysis to scan data."""
        try:
            scan_data["origin_discovery"] = self.origin_discovery_analyzer.analyze(
                scan_data,
                hostname=input_target,
                host=host,
            )
        except Exception as exc:
            scan_data["origin_discovery"] = {
                "dns_chain": {"hops": [], "error": str(exc)},
                "origin_hints": [],
                "edge_hostnames": [],
                "redirect_hosts": [],
                "summary": {"hint_count": 0, "top_hints": []},
                "error": str(exc),
            }
        return scan_data

    def attach_remediation_narrative(self, scan_data: Dict[str, Any], target_ip: str) -> Dict[str, Any]:
        """Generate ticket-ready remediation narrative and attach to scan data."""
        try:
            scan_data["remediation_narrative"] = self.narrative_generator.generate(scan_data, target_ip)
        except Exception as exc:
            scan_data["remediation_narrative"] = {
                "summary": f"Remediation narrative could not be generated: {exc}",
                "evidence_bullets": [],
                "recommended_actions": [],
                "suitable_for_remediation_response": False,
            }
        return scan_data

    def enrich_scan_data(
        self,
        scan_data: Dict[str, Any],
        target_ip: str,
        evidence: bool = False,
        backports: bool = False,
    ) -> Dict[str, Any]:
        """Attach evidence and/or backport analysis to scan results."""
        if backports or evidence:
            scan_log("[*] Analyzing for backported packages...")
            backport_results = self.backport_detector.analyze_target(scan_data)
            backport_results["evidence_report"] = self.backport_detector.generate_evidence_report(
                backport_results, target_ip
            )
            scan_data["backport_analysis"] = backport_results
            scan_log(f"[+] Backport analysis complete: {backport_results['confidence']} confidence")

        if evidence:
            scan_log("[*] Collecting compensating-controls evidence...")
            collected = self.evidence_collector.collect_comprehensive_evidence(scan_data)
            assessment = self.evidence_collector.assess_evidence_strength(collected)
            scan_data["evidence"] = {
                "items": collected,
                "assessment": assessment,
            }
            scan_log(
                f"[+] Evidence collection complete: {assessment.get('confidence', 'unknown')} confidence "
                f"({assessment.get('evidence_count', 0)} items)"
            )

        return scan_data

    def generate_evidence_reports(self, scan_data: Dict[str, Any], target_ip: str) -> Dict[str, str]:
        """Write evidence CSV/JSON artifacts from enriched scan data."""
        reports: Dict[str, str] = {}

        if "backport_analysis" in scan_data:
            try:
                reports["backport_csv"] = self.csv_reporter.generate_backport_evidence(
                    scan_data["backport_analysis"], target_ip
                )
                scan_log(f"[+] Backport evidence CSV: {reports['backport_csv']}")
            except Exception as e:
                scan_log(f"[-] Backport CSV generation error: {e}")

        if "cipher_enumeration" in scan_data:
            try:
                reports["cipher_csv"] = self.csv_reporter.generate_cipher_evidence(
                    scan_data["cipher_enumeration"], target_ip
                )
                scan_log(f"[+] Cipher evidence CSV: {reports['cipher_csv']}")
            except Exception as e:
                scan_log(f"[-] Cipher CSV generation error: {e}")

        if "evidence" in scan_data:
            try:
                evidence_payload = {
                    "items": scan_data["evidence"].get("items", {}),
                    "strength": scan_data["evidence"].get("assessment", {}).get("overall", "unknown"),
                    "recommendations": [],
                }
                if "backport_analysis" in scan_data:
                    rec = scan_data["backport_analysis"].get("recommendation")
                    if rec:
                        evidence_payload["recommendations"].append(rec)

                reports["evidence_json"] = self.json_reporter.generate_evidence_report(
                    evidence_payload, target_ip, "compensating_controls"
                )
                scan_log(f"[+] Evidence JSON: {reports['evidence_json']}")

                if "security_analysis" in scan_data:
                    reports["security_csv"] = self.csv_reporter.generate_security_evidence(
                        scan_data["security_analysis"], target_ip
                    )
                    scan_log(f"[+] Security evidence CSV: {reports['security_csv']}")
            except Exception as e:
                scan_log(f"[-] Evidence report generation error: {e}")

        return reports

    def generate_reports(self, scan_data: Dict[str, Any], target_ip: str) -> Dict[str, str]:
        """Generate all enabled report formats"""
        reports = {}
        
        try:
            if self.config.output.include_json:
                json_path = self.json_reporter.generate_report(scan_data, target_ip)
                reports["json"] = json_path
                scan_log(f"[+] JSON report: {json_path}")
            
            if self.config.output.include_markdown:
                try:
                    md_path = self.md_reporter.generate_report(scan_data, target_ip)
                    reports["markdown"] = md_path  
                    scan_log(f"[+] Markdown report: {md_path}")
                except Exception as md_error:
                    scan_log(f"[-] Markdown generation error: {md_error}")
                    import traceback
                    traceback.print_exc()
            
            if self.config.output.include_csv:
                # Generate evidence CSV if we have security analysis
                if "security_analysis" in scan_data:
                    csv_path = self.csv_reporter.generate_security_evidence(
                        scan_data["security_analysis"], target_ip
                    )
                    reports["csv"] = csv_path
                    scan_log(f"[+] CSV evidence: {csv_path}")
            
        except Exception as e:
            scan_log(f"[-] Report generation error: {str(e)}")
        
        return reports
    
    def _build_host_candidates(self, target_ip: str, user_host: Optional[str],
                              scan_data: Dict[str, Any]) -> List[str]:
        """Build ordered host candidates: user host, IP, then PTR/SAN fallbacks."""
        primary: List[str] = []
        fallbacks: List[str] = []
        seen = set()

        if user_host and user_host.lower() not in seen:
            primary.append(user_host)
            seen.add(user_host.lower())

        if target_ip.lower() not in seen:
            primary.append(target_ip)
            seen.add(target_ip.lower())

        ptr_name = scan_data.get("reverse_dns")
        if ptr_name and ptr_name.lower() not in seen:
            fallbacks.append(ptr_name)
            seen.add(ptr_name.lower())

        tls_data = scan_data.get("tls_analysis", {})
        cert = tls_data.get("default_handshake", {}).get("certificate")
        if cert:
            sans = self.tls_scanner.extract_sans({"certificate": cert})
            for san in sans:
                if san.lower() not in seen and "*" not in san:
                    fallbacks.append(san)
                    seen.add(san.lower())

        return primary + fallbacks

    def _safe_final_response(self, http_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Return the final HTTP response dict, tolerating missing/null results."""
        if not http_result:
            return {}
        final_response = http_result.get("final")
        return final_response if isinstance(final_response, dict) else {}

    def _probe_succeeded(self, http_result: Optional[Dict[str, Any]]) -> bool:
        """True when a probe returned a usable HTTP status without transport errors."""
        if not http_result or http_result.get("error"):
            return False
        final_response = self._safe_final_response(http_result)
        return final_response.get("status_code") is not None

    def _analyze_http_probe(
        self,
        http_result: Dict[str, Any],
        port: int,
        candidate: str,
        use_tls: bool,
        scan_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run analyzers for a single HTTP probe result."""
        final_response = self._safe_final_response(http_result)
        headers = final_response.get("headers", {}) or {}

        security_analysis = self.security_analyzer.analyze(headers) if headers else {}
        body_text = final_response.get("body_sample") or ""
        page_title = final_response.get("title")
        status_code = final_response.get("status_code")
        waf_analysis = (
            self.waf_detector.detect(
                headers,
                body=body_text,
                status_code=status_code,
                title=page_title,
            )
            if headers
            else {}
        )
        security_analysis = security_analysis or {}
        waf_analysis = waf_analysis or {}

        server_header = self._extract_server_header(headers)
        server_analysis = (
            self.token_analyzer.analyze_server_header(server_header)
            if server_header else {}
        )
        server_analysis = server_analysis or {}

        classification = self.classifier.classify_from_probe(
            scan_data.get("reverse_dns"),
            (scan_data.get("tls_analysis", {}) or {}).get("default_handshake"),
            headers,
            server_analysis,
        )

        return {
            "port": port,
            "host": candidate,
            "use_tls": use_tls,
            "result": http_result,
            "security_headers": security_analysis,
            "waf_cdn": waf_analysis,
            "server_analysis": server_analysis,
            "classification": classification,
            "error": http_result.get("error"),
        }

    def _probe_web_services(
        self,
        target_ip: str,
        host: Optional[str],
        scan_data: Dict[str, Any],
        web_ports: List[int],
        stealth: bool = False,
    ) -> Dict[str, Any]:
        """Probe web ports with IP-first host selection and global probe limits."""
        scan_log("[*] Analyzing HTTP/HTTPS services...")
        http_results: Dict[str, Any] = {"probes": []}
        candidates = self._build_host_candidates(target_ip, host, scan_data)
        max_probes = max(1, self.config.scan.max_http_probes)
        max_hosts_per_port = max(1, self.config.scan.max_host_candidates_per_port)
        probes_run = 0

        for port in web_ports:
            if probes_run >= max_probes:
                scan_log(f"[*] HTTP probe limit reached ({max_probes}); skipping remaining ports")
                break

            use_tls = port in (443, 8443)
            hosts_tried = 0

            for candidate in candidates:
                if probes_run >= max_probes or hosts_tried >= max_hosts_per_port:
                    break

                probe_host = candidate if candidate != target_ip else None
                scan_log(f"[*] Probing {('HTTPS' if use_tls else 'HTTP')} on {candidate}:{port}")

                try:
                    http_result = self.http_scanner.probe_http(
                        target_ip,
                        port,
                        host=probe_host,
                        use_tls=use_tls,
                        stealth=stealth,
                        capture_body=self.config.scan.capture_body,
                        capture_bytes=self.config.scan.capture_body_bytes,
                    )
                    probe_data = self._analyze_http_probe(
                        http_result, port, candidate, use_tls, scan_data
                    )
                    http_results["probes"].append(probe_data)
                    probes_run += 1
                    hosts_tried += 1

                    if http_result.get("error"):
                        scan_log(f"[-] Error: {http_result['error']}")
                    else:
                        status = self._safe_final_response(http_result).get("status_code", "Unknown")
                        scan_log(f"[+] HTTP probe complete: {status}")

                    if self._probe_succeeded(http_result):
                        break

                except Exception as exc:
                    scan_log(f"[-] HTTP probe failed: {str(exc)}")
                    http_results["probes"].append({
                        "port": port,
                        "host": candidate,
                        "use_tls": use_tls,
                        "result": {"final": {}, "error": str(exc)},
                        "error": str(exc),
                    })
                    probes_run += 1
                    hosts_tried += 1

        scan_log(f"[+] HTTP probing complete: {probes_run} probe(s)")
        return http_results
    
    def _extract_server_header(self, headers: Dict[str, List[str]]) -> Optional[str]:
        """Extract Server header value"""
        for key, values in headers.items():
            if key.lower() == "server" and values:
                return values[0]
        return None

def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser"""
    parser = argparse.ArgumentParser(
        description="TPCRM Findings Scanner - investigate ratings findings and collect dispute evidence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan 192.168.1.100
  %(prog)s scan 192.168.1.100 --host example.com --stealth
  %(prog)s scan 192.168.1.100 --profile web --evidence
  %(prog)s batch ips.txt --profile quick --output-csv --evidence
  %(prog)s config --contact "security@example.com"
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a single target")
    scan_parser.add_argument("target", help="Target IP address or hostname (apex/subdomain)")
    scan_parser.add_argument("--host", help="Hostname for SNI and Host header")
    scan_parser.add_argument("--ports", help="Comma-separated list of ports to scan")
    scan_parser.add_argument(
        "--profile",
        choices=list_profiles(),
        help="Scan profile preset: quick, web, or full (default: full or config scan.default_profile)",
    )
    scan_parser.add_argument("--stealth", action="store_true", help="Use stealth mode (no signatures)")
    scan_parser.add_argument("--evidence", action="store_true", help="Generate evidence reports")
    scan_parser.add_argument("--backports", action="store_true", help="Analyze for backported packages")
    scan_parser.add_argument("--cipher", action="store_true", help="Enumerate accepted TLS cipher suites and validate weak-cipher findings")
    scan_parser.add_argument("--timeout", type=float, help="Connection timeout in seconds")
    scan_parser.add_argument("--config", help="Path to config file")
    scan_parser.add_argument("--only-web", action="store_true", help="Probe web ports only (HTTP/HTTPS)")
    scan_parser.add_argument("--no-port-scan", action="store_true", help="Skip TCP port scan and assume target ports")
    scan_parser.add_argument("--capture-body", action="store_true", help="Capture small HTTP body sample and hash")
    scan_parser.add_argument("--capture-body-bytes", type=int, help="Bytes of body to capture (default 512 when enabled)")
    scan_parser.add_argument("-y", "--yes", action="store_true", help="Skip scan signature confirmation prompt")
    scan_parser.add_argument(
        "--allow-placeholder",
        action="store_true",
        help="Allow default/placeholder contact in signature headers (local testing)",
    )
    
    # Batch scan command
    batch_parser = subparsers.add_parser("batch", help="Scan multiple targets")
    batch_parser.add_argument(
        "targets_file",
        help="File containing targets (one IP or hostname per line)",
    )
    batch_parser.add_argument("--threads", type=int, default=10, help="Number of concurrent scans")
    batch_parser.add_argument("--output-csv", action="store_true", help="Generate batch CSV summary")
    batch_parser.add_argument("--stealth", action="store_true", help="Use stealth mode")
    batch_parser.add_argument("--evidence", action="store_true", help="Collect compensating-controls evidence per target")
    batch_parser.add_argument("--backports", action="store_true", help="Analyze for backported packages per target")
    batch_parser.add_argument("--cipher", action="store_true", help="Enumerate accepted TLS cipher suites per target")
    batch_parser.add_argument("--only-web", action="store_true", help="Probe web ports only (HTTP/HTTPS)")
    batch_parser.add_argument("--no-port-scan", action="store_true", help="Skip TCP port scan and assume web ports")
    batch_parser.add_argument(
        "--profile",
        choices=list_profiles(),
        help="Scan profile preset: quick, web, or full (default: full or config scan.default_profile)",
    )
    batch_parser.add_argument("--config", help="Path to config file")
    batch_parser.add_argument("-y", "--yes", action="store_true", help="Skip scan signature confirmation prompt")
    batch_parser.add_argument(
        "--allow-placeholder",
        action="store_true",
        help="Allow default/placeholder contact in signature headers (local testing)",
    )
    
    # Evidence command
    evidence_parser = subparsers.add_parser("evidence", help="Generate evidence reports only")
    evidence_parser.add_argument("target", help="Target IP address or hostname")
    evidence_parser.add_argument("--scan-file", help="Path to existing JSON scan file")
    evidence_parser.add_argument("--type", choices=["backports", "security", "all"], 
                                default="all", help="Type of evidence to collect")
    
    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Compare two scan JSON reports")
    diff_parser.add_argument("older", help="Older/baseline JSON report path")
    diff_parser.add_argument("newer", help="Newer JSON report path")
    diff_parser.add_argument("--json", action="store_true", help="Emit structured JSON diff")
    
    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument("--show", action="store_true", help="Show current configuration")
    config_parser.add_argument("--contact", help="Set contact information")
    config_parser.add_argument("--user-agent", help="Set custom user agent")
    config_parser.add_argument("--output-dir", help="Set output directory")
    config_parser.add_argument("--enable-signatures", action="store_true", help="Enable scan signatures")
    config_parser.add_argument("--disable-signatures", action="store_true", help="Disable scan signatures")
    
    return parser

def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Load configuration
    try:
        config = Config.load(args.config if hasattr(args, 'config') and args.config else None)
        
        # Apply command-line overrides
        if hasattr(args, 'timeout') and args.timeout:
            config.scan.timeout = args.timeout
        # Capture body overrides (scan command)
        if getattr(args, 'capture_body', False):
            config.scan.capture_body = True
            if getattr(args, 'capture_body_bytes', None):
                config.scan.capture_body_bytes = int(args.capture_body_bytes)
            elif config.scan.capture_body_bytes <= 0:
                config.scan.capture_body_bytes = 512
        
    except (OSError, ValueError, TypeError, yaml.YAMLError) as e:
        print(f"[-] Configuration error: {e}")
        sys.exit(1)
    
    # Handle config command
    if args.command == "config":
        handle_config_command(args, config)
        return
    
    # Create toolkit instance
    toolkit = SSCToolkit(config)
    
    # Handle commands
    if args.command == "scan":
        handle_scan_command(args, toolkit)
    elif args.command == "batch":
        handle_batch_command(args, toolkit)
    elif args.command == "evidence":
        handle_evidence_command(args, toolkit)
    elif args.command == "diff":
        handle_diff_command(args)

@dataclass
class TargetScanOptions:
    """Options for a single-target scan pipeline."""

    host: Optional[str] = None
    stealth: bool = False
    ports: Optional[List[int]] = None
    only_web: bool = False
    skip_port_scan: bool = False
    evidence: bool = False
    backports: bool = False
    cipher: bool = False
    profile: Optional[str] = None
    input_target: Optional[str] = None
    write_reports: bool = True
    write_evidence_reports: bool = False


def run_target_pipeline(
    toolkit: SSCToolkit,
    target_ip: str,
    options: TargetScanOptions,
) -> Dict[str, Any]:
    """Run scan, enrichment, narrative, and report generation for one target."""
    timestamp = int(time.time())
    output_paths = toolkit.config.get_output_paths(target_ip, timestamp)

    try:
        resolved_ports, resolved_only_web, profile_label = resolve_scan_options(
            toolkit.config,
            profile=options.profile,
            ports=options.ports,
            only_web=options.only_web,
        )
    except ValueError as exc:
        scan_log(f"[-] {exc}")
        return {
            "target_ip": target_ip,
            "success": False,
            "notes": str(exc),
            "error": str(exc),
        }

    with scan_log_session(output_paths["log"]) as log_path:
        scan_log(f"[+] Scan log: {log_path}")
        record_scan_signature_session(toolkit.config, stealth=options.stealth)
        scan_log(f"[*] Scan profile: {profile_label}")

        scan_data = toolkit.scan_target(
            target_ip,
            host=options.host,
            stealth=options.stealth,
            ports=resolved_ports,
            only_web=resolved_only_web,
            skip_port_scan=options.skip_port_scan,
            profile=profile_label,
            input_target=options.input_target,
            cipher=options.cipher,
        )

        success = "error" not in scan_data
        if success and (options.evidence or options.backports):
            scan_data = toolkit.enrich_scan_data(
                scan_data,
                target_ip,
                evidence=options.evidence,
                backports=options.backports,
            )

        if success:
            scan_data = toolkit.attach_origin_discovery(
                scan_data,
                host=options.host,
                input_target=options.input_target,
            )
            scan_data = toolkit.attach_remediation_narrative(scan_data, target_ip)
            if options.write_reports:
                toolkit.generate_reports(scan_data, target_ip)
            if options.write_evidence_reports:
                toolkit.generate_evidence_reports(scan_data, target_ip)

    scan_data.setdefault("metadata", {})["scan_log"] = log_path
    return scan_data


def handle_scan_command(args, toolkit: SSCToolkit):
    """Handle single target scan"""
    try:
        scan_target = parse_target_input(
            args.target,
            explicit_host=args.host,
            timeout=toolkit.config.scan.timeout,
        )
    except ValueError as exc:
        print(f"[-] {exc}")
        sys.exit(1)

    if scan_target.input != scan_target.ip:
        print(f"[+] Resolved {scan_target.input} -> {scan_target.ip}")

    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(f"[-] Invalid ports format: {args.ports}")
            sys.exit(1)

    begin_scan_session(
        toolkit.config,
        stealth=args.stealth,
        assume_yes=args.yes,
        allow_placeholder=getattr(args, "allow_placeholder", False),
    )

    try:
        run_target_pipeline(
            toolkit,
            scan_target.ip,
            TargetScanOptions(
                host=scan_target.host,
                stealth=args.stealth,
                ports=ports,
                only_web=getattr(args, "only_web", False),
                skip_port_scan=getattr(args, "no_port_scan", False),
                evidence=args.evidence,
                backports=args.backports,
                cipher=args.cipher,
                profile=getattr(args, "profile", None),
                input_target=scan_target.input,
                write_reports=True,
                write_evidence_reports=args.evidence or args.backports or args.cipher,
            ),
        )
    except ValueError as exc:
        print(f"[-] {exc}")
        sys.exit(1)

def load_targets_file(path: str, timeout: float = 2.0) -> List[ScanTarget]:
    """Load targets from a text file, resolving hostnames when present."""
    targets: List[ScanTarget] = []
    seen = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            dedupe_key = value.lower().rstrip(".")
            if dedupe_key in seen:
                continue
            try:
                target = parse_target_input(value, timeout=timeout)
            except ValueError as exc:
                print(f"[-] Skipping invalid target {value}: {exc}")
                continue
            seen.add(dedupe_key)
            targets.append(target)
    return targets


def find_latest_scan_file(
    reports_dir: str,
    target: str,
    timeout: float = 2.0,
) -> Optional[str]:
    """Find the newest JSON scan report for a target IP or hostname."""
    try:
        parsed = parse_target_input(target, timeout=timeout)
    except ValueError:
        return None
    safe_ip = parsed.ip.replace(":", "_")
    candidates = sorted(
        Path(reports_dir).glob(f"scan_{safe_ip}_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return str(candidates[0]) if candidates else None


def load_scan_data_from_file(scan_file: str) -> Dict[str, Any]:
    """Load scan results from a JSON report file."""
    with open(scan_file, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload.get("scan_results"), dict):
        return payload["scan_results"]
    return payload


def run_batch_target(
    toolkit: SSCToolkit,
    scan_target: ScanTarget,
    stealth: bool = False,
    only_web: bool = False,
    skip_port_scan: bool = False,
    evidence: bool = False,
    backports: bool = False,
    cipher: bool = False,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan a single batch target and return a flattened summary row payload."""
    try:
        scan_data = run_target_pipeline(
            toolkit,
            scan_target.ip,
            TargetScanOptions(
                host=scan_target.host,
                stealth=stealth,
                only_web=only_web,
                skip_port_scan=skip_port_scan,
                evidence=evidence,
                backports=backports,
                cipher=cipher,
                profile=profile,
                input_target=scan_target.input,
                write_reports=True,
                write_evidence_reports=evidence or backports or cipher,
            ),
        )
        success = "error" not in scan_data
        return {
            "target_ip": scan_target.ip,
            "input_target": scan_target.input,
            "scan_host": scan_target.host,
            "success": success,
            "notes": scan_data.get("error", ""),
            **scan_data,
        }
    except Exception as exc:
        return {
            "target_ip": scan_target.ip,
            "input_target": scan_target.input,
            "scan_host": scan_target.host,
            "success": False,
            "notes": str(exc),
            "error": str(exc),
        }


def handle_batch_command(args, toolkit: SSCToolkit):
    """Handle batch scanning"""
    if not os.path.exists(args.targets_file):
        print(f"[-] Targets file not found: {args.targets_file}")
        sys.exit(1)

    targets = load_targets_file(args.targets_file, timeout=toolkit.config.scan.timeout)
    if not targets:
        print(f"[-] No valid targets found in {args.targets_file}")
        sys.exit(1)

    batch_name = Path(args.targets_file).stem
    print(f"[+] Batch scanning {len(targets)} targets from {args.targets_file}")
    begin_scan_session(
        toolkit.config,
        stealth=args.stealth,
        assume_yes=args.yes,
        allow_placeholder=getattr(args, "allow_placeholder", False),
    )

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        futures = {
            executor.submit(
                run_batch_target,
                toolkit,
                scan_target,
                stealth=args.stealth,
                only_web=getattr(args, "only_web", False),
                skip_port_scan=getattr(args, "no_port_scan", False),
                evidence=getattr(args, "evidence", False),
                backports=getattr(args, "backports", False),
                cipher=getattr(args, "cipher", False),
                profile=getattr(args, "profile", None),
            ): scan_target
            for scan_target in targets
        }
        for future in as_completed(futures):
            scan_target = futures[future]
            result = future.result()
            results.append(result)
            status = "ok" if result.get("success") else "failed"
            label = scan_target.input
            if scan_target.input != scan_target.ip:
                label = f"{scan_target.input} ({scan_target.ip})"
            log_path = (result.get("metadata") or {}).get("scan_log")
            if log_path:
                print(f"[+] Batch progress: {label} ({status}) log={log_path}")
            else:
                print(f"[+] Batch progress: {label} ({status})")

    results.sort(key=lambda row: (row.get("input_target", ""), row.get("target_ip", "")))
    batch_results = {
        "targets": [target.input for target in targets],
        "resolved_targets": [
            {
                "input": target.input,
                "ip": target.ip,
                "host": target.host,
            }
            for target in targets
        ],
        "results": results,
        "metadata": {
            "batch_name": batch_name,
            "threads": args.threads,
            "stealth": args.stealth,
            "only_web": getattr(args, "only_web", False),
            "skip_port_scan": getattr(args, "no_port_scan", False),
            "evidence": getattr(args, "evidence", False),
            "backports": getattr(args, "backports", False),
            "cipher": getattr(args, "cipher", False),
            "profile": getattr(args, "profile", None),
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        },
    }

    json_path = toolkit.json_reporter.generate_batch_summary(batch_results, batch_name)
    print(f"[+] Batch JSON summary: {json_path}")

    if args.output_csv:
        csv_path = toolkit.csv_reporter.generate_batch_summary_csv(batch_results, batch_name)
        print(f"[+] Batch CSV summary: {csv_path}")

def handle_evidence_command(args, toolkit: SSCToolkit):
    """Handle evidence-only analysis"""
    try:
        scan_target = parse_target_input(
            args.target,
            timeout=toolkit.config.scan.timeout,
        )
    except ValueError as exc:
        print(f"[-] {exc}")
        sys.exit(1)

    if scan_target.input != scan_target.ip:
        print(f"[+] Resolved {scan_target.input} -> {scan_target.ip}")

    scan_file = args.scan_file
    if not scan_file:
        reports_dir = os.path.join(toolkit.config.output.base_dir, toolkit.config.output.reports_dir)
        scan_file = find_latest_scan_file(
            reports_dir,
            scan_target.input,
            timeout=toolkit.config.scan.timeout,
        )

    if not scan_file or not os.path.exists(scan_file):
        print(
            f"[-] No scan data found for {scan_target.input}. "
            "Run a scan first or pass --scan-file."
        )
        sys.exit(1)

    print(f"[+] Evidence analysis for {scan_target.input} using {scan_file}")
    scan_data = load_scan_data_from_file(scan_file)

    include_backports = args.type in ("backports", "all")
    include_security = args.type in ("security", "all")
    scan_data = toolkit.enrich_scan_data(
        scan_data,
        scan_target.ip,
        evidence=include_security,
        backports=include_backports,
    )
    metadata = scan_data.get("metadata", {}) or {}
    scan_data = toolkit.attach_origin_discovery(
        scan_data,
        host=metadata.get("host") or scan_target.host,
        input_target=metadata.get("input_target") or scan_target.input,
    )
    scan_data = toolkit.attach_remediation_narrative(scan_data, scan_target.ip)
    toolkit.generate_evidence_reports(scan_data, scan_target.ip)

def handle_diff_command(args) -> None:
    """Compare two scan JSON reports."""
    for label, path in (("older", args.older), ("newer", args.newer)):
        if not os.path.exists(path):
            print(f"[-] {label} report not found: {path}")
            sys.exit(1)

    with open(args.older, "r", encoding="utf-8") as handle:
        older_payload = json.load(handle)
    with open(args.newer, "r", encoding="utf-8") as handle:
        newer_payload = json.load(handle)

    diff = compare_scan_reports(older_payload, newer_payload)
    if args.json:
        print(json.dumps(diff, indent=2))
    else:
        print(format_scan_diff_text(diff, args.older, args.newer))


def handle_config_command(args, config: Config):
    """Handle configuration management"""
    if args.show:
        from ssc.utils import contact_configuration_issues

        print("Current Configuration:")
        print(f"  Contact: {config.signature.contact_value}")
        print(f"  User Agent: {config.signature.user_agent}")
        print(f"  Signatures Enabled: {config.signature.enabled}")
        print(f"  Output Directory: {config.output.base_dir}")
        print(f"  Default Timeout: {config.scan.timeout}")
        issues = contact_configuration_issues(config)
        if issues and config.signature.enabled:
            print("  Contact status: placeholder (update before production scans)")
            for issue in issues:
                print(f"    - {issue}")
        elif config.signature.enabled:
            print("  Contact status: configured")
        return
    
    # Update configuration
    changed = False
    if args.contact:
        config.signature.contact_value = args.contact
        changed = True
        print(f"[+] Contact updated: {args.contact}")
    
    if args.user_agent:
        config.signature.user_agent = args.user_agent
        changed = True
        print(f"[+] User Agent updated: {args.user_agent}")
    
    if args.output_dir:
        config.output.base_dir = args.output_dir
        changed = True
        print(f"[+] Output directory updated: {args.output_dir}")
    
    if args.enable_signatures:
        config.signature.enabled = True
        changed = True
        print("[+] Signatures enabled")
    
    if args.disable_signatures:
        config.signature.enabled = False
        changed = True
        print("[+] Signatures disabled")
    
    if changed:
        config.save("config.yaml")
        print("[+] Configuration saved")

if __name__ == "__main__":
    main()
