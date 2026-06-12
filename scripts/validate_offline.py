#!/usr/bin/env python3
"""
Offline validation for TPCRM Findings Scanner components without network access.

Validates:
- Cloud/CDN/LB classifier against Google, Cloudflare, CloudFront, and origin-like cases
- HTTP response parsing + body fingerprint extraction
- Markdown report includes environment classification
"""

import os
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssc.analyzers.cloud_classifier import CloudGatewayClassifier
from ssc.analyzers.origin_discovery import OriginDiscoveryAnalyzer
from ssc.analyzers.remediation_narrative import RemediationNarrativeGenerator
from ssc.utils.dns_chain import build_chain_hops, resolve_forward_chain
from ssc.analyzers.waf_cdn import WAFCDNDetector
from ssc.analyzers.scan_diff import compare_scan_reports, format_scan_diff_text
from ssc.utils.signatures import (
    contact_configuration_issues,
    ensure_production_contact,
    is_placeholder_contact,
)
from ssc.scan_profiles import resolve_scan_options, PROFILE_PRESETS
from ssc.utils.scan_log import scan_log_session, scan_log
from ssc.utils.signatures import format_scan_signature_banner, confirm_scan_session
from ssc.scanners.http_scanner import HTTPScanner
from ssc.scanners.tls_scanner import TLSScanner
from ssc.config import ScanConfig, SignatureConfig, Config
from ssc.utils import ScanTarget, is_valid_hostname, parse_target_input
from ssc.reporters.markdown_reporter import MarkdownReporter
from ssc.reporters.json_reporter import JSONReporter
from ssc.reporters.csv_reporter import CSVReporter
from cli import (
    SSCToolkit,
    create_parser,
    load_targets_file,
    load_scan_data_from_file,
    run_batch_target,
    run_target_pipeline,
    TargetScanOptions,
)


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_classifier():
    clf = CloudGatewayClassifier()

    # Google edge
    g_headers = {"Server": ["ESF"], "Via": ["1.1 google"]}
    res_g = clf.classify_from_probe(
        reverse_dns="edge-cache-xyz.1e100.net",
        tls_info=None,
        headers=g_headers,
        server_analysis={"raw": "ESF"},
    )
    assert_true(res_g["classification"] == "managed_edge", f"GCP classification wrong: {res_g}")
    assert_true(res_g["provider"] == "google", f"GCP provider wrong: {res_g}")

    # Cloudflare
    cf_headers = {"CF-RAY": ["abc"], "Server": ["cloudflare"]}
    res_cf = clf.classify_from_probe(
        reverse_dns="cf-xxx.cloudflare.net",
        tls_info=None,
        headers=cf_headers,
        server_analysis={"raw": "cloudflare"},
    )
    assert_true(res_cf["classification"] == "managed_edge", f"CF classification wrong: {res_cf}")
    assert_true(res_cf["provider"] == "cloudflare", f"CF provider wrong: {res_cf}")

    # CloudFront via SAN
    cf_cert = {
        "certificate": {
            "issuer": (("organizationName", "Amazon"),),
            "subjectAltName": [("DNS", "d111111abcdef8.cloudfront.net"), ("DNS", "example.com")],
        }
    }
    res_cfront = clf.classify_from_probe(
        reverse_dns=None,
        tls_info=cf_cert,
        headers={},
        server_analysis={"raw": ""},
    )
    assert_true(res_cfront["classification"] == "managed_edge", f"CloudFront classification wrong: {res_cfront}")
    assert_true(res_cfront["provider"] == "aws-cloudfront", f"CloudFront provider wrong: {res_cfront}")

    # Origin-like server
    res_origin = clf.classify_from_probe(
        reverse_dns="www.example.internal",
        tls_info=None,
        headers={"Server": ["nginx/1.22.1"]},
        server_analysis={"raw": "nginx/1.22.1"},
    )
    assert_true(res_origin["classification"] in ("origin", "unknown"), f"Origin classification unexpected: {res_origin}")
    print("Classifier tests: OK")


def test_http_parser_features():
    scan_cfg = ScanConfig()
    sig_cfg = SignatureConfig()
    http = HTTPScanner(scan_cfg, sig_cfg)

    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Server: test\r\n\r\n"
        b"<html><head><title>Hello World</title></head><body>Sample Body</body></html>"
    )
    parsed = http._parse_http_response(raw)
    assert_true(parsed["status_code"] == 200, f"Status parse failed: {parsed}")
    feats = http._extract_body_features(raw, capture_bytes=32)
    assert_true(feats.get("title") == "Hello World", f"Title extract failed: {feats}")
    assert_true(len(feats.get("body_sha256", "")) == 64, f"Hash missing: {feats}")
    assert_true("body_sample" in feats and len(feats["body_sample"]) > 0, "Sample missing")
    print("HTTP parse + features: OK")


def test_markdown_report():
    scan_data = {
        "security_analysis": {
            "classification": {
                "classification": "managed_edge",
                "provider": "google",
                "role": "edge",
                "confidence": "high",
            }
        },
        "http_analysis": {
            "probes": [
                {
                    "port": 443,
                    "host": "example.com",
                    "use_tls": True,
                    "result": {"final": {"status_code": 200, "title": "Hello", "body_sha256": "0" * 64}},
                    "classification": {"role": "edge", "provider": "google", "confidence": "high"},
                }
            ]
        },
        "port_scan": {"open_ports": [80, 443]}
    }
    with tempfile.TemporaryDirectory() as tmp:
        md = MarkdownReporter(output_dir=tmp)
        path = md.generate_report(scan_data, "203.0.113.10")
        assert_true(os.path.exists(path), "Markdown file not created")
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
            assert_true("Environment" in text and "google" in text, "Classification not in report")
    print("Markdown report: OK")


def test_json_summary():
    scan_data = {
        "security_analysis": {
            "classification": {
                "classification": "managed_edge",
                "provider": "google",
                "role": "edge",
                "confidence": "high",
            }
        },
        "http_analysis": {
            "probes": [
                {
                    "port": 443,
                    "use_tls": True,
                    "result": {"final": {"status_code": 200}},
                },
                {
                    "port": 80,
                    "use_tls": False,
                    "result": {"final": {"status_code": 301}},
                },
            ]
        },
        "port_scan": {"open_ports": [80, 443, 22]}
    }
    with tempfile.TemporaryDirectory() as tmp:
        jr = JSONReporter(output_dir=tmp)
        path = jr.generate_report(scan_data, "203.0.113.10")
        assert_true(os.path.exists(path), "JSON file not created")
        import json
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert_true("summary" in data, "Missing summary in JSON report")
            env = data["summary"].get("environment", {})
            assert_true(env.get("provider") == "google", f"Env provider wrong: {env}")
            assert_true(data["summary"].get("open_port_count") == 3, "Open port count wrong")
            ws = data["summary"].get("web_services", [])
            assert_true("HTTPS 443" in ws and "HTTP 80" in ws, f"Web services wrong: {ws}")
    print("JSON summary: OK")


def test_tls_certificate_formatting():
    scanner = TLSScanner(ScanConfig())
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example CA"),),),
        "serialNumber": "1A2B",
        "notBefore": "Jan  1 00:00:00 2025 GMT",
        "notAfter": "Jan  1 00:00:00 2026 GMT",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }
    formatted = scanner._format_certificate(cert)
    assert_true(formatted["subject"] == cert["subject"], "Subject not preserved")
    assert_true(len(formatted["subjectAltName"]) == 2, "SANs not preserved")
    sans = scanner.extract_sans({"certificate": formatted})
    assert_true("example.com" in sans and "www.example.com" in sans, f"SAN extract failed: {sans}")
    print("TLS certificate formatting: OK")


def test_security_score_promotion():
    toolkit = SSCToolkit(Config.load())
    security_analysis = {
        "security_headers": {
            "present": ["strict-transport-security"],
            "score": {"percentage": 77.7, "grade": "C", "present_count": 7, "total_count": 9},
        }
    }
    toolkit._apply_security_score(security_analysis)
    assert_true("score" in security_analysis, "Top-level score missing")
    assert_true(security_analysis["score"]["grade"] == "C", "Score promotion failed")
    print("Security score promotion: OK")


def test_backport_csv_and_batch_helpers():
    backport_results = {
        "confidence": "medium",
        "recommendation": "Verify patch levels manually.",
        "backport_evidence": [
            {
                "distribution": "debian",
                "indicator": "Apache/2.4.38 (Debian)",
                "pattern": "Debian",
                "source": "http_server_header_port_443",
            }
        ],
        "software_versions": [
            {
                "name": "Apache",
                "version": "2.4.38",
                "raw_match": "Apache/2.4.38",
                "source": "http_server_header_port_443",
            }
        ],
        "distribution_indicators": [{"distribution": "debian", "confidence": "high"}],
    }

    with tempfile.TemporaryDirectory() as tmp:
        csv_reporter = CSVReporter(output_dir=tmp)
        csv_path = csv_reporter.generate_backport_evidence(backport_results, "203.0.113.10")
        assert_true(os.path.exists(csv_path), "Backport CSV not created")
        with open(csv_path, "r", encoding="utf-8") as handle:
            text = handle.read()
            assert_true("debian" in text and "Verify patch levels manually." in text, "Backport CSV content wrong")

        batch_results = {
            "targets": ["203.0.113.10"],
            "results": [
                {
                    "target_ip": "203.0.113.10",
                    "success": True,
                    "port_scan": {"open_ports": [80, 443]},
                    "security_analysis": {
                        "score": {"percentage": 50.0, "grade": "F"},
                        "waf_cdn": {"services": ["cloudflare"]},
                    },
                    "backport_analysis": backport_results,
                    "http_analysis": {
                        "probes": [
                            {"port": 443, "use_tls": True, "result": {"final": {"status_code": 200}}},
                        ]
                    },
                    "tls_analysis": {"default_handshake": {"ok": True}},
                }
            ],
        }
        batch_csv = csv_reporter.generate_batch_summary_csv(batch_results, "sample")
        with open(batch_csv, "r", encoding="utf-8") as handle:
            text = handle.read()
            assert_true("debian" in text and "cloudflare" in text, f"Batch CSV content wrong: {text}")

        targets_file = os.path.join(tmp, "targets.txt")
        with open(targets_file, "w", encoding="utf-8") as handle:
            handle.write("# comment\n203.0.113.10\n\n203.0.113.11\nbad-ip\n")
        loaded = load_targets_file(targets_file)
        assert_true(
            [target.input for target in loaded] == ["203.0.113.10", "203.0.113.11"],
            f"Target load failed: {loaded}",
        )
    print("Backport CSV + batch helpers: OK")


def test_waf_cdn_detector():
    detector = WAFCDNDetector()

    cf_headers = {
        "Server": ["cloudflare"],
        "CF-RAY": ["7abc123-LAX"],
        "Set-Cookie": ["__cf_bm=abc; path=/; HttpOnly"],
    }
    cf_result = detector.detect(cf_headers)
    assert_true(cf_result["primary_service"] == "cloudflare", f"Cloudflare primary wrong: {cf_result}")
    assert_true("cloudflare" in cf_result["services"], f"Cloudflare services wrong: {cf_result}")
    assert_true(cf_result["manufacturer"] == "Cloudflare Inc.", f"Manufacturer wrong: {cf_result}")

    # Strong CDN should suppress weak single-marker F5 noise.
    noisy_headers = {
        "Server": ["cloudflare"],
        "CF-RAY": ["7abc123-LAX"],
        "X-WAF": ["generic"],
    }
    noisy_result = detector.detect(noisy_headers)
    assert_true(noisy_result["primary_service"] == "cloudflare", f"Noisy primary wrong: {noisy_result}")
    assert_true(
        "f5-big-ip" not in noisy_result["services"],
        f"F5 false positive not filtered: {noisy_result}",
    )

    incapsula_headers = {"Set-Cookie": ["visid_incap_123=abc; path=/"]}
    incapsula_body = "<html>powered by incapsula incident id 12345</html>"
    inc_result = detector.detect(incapsula_headers, body=incapsula_body)
    assert_true(
        inc_result["primary_service"] == "imperva-incapsula",
        f"Incapsula detection failed: {inc_result}",
    )
    assert_true(len(inc_result["evidence"]["imperva-incapsula"]) >= 2, f"Incapsula evidence thin: {inc_result}")

    fastly_headers = {
        "X-Fastly-Request-ID": ["abc123"],
        "X-Served-By": ["cache-lax123-LAX"],
    }
    fastly_result = detector.detect(fastly_headers)
    assert_true(fastly_result["primary_service"] == "fastly", f"Fastly detection failed: {fastly_result}")

    azure_headers = {"X-Azure-Ref": ["0abcREF123=="]}
    azure_result = detector.detect(azure_headers)
    assert_true(azure_result["primary_service"] == "azure-front-door", f"Azure FD failed: {azure_result}")

    empty_result = detector.detect({})
    assert_true(empty_result["services"] == [], f"Empty headers should not match: {empty_result}")
    assert_true(not empty_result["has_waf_cdn"], "Empty detection should report no WAF/CDN")
    print("WAF/CDN detector tests: OK")


def test_dns_chain_resolution():
    def fake_lookup(hostname, _timeout):
        if hostname == "www.example.com":
            return (
                "d123.cloudfront.net",
                ["www.example.com"],
                ["203.0.113.10"],
            )
        raise socket.gaierror("unexpected host")

    chain = resolve_forward_chain("www.example.com", lookup_fn=fake_lookup)
    assert_true(chain["canonical_name"] == "d123.cloudfront.net", f"Canonical wrong: {chain}")
    assert_true(chain["aliases"] == ["www.example.com"], f"Aliases wrong: {chain}")
    assert_true(chain["resolved_ips"] == ["203.0.113.10"], f"IPs wrong: {chain}")

    hops = build_chain_hops(chain)
    assert_true(len(hops) == 2, f"Hop count wrong: {hops}")
    assert_true(hops[0]["hostname"] == "www.example.com", f"First hop wrong: {hops}")
    assert_true(hops[1]["hostname"] == "d123.cloudfront.net", f"Second hop wrong: {hops}")
    print("DNS chain resolution: OK")


def test_origin_discovery_analyzer():
    def fake_lookup(hostname, _timeout):
        return (
            "d123.cloudfront.net",
            ["www.example.com"],
            ["203.0.113.10"],
        )

    analyzer = OriginDiscoveryAnalyzer(lookup_fn=fake_lookup)
    scan_data = {
        "metadata": {
            "target_ip": "203.0.113.10",
            "input_target": "www.example.com",
            "host": "www.example.com",
        },
        "reverse_dns": "origin.internal.example.com",
        "tls_analysis": {
            "default_handshake": {
                "certificate": {
                    "subject": ((("commonName", "origin.internal.example.com"),),),
                    "subjectAltName": (
                        ("DNS", "origin.internal.example.com"),
                        ("DNS", "d123.cloudfront.net"),
                    ),
                }
            }
        },
        "http_analysis": {
            "probes": [
                {
                    "port": 443,
                    "result": {
                        "requests": [
                            {"host_header": "www.example.com"},
                            {"host_header": "origin.internal.example.com"},
                        ]
                    },
                }
            ]
        },
        "security_analysis": {
            "classification": {
                "classification": "managed_edge",
                "provider": "aws-cloudfront",
                "confidence": "high",
            }
        },
    }

    result = analyzer.analyze(scan_data, hostname="www.example.com", host="www.example.com")
    assert_true(result["summary"]["edge_detected_in_chain"], f"Edge not detected: {result}")
    assert_true(
        any(hint["hostname"] == "origin.internal.example.com" for hint in result["origin_hints"]),
        f"Origin hint missing: {result['origin_hints']}",
    )
    assert_true(
        any(hop.get("provider") == "aws-cloudfront" for hop in result["dns_chain"]["hops"]),
        f"CloudFront hop missing: {result['dns_chain']['hops']}",
    )

    edge_scan = dict(scan_data)
    edge_scan["origin_discovery"] = result
    narrative = RemediationNarrativeGenerator().generate(edge_scan, "203.0.113.10")
    assert_true(
        any("origin.internal.example.com" in bullet for bullet in narrative["evidence_bullets"]),
        f"Narrative missing origin hint bullet: {narrative['evidence_bullets']}",
    )
    assert_true(
        any("origin.internal.example.com" in action for action in narrative["recommended_actions"]),
        f"Narrative missing origin action: {narrative['recommended_actions']}",
    )
    print("Origin discovery analyzer: OK")


def test_origin_discovery_reports():
    scan_data = {
        "origin_discovery": {
            "dns_chain": {
                "query_hostname": "www.example.com",
                "canonical_name": "d123.cloudfront.net",
                "aliases": ["www.example.com"],
                "resolved_ips": ["203.0.113.10"],
                "hops": [
                    {"hostname": "www.example.com", "position": "query", "is_edge": False},
                    {
                        "hostname": "d123.cloudfront.net",
                        "position": "canonical",
                        "is_edge": True,
                        "provider": "aws-cloudfront",
                    },
                ],
                "error": None,
            },
            "origin_hints": [
                {
                    "hostname": "origin.internal.example.com",
                    "source": "tls_san",
                    "confidence": "medium",
                }
            ],
            "edge_hostnames": ["d123.cloudfront.net"],
            "redirect_hosts": ["origin.internal.example.com"],
            "summary": {
                "query_hostname": "www.example.com",
                "has_dns_chain": True,
                "edge_detected_in_chain": True,
                "hint_count": 1,
                "top_hints": ["origin.internal.example.com"],
                "redirect_host_count": 1,
            },
        }
    }

    with tempfile.TemporaryDirectory() as tmp:
        md = MarkdownReporter(output_dir=tmp)
        md_path = md.generate_report(scan_data, "203.0.113.10")
        with open(md_path, "r", encoding="utf-8") as handle:
            md_text = handle.read()
        assert_true("Origin Discovery" in md_text, "Markdown missing origin discovery section")
        assert_true("d123.cloudfront.net" in md_text, "Markdown missing DNS chain hop")
        assert_true("origin.internal.example.com" in md_text, "Markdown missing origin hint")

        jr = JSONReporter(output_dir=tmp)
        json_path = jr.generate_report(scan_data, "203.0.113.10")
        import json

        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        origin_summary = payload["summary"].get("origin_discovery", {})
        assert_true(origin_summary.get("hint_count") == 1, f"JSON summary wrong: {origin_summary}")
        assert_true(
            "origin.internal.example.com" in origin_summary.get("top_hints", []),
            f"JSON top hints wrong: {origin_summary}",
        )
    print("Origin discovery reports: OK")


def test_remediation_narrative():
    generator = RemediationNarrativeGenerator()

    edge_scan = {
        "reverse_dns": "one.one.one.one",
        "security_analysis": {
            "classification": {
                "classification": "managed_edge",
                "provider": "cloudflare",
                "role": "cloud-waf",
                "confidence": "high",
                "evidence": {
                    "rdns_match": "one.one.one.one",
                    "header_markers": {"cloudflare": ["cf-ray", "server: cloudflare"]},
                    "server_token": "cloudflare",
                },
            },
            "waf_cdn": {"services": ["cloudflare"]},
            "score": {"grade": "D", "percentage": 44.4},
        },
    }
    edge = generator.generate(edge_scan, "1.1.1.1")
    assert_true("managed edge" in edge["summary"].lower() or "cloud waf" in edge["summary"].lower(),
                f"Edge narrative missing context: {edge['summary']}")
    assert_true("origin" in edge["summary"].lower(), "Edge narrative should mention origin validation")
    assert_true(edge["suitable_for_remediation_response"], "Edge case should be ticket-ready")
    assert_true(any("origin" in action.lower() for action in edge["recommended_actions"]),
                f"Edge actions missing origin guidance: {edge['recommended_actions']}")

    origin_scan = {
        "security_analysis": {
            "classification": {
                "classification": "origin",
                "provider": None,
                "role": None,
                "confidence": "medium",
                "evidence": {},
            }
        }
    }
    origin = generator.generate(origin_scan, "203.0.113.50")
    assert_true("origin" in origin["summary"].lower(), f"Origin narrative wrong: {origin['summary']}")

    backport_scan = {
        "security_analysis": {"classification": {"classification": "origin", "confidence": "low"}},
        "backport_analysis": {
            "confidence": "high",
            "recommendation": "Validate Debian package patch levels before remediating.",
            "backport_evidence": [
                {"distribution": "debian", "indicator": "Apache/2.4.38 (Debian)", "pattern": "Debian"}
            ],
        },
    }
    backport = generator.generate(backport_scan, "203.0.113.51")
    assert_true("patch" in backport["summary"].lower(), f"Backport narrative missing: {backport['summary']}")
    assert_true(backport["suitable_for_remediation_response"], "Backport case should be ticket-ready")

    with tempfile.TemporaryDirectory() as tmp:
        edge_scan["remediation_narrative"] = edge
        md = MarkdownReporter(output_dir=tmp)
        md_path = md.generate_report(edge_scan, "1.1.1.1")
        with open(md_path, "r", encoding="utf-8") as handle:
            md_text = handle.read()
            assert_true("Remediation Narrative" in md_text, "Markdown missing narrative section")
            assert_true("cloudflare" in md_text.lower(), "Markdown narrative missing provider context")

        jr = JSONReporter(output_dir=tmp)
        json_path = jr.generate_report(edge_scan, "1.1.1.1")
        import json
        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
            narrative = payload["summary"].get("remediation_narrative", {})
            assert_true(narrative.get("summary"), "JSON summary missing narrative")
            assert_true(narrative.get("recommended_actions"), "JSON summary missing actions")

    print("Remediation narrative: OK")


def test_probe_host_ordering_and_limits():
    toolkit = SSCToolkit(Config.load())
    scan_data = {
        "reverse_dns": "edge.example.cdn",
        "tls_analysis": {
            "default_handshake": {
                "certificate": {
                    "subjectAltName": [
                        ("DNS", "www.example.com"),
                        ("DNS", "cdn.example.com"),
                    ]
                }
            }
        },
    }
    hosts = toolkit._build_host_candidates("203.0.113.10", "app.example.com", scan_data)
    assert_true(hosts[:2] == ["app.example.com", "203.0.113.10"], f"Primary host order wrong: {hosts}")
    assert_true("edge.example.cdn" in hosts[2:], f"PTR fallback missing: {hosts}")
    assert_true("www.example.com" in hosts, f"SAN fallback missing: {hosts}")

    assert_true(not toolkit._probe_succeeded({"error": "timeout", "final": {}}), "Error probe should fail")
    assert_true(not toolkit._probe_succeeded({"final": None}), "Null final should fail")
    assert_true(toolkit._probe_succeeded({"final": {"status_code": 200}}), "200 probe should succeed")
    assert_true(toolkit._safe_final_response({"final": None}) == {}, "Null final should normalize to {}")

    web_ports = [80, 443, 8080, 8443]
    candidates = ["203.0.113.10", "edge.example.cdn", "www.example.com", "cdn.example.com"]
    toolkit.config.scan.max_http_probes = 2
    toolkit.config.scan.max_host_candidates_per_port = 2

    class StubHTTPScanner:
        def __init__(self):
            self.calls = []

        def probe_http(self, ip, port, host=None, use_tls=False, method="GET", path="/",
                       stealth=False, capture_body=False, capture_bytes=0):
            self.calls.append((port, host))
            if port == 80:
                return {"final": {"status_code": 200, "headers": {"Server": ["nginx"]}}, "error": None}
            return {"final": {}, "error": "connection refused"}

    toolkit.http_scanner = StubHTTPScanner()
    result = toolkit._probe_web_services("203.0.113.10", None, scan_data, web_ports)
    assert_true(len(result["probes"]) == 2, f"Expected 2 probes, got {len(result['probes'])}")
    assert_true(toolkit.http_scanner.calls[0] == (80, None), "First probe should be IP on port 80")
    assert_true(toolkit.http_scanner.calls[1] == (443, None), "Second probe should be IP on port 443")
    print("Probe host ordering + limits: OK")


def test_contact_placeholder_enforcement():
    config = Config.load()
    assert_true(is_placeholder_contact("security@example.com"), "Template contact not detected")
    assert_true(not is_placeholder_contact("security@acme.example"), "Real contact flagged as placeholder")

    issues = contact_configuration_issues(config)
    assert_true(issues, f"Default config should report placeholder issues: {issues}")

    try:
        ensure_production_contact(config, allow_placeholder=False)
        raise AssertionError("Placeholder contact should block identified scans")
    except SystemExit:
        pass

    ensure_production_contact(config, allow_placeholder=True)
    print("Contact placeholder enforcement: OK")


def test_scan_diff():
    older = {
        "scan_results": {
            "metadata": {"target_ip": "203.0.113.10", "input_target": "example.com"},
            "reverse_dns": "old.example.net",
            "port_scan": {"open_ports": [80, 443]},
            "security_analysis": {
                "classification": {
                    "classification": "managed_edge",
                    "provider": "google",
                    "confidence": "medium",
                },
                "waf_cdn": {"services": ["azure-front-door"], "primary_service": "azure-front-door"},
                "score": {"grade": "C", "percentage": 66.7},
            },
            "tls_analysis": {"default_handshake": {"ok": True, "tls_version": "TLSv1.3"}, "days_until_expiry": 30},
        },
        "summary": {"open_ports": [80, 443], "security_score": {"grade": "C", "percentage": 66.7}},
    }
    newer = {
        "scan_results": {
            "metadata": {"target_ip": "203.0.113.10", "input_target": "example.com"},
            "reverse_dns": "new.example.net",
            "port_scan": {"open_ports": [80, 443, 8080]},
            "security_analysis": {
                "classification": {
                    "classification": "managed_edge",
                    "provider": "google",
                    "confidence": "high",
                },
                "waf_cdn": {"services": ["azure-front-door", "cloudflare"], "primary_service": "cloudflare"},
                "score": {"grade": "B", "percentage": 77.8},
            },
            "tls_analysis": {"default_handshake": {"ok": True, "tls_version": "TLSv1.3"}, "days_until_expiry": 60},
        },
        "summary": {"open_ports": [80, 443, 8080], "security_score": {"grade": "B", "percentage": 77.8}},
    }

    diff = compare_scan_reports(older, newer)
    assert_true(diff["compatible_targets"] is True, f"Targets should match: {diff}")
    assert_true(diff["change_count"] > 0, f"Expected changes: {diff}")
    changed_fields = {item["field"] for item in diff["changed"]}
    assert_true("open_ports" in changed_fields, f"Port change missing: {changed_fields}")
    assert_true("security_grade" in changed_fields, f"Grade change missing: {changed_fields}")
    assert_true("confidence" in changed_fields, f"Confidence change missing: {changed_fields}")

    text = format_scan_diff_text(diff, "older.json", "newer.json")
    assert_true("Changed" in text and "+8080" in text, f"Diff text missing port delta: {text}")
    print("Scan diff: OK")


def test_domain_target_resolution():
    assert_true(is_valid_hostname("example.com"), "Apex domain should be valid")
    assert_true(is_valid_hostname("www.example.com"), "Subdomain should be valid")
    assert_true(not is_valid_hostname("not-a-host"), "Single-label host should be invalid")

    ip_target = parse_target_input("203.0.113.10")
    assert_true(ip_target.ip == "203.0.113.10", f"IP target parse failed: {ip_target}")
    assert_true(ip_target.host is None, "IP target should not set host automatically")

    host_target = parse_target_input("203.0.113.10", explicit_host="app.example.com")
    assert_true(host_target.host == "app.example.com", f"Explicit host not preserved: {host_target}")

    original_getaddrinfo = socket.getaddrinfo

    def stub_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host == "example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0))]
        if host == "www.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.11", 0))]
        return original_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = stub_getaddrinfo
    try:
        apex = parse_target_input("example.com")
        assert_true(apex.ip == "203.0.113.10", f"Apex resolve failed: {apex}")
        assert_true(apex.host == "example.com", f"Apex host not preserved: {apex}")

        sub = parse_target_input("www.example.com")
        assert_true(sub.ip == "203.0.113.11", f"Subdomain resolve failed: {sub}")
        assert_true(sub.host == "www.example.com", f"Subdomain host not preserved: {sub}")
    finally:
        socket.getaddrinfo = original_getaddrinfo

    print("Domain target resolution: OK")


def test_scan_profiles():
    config = Config.load()
    web_ports, web_only, web_label = resolve_scan_options(config, profile="web")
    assert_true(web_ports == PROFILE_PRESETS["web"]["ports"], f"Web ports wrong: {web_ports}")
    assert_true(web_only is True, "Web profile should enable only_web")
    assert_true(web_label == "web", f"Web label wrong: {web_label}")

    quick_ports, quick_only, quick_label = resolve_scan_options(config, profile="quick")
    assert_true(22 in quick_ports and 443 in quick_ports, f"Quick ports missing expected entries: {quick_ports}")
    assert_true(quick_only is False, "Quick profile should not force only_web")
    assert_true(quick_label == "quick", f"Quick label wrong: {quick_label}")

    full_ports, full_only, full_label = resolve_scan_options(config, profile="full")
    assert_true(full_ports is None, f"Full profile should defer to config ports: {full_ports}")
    assert_true(full_only is False, "Full profile should not force only_web")
    assert_true(full_label == "full", f"Full label wrong: {full_label}")

    custom_ports, _, custom_label = resolve_scan_options(
        config, profile="quick", ports=[80, 443]
    )
    assert_true(custom_ports == [80, 443], f"Explicit ports not honored: {custom_ports}")
    assert_true(custom_label == "custom", f"Custom label wrong: {custom_label}")

    try:
        resolve_scan_options(config, profile="invalid")
        raise AssertionError("Invalid profile should raise ValueError")
    except ValueError:
        pass
    print("Scan profiles: OK")


def test_scan_signature_confirmation():
    assert_true(confirm_scan_session(assume_yes=True) is True, "--yes should auto-confirm")
    parser = create_parser()
    scan_args = parser.parse_args(["scan", "203.0.113.10", "-y"])
    batch_args = parser.parse_args(["batch", "targets.txt", "--yes"])
    assert_true(scan_args.yes is True, "scan --yes not parsed")
    assert_true(batch_args.yes is True, "batch --yes not parsed")
    print("Scan signature confirmation: OK")


def test_scan_signature_banner():
    config = Config.load()
    identified = "\n".join(format_scan_signature_banner(config, stealth=False))
    assert_true("identified (SIEM-friendly)" in identified, f"Identified banner wrong: {identified}")
    assert_true("User-Agent:" in identified, f"User-Agent missing: {identified}")
    assert_true("X-Security-Scan:" in identified, f"Signature header missing: {identified}")
    assert_true("X-Contact:" in identified, f"Contact header missing: {identified}")

    stealth = "\n".join(format_scan_signature_banner(config, stealth=True))
    assert_true("stealth" in stealth.lower(), f"Stealth banner wrong: {stealth}")
    assert_true("X-Contact" not in stealth, f"Stealth banner should not list contact header: {stealth}")
    print("Scan signature banner: OK")


def test_scan_log_session():
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "scan_203.0.113.10_123.log")
        with scan_log_session(log_path):
            scan_log("probe complete", also_print=False)
        with open(log_path, "r", encoding="utf-8") as handle:
            text = handle.read()
        assert_true("probe complete" in text, f"Scan log missing message: {text}")
        assert_true("log started" in text.lower(), f"Scan log missing header: {text}")
    print("Scan log session: OK")


def test_batch_flag_passthrough():
    parser = create_parser()
    args = parser.parse_args([
        "batch",
        "targets.txt",
        "--threads",
        "3",
        "--output-csv",
        "--evidence",
        "--backports",
        "--only-web",
        "--no-port-scan",
    ])
    assert_true(args.command == "batch", f"Expected batch command, got {args.command}")
    assert_true(args.evidence, "Batch --evidence flag not parsed")
    assert_true(args.backports, "Batch --backports flag not parsed")
    assert_true(args.only_web, "Batch --only-web flag not parsed")
    assert_true(args.no_port_scan, "Batch --no-port-scan flag not parsed")

    with tempfile.TemporaryDirectory() as tmp:
        config = Config.load()
        config.output.base_dir = tmp
        toolkit = SSCToolkit(config)
        original_scan = toolkit.scan_target
        original_enrich = toolkit.enrich_scan_data
        original_narrative = toolkit.attach_remediation_narrative
        original_reports = toolkit.generate_reports
        original_evidence_reports = toolkit.generate_evidence_reports
        calls = {"scan": [], "enrich": []}

        def stub_scan_target(target_ip, **kwargs):
            calls["scan"].append((target_ip, kwargs))
            return {
                "metadata": {"target_ip": target_ip},
                "port_scan": {"open_ports": [80, 443], "banners": {}},
                "http_analysis": {"probes": []},
                "security_analysis": {},
            }

        def stub_enrich(scan_data, target_ip, evidence=False, backports=False):
            calls["enrich"].append((target_ip, evidence, backports))
            enriched = dict(scan_data)
            if backports:
                enriched["backport_analysis"] = {"confidence": "low"}
            if evidence:
                enriched["evidence"] = {"assessment": {"overall": "low", "evidence_count": 1}}
            return enriched

        toolkit.scan_target = stub_scan_target
        toolkit.enrich_scan_data = stub_enrich
        toolkit.attach_remediation_narrative = lambda data, _ip: data
        toolkit.generate_reports = lambda _data, _ip: {}
        toolkit.generate_evidence_reports = lambda _data, _ip: {}

        result = run_batch_target(
            toolkit,
            ScanTarget(input="203.0.113.10", ip="203.0.113.10"),
            only_web=True,
            skip_port_scan=True,
            evidence=True,
            backports=True,
            profile="web",
        )
        assert_true(result["success"], f"Batch target run failed: {result}")
        assert_true(calls["scan"], "scan_target was not called")
        scan_kwargs = calls["scan"][0][1]
        assert_true(scan_kwargs.get("only_web") is True, f"only_web not passed: {scan_kwargs}")
        assert_true(scan_kwargs.get("skip_port_scan") is True, f"skip_port_scan not passed: {scan_kwargs}")
        assert_true(scan_kwargs.get("profile") == "web", f"profile not passed: {scan_kwargs}")
        assert_true(calls["enrich"] == [("203.0.113.10", True, True)], f"enrich calls wrong: {calls['enrich']}")
        assert_true("backport_analysis" in result, "Backport analysis missing from batch result")
        assert_true("evidence" in result, "Evidence missing from batch result")
        log_path = (result.get("metadata") or {}).get("scan_log")
        assert_true(log_path and os.path.exists(log_path), f"Per-scan log missing: {log_path}")

        toolkit.scan_target = original_scan
        toolkit.enrich_scan_data = original_enrich
        toolkit.attach_remediation_narrative = original_narrative
        toolkit.generate_reports = original_reports
        toolkit.generate_evidence_reports = original_evidence_reports
    print("Batch flag passthrough: OK")


def test_enrich_scan_data_and_scan_loader():
    scan_data = {
        "http_analysis": {
            "probes": [
                {
                    "port": 443,
                    "result": {"final": {"headers": {"Server": ["Apache/2.4.38 (Debian)"]}}},
                    "security_headers": {
                        "present": ["strict-transport-security"],
                        "values": {"strict-transport-security": ["max-age=31536000"]},
                    },
                    "waf_cdn": {"services": [], "evidence": {}},
                }
            ]
        },
        "security_analysis": {
            "security_headers": {
                "present": ["strict-transport-security"],
                "score": {"percentage": 44.4, "grade": "D"},
            }
        },
    }

    toolkit = SSCToolkit(Config.load())
    enriched = toolkit.enrich_scan_data(scan_data, "203.0.113.10", evidence=True, backports=True)
    assert_true("backport_analysis" in enriched, "Backport analysis missing")
    assert_true("evidence" in enriched, "Evidence block missing")
    assert_true(enriched["evidence"]["assessment"]["evidence_count"] > 0, "Evidence count should be > 0")

    with tempfile.TemporaryDirectory() as tmp:
        json_reporter = JSONReporter(output_dir=tmp)
        scan_path = json_reporter.generate_report(enriched, "203.0.113.10")
        loaded = load_scan_data_from_file(scan_path)
        assert_true("backport_analysis" in loaded, "Loaded scan missing backport analysis")
        assert_true("summary" not in loaded, "Loader should return scan_results only")
    print("Enrich scan data + scan loader: OK")


# Throwaway self-signed certificate used ONLY by the offline TLS test below.
# Generated for CN=offline-test.invalid with a 100-year validity; it grants
# access to nothing and is intentionally committed.
TEST_TLS_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDQjCCAiqgAwIBAgIUJADeSTnjtsuIp3b2fX/DPICvUhwwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUb2ZmbGluZS10ZXN0LmludmFsaWQwIBcNMjYwNjEyMTg0
MTQwWhgPMjEyNjA1MTkxODQxNDBaMB8xHTAbBgNVBAMMFG9mZmxpbmUtdGVzdC5p
bnZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0TjMOYK0DBK2
p8nB26VIx3lfpuIeaNnHP1Wk3lgWTRDwbldqarMtAsbyfJxVl2Qj+crV/ZWIbxFh
T6ya/rRrzVPBKVeJrXoB2dsZ7SmHXdATiApCxhSr0vaLCkAevMgY7GE+QbDRmBgq
LJ1H1o8CIy+muuG7FhD8LVs9PKKiD61mj37HTWwhGobNRQa5QUNkj/xLaGes7CAQ
DJew/rKCBdZ1o3iPHvyWmXfFT4Pu0x+noJwOQQ0+DwKyJrQlHu8EF8Ercxq+6ylY
hgNw47i79wHRYM43xPetnnX2tb/vGPr6CU4xoTWkwnj7QKHWaKagDYsCs68iLPGP
owgiDk8B/wIDAQABo3QwcjAdBgNVHQ4EFgQUgN+f4oG05JElCOZw4AeR6VNmaZYw
HwYDVR0jBBgwFoAUgN+f4oG05JElCOZw4AeR6VNmaZYwDwYDVR0TAQH/BAUwAwEB
/zAfBgNVHREEGDAWghRvZmZsaW5lLXRlc3QuaW52YWxpZDANBgkqhkiG9w0BAQsF
AAOCAQEAxhpnbbL8BbWDxUULAzN+YGX0GXYkl+hvvvriZuYxP0xdRoIOrxYFHHSz
GYa4dNSjgoGo673duAIDAQ7V8EAQfYEh1PF6M5ZW/zfaR1KKg+4GnSKZC+RzbIOL
E6fMLa7DUtflBuAujq0/5i3pSTO5dSVXYeO3RE/eWTVeYu8mtO3DBr2HcQhZAPYy
fyO2fsIqoYtwFRLgONWKU4NskA3oNaxrzO/SoHsrq04W9JTsUAw8RiD2i5LDTBq+
d7a2Yc9qocG67SGwR2EuhkZSOUYgjpv4famw9pb0hCiTCYGba+B4m/swnVtyWufy
lb23NX5DCA2WZ08VTiUQlqknPYdQMQ==
-----END CERTIFICATE-----
"""

TEST_TLS_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDROMw5grQMEran
ycHbpUjHeV+m4h5o2cc/VaTeWBZNEPBuV2pqsy0CxvJ8nFWXZCP5ytX9lYhvEWFP
rJr+tGvNU8EpV4mtegHZ2xntKYdd0BOICkLGFKvS9osKQB68yBjsYT5BsNGYGCos
nUfWjwIjL6a64bsWEPwtWz08oqIPrWaPfsdNbCEahs1FBrlBQ2SP/EtoZ6zsIBAM
l7D+soIF1nWjeI8e/JaZd8VPg+7TH6egnA5BDT4PArImtCUe7wQXwStzGr7rKViG
A3DjuLv3AdFgzjfE962edfa1v+8Y+voJTjGhNaTCePtAodZopqANiwKzryIs8Y+j
CCIOTwH/AgMBAAECggEAPLkcZPCvavWfd9FR53rwRZzPizMDmnDiqFomELZGOrXY
4l2SsEcyoCS3yjzhhp/05RHey8uznnDP6nzxO02IID7XyDT065mGogE6ZB/yfuLe
WFSKDs1/FSqjLiVwBmCZAzoyBITaQCd7ThmT+QzmlOnGnWTYlM33Mv7RJiEZoiyu
LmveAwGb3U9y1immfXbZMVzzIS26iqVMTMj4LgQMb0zAiFpDcwVFZB4ZF5hnOJ3a
APS+RwLsc/Ee/K9KzmwxRyRq/ehjD5ri2DPRCeNLhBxcuzYJo950KozEoo8zr1oU
G2DRaHfRXoBr9KtBVTORxeXHo0ILkfSo4XRHjm8b6QKBgQDwy/eUkw/uhgW93Iw5
qsQQaZWUY6gMlpzoT4Q7h5wNkPqPMwZPA7cNFtkN0BUtUgbTN8pG+lciK41JKeHq
zX+uo+nnT2pZNOktF7d3yf4nxjs+tk8c/OjGen4G1wu9A5ogr5jE9Pddw97ZZo/w
injVKc68FtgdKBItsXzpIjKwUwKBgQDebnszVddmuHmuyuVu7KETFlfLwcCjtQga
IW9J7Rdq+g7svI8AR/H3Qvd5jQ9LhiuEAlWClfRBZme1wl2nikjwmeSdkZ2RoMxL
9agU9tbPXQsYBYj1XgPW2vSR3oSFcJ5nR+dYmhWUf+Byx0dQ32sceHmKM8jj4ijD
IMg3sB2iJQKBgQCcYMnzaiJBlDYsXAuQ886KnhcvHB0pt7JEyEcm5eW5hbrCvq9N
Jyt8y6bAaq8mFIwsJaIuwCtQHJqPtixqcXSHNRoVRyTYtBzuVOWoXLy6lekpy/nK
6JA/PZOU25la8fjpW0BKQJBZC3gxFYNLApKAVLtWuTs2jCxqEkb9nGDw0wKBgQCX
Dlq2uzZEeUWR8hKsKSEekE7hflxwEPJGpKwqfUwpB1b5aPiIjVOCw0TDlIttk9mb
leYyf9nYTE5kPnJR5HSyiSCb7Zcfnh7/+v3B9vxc6Ogu0Rt43vcmg54SLha7dIbu
xwMSxdmf9tQbvr/s6T2ZoSuRMqfcMuvR0EKIpx8IzQKBgB+g7zx1ft3Qm3GJr+CM
a2YeY1PfospBHJoBxHkZAyzALiM5Ccy45McFpqRKs0vdaribFQqlu2bvgVMmp0z2
TkMqe4g1TcdKtkinVMrqRNhGQxFbg7/IhQFCEbwG6HyhKQVKPKiggcd3ftXf0rr/
jdwZbB0xnkAA204sDo8hfOJ6
-----END PRIVATE KEY-----
"""


def test_tls_self_signed_extraction():
    """TLS analysis must capture cert details even when the chain is untrusted."""
    import ssl
    import threading

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "key.pem")
        with open(cert_path, "w", encoding="utf-8") as handle:
            handle.write(TEST_TLS_CERT_PEM)
        with open(key_path, "w", encoding="utf-8") as handle:
            handle.write(TEST_TLS_KEY_PEM)

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_path, key_path)
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(5)

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    break
                try:
                    tls_conn = server_ctx.wrap_socket(conn, server_side=True)
                    tls_conn.recv(64)
                    tls_conn.close()
                except OSError:
                    conn.close()

        threading.Thread(target=serve, daemon=True).start()

        scanner = TLSScanner(ScanConfig())
        result = scanner.analyze_certificate("127.0.0.1", port, server_name="offline-test.invalid")
        server.close()

    assert_true(result.get("ok"), f"Self-signed handshake failed: {result.get('error')}")
    cert = result.get("certificate") or {}
    assert_true(cert, "Certificate missing for self-signed target")
    assert_true(
        "offline-test.invalid" in str(cert.get("subject")),
        f"CN missing from self-signed cert: {cert.get('subject')}",
    )
    sans = TLSScanner(ScanConfig()).extract_sans({"certificate": cert})
    assert_true("offline-test.invalid" in sans, f"SAN missing from self-signed cert: {sans}")
    print("TLS self-signed extraction: OK")


def test_batch_summary_stats():
    import json

    batch_results = {
        "targets": ["203.0.113.10"],
        "results": [
            {
                "target_ip": "203.0.113.10",
                "success": True,
                "port_scan": {"open_ports": [80, 443]},
                "security_analysis": {"waf_cdn": {"services": ["cloudflare"]}},
            }
        ],
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = JSONReporter(output_dir=tmp).generate_batch_summary(batch_results, "stats")
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    stats = payload["summary"]
    assert_true(stats["total_open_ports"] == 2, f"total_open_ports wrong: {stats}")
    assert_true(stats["unique_services"] == 1, f"unique_services wrong: {stats}")
    print("Batch summary stats: OK")


def test_dns_lookups_leave_default_timeout():
    from ssc.utils.network import reverse_dns

    socket.setdefaulttimeout(None)
    reverse_dns("127.0.0.1", timeout=1.0)
    assert_true(
        socket.getdefaulttimeout() is None,
        f"reverse_dns leaked global socket timeout: {socket.getdefaulttimeout()}",
    )
    print("DNS lookups leave default timeout: OK")


def test_unique_output_paths():
    import time as time_mod

    scan_data = {"metadata": {"target_ip": "203.0.113.10"}}
    original_time = time_mod.time
    time_mod.time = lambda: 1700000000.0
    try:
        with tempfile.TemporaryDirectory() as tmp:
            reporter = JSONReporter(output_dir=tmp)
            first = reporter.generate_report(scan_data, "203.0.113.10")
            second = reporter.generate_report(scan_data, "203.0.113.10")
            assert_true(first != second, f"JSON report paths collide: {first}")
            assert_true(os.path.exists(first) and os.path.exists(second), "Both JSON reports should exist")

            md_reporter = MarkdownReporter(output_dir=tmp)
            md_first = md_reporter.generate_report(scan_data, "203.0.113.10")
            md_second = md_reporter.generate_report(scan_data, "203.0.113.10")
            assert_true(md_first != md_second, f"Markdown report paths collide: {md_first}")

            log_path = os.path.join(tmp, "scan_203.0.113.10_1700000000.log")
            with scan_log_session(log_path) as first_log:
                scan_log("first session", also_print=False)
            with scan_log_session(log_path) as second_log:
                scan_log("second session", also_print=False)
            assert_true(first_log != second_log, f"Log paths collide: {first_log}")
            with open(first_log, "r", encoding="utf-8") as handle:
                assert_true("first session" in handle.read(), "First log was clobbered by second session")
    finally:
        time_mod.time = original_time
    print("Unique output paths: OK")


def test_scan_diff_order_insensitive():
    from ssc.analyzers.scan_diff import _set_delta

    older = {
        "scan_results": {"metadata": {"target_ip": "203.0.113.10"}},
        "summary": {"web_services": ["HTTPS 443", "HTTP 80"]},
    }
    newer = {
        "scan_results": {"metadata": {"target_ip": "203.0.113.10"}},
        "summary": {"web_services": ["HTTP 80", "HTTPS 443"]},
    }
    diff = compare_scan_reports(older, newer)
    changed_fields = {item["field"] for item in diff["changed"]}
    assert_true(
        "web_services" not in changed_fields,
        f"Order-only web_services change flagged: {changed_fields}",
    )

    delta = _set_delta([18080, 18443], [8443])
    assert_true(
        "+8443" in delta and "-18080" in delta and "-18443" in delta,
        f"Delta rendering ambiguous: {delta}",
    )
    print("Scan diff order insensitivity: OK")


def main():
    test_classifier()
    test_http_parser_features()
    test_markdown_report()
    test_json_summary()
    test_tls_certificate_formatting()
    test_security_score_promotion()
    test_backport_csv_and_batch_helpers()
    test_waf_cdn_detector()
    test_dns_chain_resolution()
    test_origin_discovery_analyzer()
    test_origin_discovery_reports()
    test_remediation_narrative()
    test_probe_host_ordering_and_limits()
    test_contact_placeholder_enforcement()
    test_scan_diff()
    test_domain_target_resolution()
    test_scan_profiles()
    test_scan_signature_confirmation()
    test_scan_signature_banner()
    test_scan_log_session()
    test_batch_flag_passthrough()
    test_enrich_scan_data_and_scan_loader()
    test_tls_self_signed_extraction()
    test_batch_summary_stats()
    test_dns_lookups_leave_default_timeout()
    test_unique_output_paths()
    test_scan_diff_order_insensitive()
    print("All offline validations passed.")


if __name__ == "__main__":
    main()
