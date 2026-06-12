#!/usr/bin/env python3
"""
Live validation for TPCRM Findings Scanner (requires network access).

Validates against:
- A known CDN/WAF edge target (default: 1.1.1.1 / Cloudflare)
- A likely direct-origin target (default: scanme.nmap.org)

Checks classification, remediation narrative, probe limits, TLS extraction,
and JSON summary shape on real scan results.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from cli import SSCToolkit  # noqa: E402
from ssc.config import Config  # noqa: E402
from ssc.utils import begin_scan_session  # noqa: E402
from ssc.reporters.json_reporter import JSONReporter  # noqa: E402
from ssc.reporters.markdown_reporter import MarkdownReporter  # noqa: E402


class ValidationError(AssertionError):
    """Raised when a live validation check fails."""


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def resolve_host(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise ValidationError(f"Cannot resolve {hostname}: {exc}") from exc


def successful_probes(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    probes = (scan_data.get("http_analysis", {}) or {}).get("probes", []) or []
    successful = []
    for probe in probes:
        result = probe.get("result") or {}
        final = result.get("final") if isinstance(result.get("final"), dict) else {}
        if result.get("error"):
            continue
        if final.get("status_code") is not None:
            successful.append(probe)
    return successful


def validate_json_and_markdown(
    scan_data: Dict[str, Any],
    target_ip: str,
    expect_narrative_keywords: Optional[List[str]] = None,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        json_path = JSONReporter(output_dir=tmp).generate_report(scan_data, target_ip)
        md_path = MarkdownReporter(output_dir=tmp).generate_report(scan_data, target_ip)

        assert_true(Path(json_path).exists(), "JSON report was not created")
        assert_true(Path(md_path).exists(), "Markdown report was not created")

        with open(json_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)

        summary = report.get("summary", {})
        assert_true(summary, "JSON summary block missing")
        assert_true(summary.get("environment") or summary.get("web_services") is not None,
                    "JSON summary missing environment/web service context")

        narrative = summary.get("remediation_narrative", {})
        assert_true(narrative.get("summary"), "JSON summary missing remediation narrative")
        assert_true(narrative.get("recommended_actions"), "JSON summary missing recommended actions")

        with open(md_path, "r", encoding="utf-8") as handle:
            md_text = handle.read()

        assert_true("Remediation Narrative" in md_text, "Markdown missing remediation narrative section")
        if expect_narrative_keywords:
            lowered = md_text.lower()
            assert_true(
                any(keyword in lowered for keyword in expect_narrative_keywords),
                f"Markdown narrative missing expected keywords: {expect_narrative_keywords}",
            )


def validate_cdn_target(toolkit: SSCToolkit, target_ip: str) -> None:
    print(f"[*] Live CDN validation: {target_ip}")
    scan_data = toolkit.scan_target(target_ip, only_web=True)
    scan_data = toolkit.attach_remediation_narrative(scan_data, target_ip)

    assert_true("error" not in scan_data, f"CDN scan failed: {scan_data.get('error')}")

    probes = (scan_data.get("http_analysis", {}) or {}).get("probes", []) or []
    assert_true(
        len(probes) <= toolkit.config.scan.max_http_probes,
        f"Probe count exceeded cap: {len(probes)} > {toolkit.config.scan.max_http_probes}",
    )
    assert_true(successful_probes(scan_data), "CDN target produced no successful HTTP probes")

    tls = (scan_data.get("tls_analysis", {}) or {}).get("default_handshake", {}) or {}
    assert_true(tls.get("ok"), f"TLS handshake failed on CDN target: {tls.get('error')}")
    assert_true(tls.get("certificate"), "TLS certificate missing on CDN target")

    security = scan_data.get("security_analysis", {}) or {}
    classification = security.get("classification", {}) or {}
    waf_services = security.get("waf_cdn", {}).get("services", []) or []

    edge_signals = (
        classification.get("classification") == "managed_edge"
        or bool(waf_services)
        or classification.get("provider") in {"cloudflare", "aws-cloudfront", "akamai", "fastly", "google"}
    )
    assert_true(edge_signals, f"CDN target missing edge/WAF signals: classification={classification}, waf={waf_services}")

    narrative = scan_data.get("remediation_narrative", {}) or {}
    assert_true(narrative.get("summary"), "Remediation narrative missing on CDN target")
    assert_true(
        narrative.get("suitable_for_remediation_response"),
        "CDN target should be suitable for remediation response",
    )

    validate_json_and_markdown(
        scan_data,
        target_ip,
        expect_narrative_keywords=["edge", "waf", "protection", "cloudflare", "origin"],
    )
    print(f"[+] CDN validation passed: {target_ip}")


def validate_origin_target(toolkit: SSCToolkit, target_ip: str, hostname: str) -> None:
    print(f"[*] Live origin validation: {hostname} ({target_ip})")
    scan_data = toolkit.scan_target(target_ip, host=hostname, only_web=True)
    scan_data = toolkit.attach_remediation_narrative(scan_data, target_ip)

    assert_true("error" not in scan_data, f"Origin scan failed: {scan_data.get('error')}")
    assert_true(successful_probes(scan_data), "Origin target produced no successful HTTP probes")

    security = scan_data.get("security_analysis", {}) or {}
    classification = security.get("classification", {}) or {}
    env_class = classification.get("classification")
    confidence = classification.get("confidence")
    provider = classification.get("provider")

    major_edge_providers = {"cloudflare", "aws-cloudfront", "akamai", "fastly", "google", "azure-front-door"}
    assert_true(
        not (env_class == "managed_edge" and confidence == "high" and provider in major_edge_providers),
        f"Origin candidate looks like major managed edge: {classification}",
    )

    acceptable_origin_classes = {"origin", "unknown", None}
    if env_class not in acceptable_origin_classes and env_class == "managed_edge":
        assert_true(
            confidence in ("low", "medium"),
            f"Origin candidate unexpectedly classified as managed edge: {classification}",
        )

    narrative = scan_data.get("remediation_narrative", {}) or {}
    assert_true(narrative.get("summary"), "Remediation narrative missing on origin target")
    assert_true(narrative.get("recommended_actions"), "Origin narrative missing recommended actions")

    validate_json_and_markdown(scan_data, target_ip)
    print(f"[+] Origin validation passed: {hostname} ({target_ip})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run live TPCRM Findings Scanner validations against real targets.")
    parser.add_argument("--cdn-ip", default="1.1.1.1", help="Known CDN/WAF edge IP (default: 1.1.1.1)")
    parser.add_argument(
        "--origin-host",
        default="scanme.nmap.org",
        help="Hostname that should behave more like a direct origin (default: scanme.nmap.org)",
    )
    parser.add_argument("--skip-origin", action="store_true", help="Only run the CDN edge validation")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-connection timeout for live scans")
    parser.add_argument("--config", help="Optional config file path")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    config = Config.load(args.config)
    config.scan.timeout = max(config.scan.timeout, args.timeout)
    toolkit = SSCToolkit(config)

    # Mirror `cli.py scan -y`: show signature banner, skip interactive confirmation.
    begin_scan_session(config, stealth=False, assume_yes=True, allow_placeholder=True)

    validate_cdn_target(toolkit, args.cdn_ip)

    if not args.skip_origin:
        origin_ip = resolve_host(args.origin_host)
        validate_origin_target(toolkit, origin_ip, args.origin_host)

    print("All live validations passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc