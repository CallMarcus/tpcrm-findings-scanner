"""Compare two TPCRM Findings Scanner JSON reports."""

from typing import Any, Dict, List, Optional, Set, Tuple


def _scan_body(payload: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(payload.get("scan_results"), dict):
        return payload["scan_results"]
    return payload


def _summary_body(payload: Dict[str, Any]) -> Dict[str, Any]:
    summary = payload.get("summary")
    if isinstance(summary, dict):
        return summary
    return {}


def extract_scan_snapshot(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract comparable fields from a report or raw scan_results payload."""
    scan = _scan_body(payload)
    summary = _summary_body(payload)
    metadata = scan.get("metadata", {}) or {}
    top_metadata = payload.get("metadata", {}) or {}

    security = scan.get("security_analysis", {}) or {}
    classification = security.get("classification", {}) or {}
    waf_cdn = security.get("waf_cdn", {}) or {}
    score = security.get("score") or (security.get("security_headers", {}) or {}).get("score") or {}

    tls = (scan.get("tls_analysis", {}) or {}).get("default_handshake", {}) or {}
    backport = scan.get("backport_analysis", {}) or {}
    evidence = (scan.get("evidence", {}) or {}).get("assessment", {}) or {}

    env_summary = summary.get("environment", {}) or {}
    security_summary = summary.get("security_score", {}) or {}

    return {
        "target_ip": metadata.get("target_ip") or top_metadata.get("target_ip"),
        "input_target": metadata.get("input_target") or metadata.get("target_ip"),
        "host": metadata.get("host"),
        "scan_profile": metadata.get("scan_profile"),
        "timestamp": metadata.get("timestamp") or top_metadata.get("timestamp"),
        "reverse_dns": scan.get("reverse_dns"),
        "open_ports": sorted((scan.get("port_scan", {}) or {}).get("open_ports", []) or []),
        "web_services": sorted(
            summary.get("web_services") or _web_services_from_probes(scan)
        ),
        "classification": classification.get("classification") or env_summary.get("classification"),
        "provider": classification.get("provider") or env_summary.get("provider"),
        "role": classification.get("role") or env_summary.get("role"),
        "confidence": classification.get("confidence") or env_summary.get("confidence"),
        "waf_cdn_services": sorted(waf_cdn.get("services", []) or []),
        "primary_service": waf_cdn.get("primary_service"),
        "security_grade": score.get("grade") or security_summary.get("grade"),
        "security_percentage": score.get("percentage") if score.get("percentage") is not None else security_summary.get("percentage"),
        "tls_ok": tls.get("ok"),
        "tls_version": tls.get("tls_version"),
        "days_until_expiry": scan.get("tls_analysis", {}).get("days_until_expiry"),
        "backport_confidence": backport.get("confidence") or summary.get("backport_confidence"),
        "evidence_overall": evidence.get("overall") or (summary.get("evidence_assessment", {}) or {}).get("overall"),
        "narrative_suitable": (scan.get("remediation_narrative", {}) or {}).get("suitable_for_remediation_response"),
    }


def _web_services_from_probes(scan: Dict[str, Any]) -> List[str]:
    services: List[str] = []
    probes = (scan.get("http_analysis", {}) or {}).get("probes", []) or []
    for probe in probes:
        final = (probe.get("result", {}) or {}).get("final", {}) or {}
        if final.get("status_code") is None:
            continue
        protocol = "HTTPS" if probe.get("use_tls") else "HTTP"
        services.append(f"{protocol} {probe.get('port')}")
    return services


def _targets_compatible(old: Dict[str, Any], new: Dict[str, Any]) -> Tuple[bool, str]:
    old_ip = old.get("target_ip")
    new_ip = new.get("target_ip")
    if old_ip and new_ip and old_ip != new_ip:
        return False, f"target_ip differs ({old_ip} vs {new_ip})"

    old_inputs = {value for value in (old.get("input_target"), old.get("host")) if value}
    new_inputs = {value for value in (new.get("input_target"), new.get("host")) if value}
    if old_inputs and new_inputs and old_inputs.isdisjoint(new_inputs):
        return False, f"input_target/host differ ({sorted(old_inputs)} vs {sorted(new_inputs)})"

    return True, "targets appear compatible"


def _format_value(value: Any) -> str:
    if value is None:
        return "(none)"
    if isinstance(value, list):
        return "[" + ", ".join(str(item) for item in value) + "]" if value else "[]"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def _set_delta(old_values: List[Any], new_values: List[Any]) -> Optional[str]:
    old_set = set(old_values)
    new_set = set(new_values)
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    parts = []
    if added:
        parts.append(", ".join(f"+{item}" for item in added))
    if removed:
        parts.append(", ".join(f"-{item}" for item in removed))
    return ", ".join(parts) if parts else None


TRACKED_FIELDS = [
    "reverse_dns",
    "open_ports",
    "web_services",
    "classification",
    "provider",
    "role",
    "confidence",
    "waf_cdn_services",
    "primary_service",
    "security_grade",
    "security_percentage",
    "tls_ok",
    "tls_version",
    "days_until_expiry",
    "backport_confidence",
    "evidence_overall",
    "narrative_suitable",
]


def compare_scan_reports(old_payload: Dict[str, Any], new_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two scan reports and return structured diff data."""
    old = extract_scan_snapshot(old_payload)
    new = extract_scan_snapshot(new_payload)
    compatible, compatibility_note = _targets_compatible(old, new)

    changed: List[Dict[str, Any]] = []
    unchanged: List[str] = []

    for field in TRACKED_FIELDS:
        old_value = old.get(field)
        new_value = new.get(field)
        if old_value == new_value:
            unchanged.append(f"{field}: {_format_value(old_value)}")
            continue

        entry: Dict[str, Any] = {
            "field": field,
            "old": old_value,
            "new": new_value,
        }
        if field in ("open_ports", "web_services", "waf_cdn_services"):
            entry["delta"] = _set_delta(old_value or [], new_value or [])
        changed.append(entry)

    return {
        "compatible_targets": compatible,
        "compatibility_note": compatibility_note,
        "older": {
            "target_ip": old.get("target_ip"),
            "input_target": old.get("input_target"),
            "timestamp": old.get("timestamp"),
            "scan_profile": old.get("scan_profile"),
        },
        "newer": {
            "target_ip": new.get("target_ip"),
            "input_target": new.get("input_target"),
            "timestamp": new.get("timestamp"),
            "scan_profile": new.get("scan_profile"),
        },
        "changed": changed,
        "unchanged": unchanged,
        "change_count": len(changed),
    }


def format_scan_diff_text(diff: Dict[str, Any], older_path: str, newer_path: str) -> str:
    """Render a human-readable diff report."""
    lines = [
        f"Scan diff: {older_path} -> {newer_path}",
        (
            f"Older: {diff['older'].get('input_target')} "
            f"({diff['older'].get('target_ip')}) @ {diff['older'].get('timestamp') or 'unknown'}"
        ),
        (
            f"Newer: {diff['newer'].get('input_target')} "
            f"({diff['newer'].get('target_ip')}) @ {diff['newer'].get('timestamp') or 'unknown'}"
        ),
    ]

    if diff["compatible_targets"]:
        lines.append("Target match: OK")
    else:
        lines.append(f"Target match: WARNING — {diff['compatibility_note']}")

    lines.append("")
    if not diff["changed"]:
        lines.append("No material changes detected in tracked fields.")
    else:
        lines.append(f"Changed ({diff['change_count']}):")
        for item in diff["changed"]:
            delta = item.get("delta")
            delta_text = f" ({delta})" if delta else ""
            lines.append(
                f"  {item['field']}: {_format_value(item['old'])} -> "
                f"{_format_value(item['new'])}{delta_text}"
            )

    lines.append("")
    lines.append(f"Unchanged ({len(diff['unchanged'])}):")
    for item in diff["unchanged"]:
        lines.append(f"  {item}")

    return "\n".join(lines)