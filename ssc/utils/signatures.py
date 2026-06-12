"""SIEM-friendly signature utilities"""

from typing import Dict, List, Optional

from ..config import Config, SignatureConfig

PLACEHOLDER_CONTACTS = {
    "security@yourcompany.com",
    "security@example.com",
    "your@email.com",
}


def is_placeholder_contact(contact: Optional[str]) -> bool:
    """Return True when contact is empty or still a template value."""
    normalized = (contact or "").strip().lower()
    return not normalized or normalized in PLACEHOLDER_CONTACTS


def contact_configuration_issues(config: Config) -> List[str]:
    """Return human-readable issues when signature contact is not production-ready."""
    issues: List[str] = []
    contact = (config.signature.contact_value or "").strip()

    if is_placeholder_contact(contact):
        issues.append(
            f"contact_value is unset or placeholder ({contact or 'empty'})"
        )

    user_agent = (config.signature.user_agent or "").lower()
    for placeholder in PLACEHOLDER_CONTACTS:
        if placeholder in user_agent:
            issues.append(f"user_agent still references placeholder '{placeholder}'")
            break

    return issues


def ensure_production_contact(config: Config, allow_placeholder: bool = False) -> None:
    """Block identified scans until a real contact address is configured."""
    if allow_placeholder or not config.signature.enabled:
        return

    issues = contact_configuration_issues(config)
    if not issues:
        return

    details = "; ".join(issues)
    raise SystemExit(
        "[-] Scan signature contact is not production-ready: "
        f"{details}\n"
        "    python cli.py config --contact your@email.com\n"
        "    python cli.py config --user-agent \"Your Team Scan (Contact: your@email.com)\"\n"
        "Or pass --allow-placeholder for local testing."
    )


def format_scan_signature_banner(config: Config, stealth: bool = False) -> List[str]:
    """Build human-readable lines describing the active scan identity."""
    signature = config.signature
    lines = ["[*] Scan session signature (HTTP/HTTPS probes only):"]

    if stealth:
        lines.extend([
            "  Mode: stealth (identifying headers disabled)",
            f"  User-Agent: {signature.stealth_user_agent}",
        ])
        return lines

    lines.extend([
        "  Mode: identified (SIEM-friendly)",
        f"  Signatures enabled: {signature.enabled}",
        f"  User-Agent: {signature.user_agent}",
    ])
    if signature.enabled:
        lines.append(f"  {signature.signature_header}: {signature.signature_value}")
        lines.append(f"  {signature.contact_header}: {signature.contact_value}")

    contact = (signature.contact_value or "").strip().lower()
    if is_placeholder_contact(contact):
        lines.append(
            "  Note: contact is still a placeholder — run "
            "`python cli.py config --contact your@email.com` before production scans"
        )

    return lines


def print_scan_signature_session(config: Config, stealth: bool = False) -> None:
    """Print the scan signature banner to stdout before a scan session starts."""
    for line in format_scan_signature_banner(config, stealth):
        print(line)


def confirm_scan_session(assume_yes: bool = False) -> bool:
    """Prompt the operator to confirm before the first scan in a session."""
    if assume_yes:
        return True

    try:
        answer = input("Proceed with scan using the signature above? [y/N]: ").strip().lower()
    except EOFError:
        return False

    return answer in ("y", "yes")


def begin_scan_session(
    config: Config,
    stealth: bool = False,
    assume_yes: bool = False,
    allow_placeholder: bool = False,
) -> None:
    """Show the signature banner and require confirmation before scanning."""
    if not stealth:
        ensure_production_contact(config, allow_placeholder=allow_placeholder)
    print_scan_signature_session(config, stealth=stealth)
    if not confirm_scan_session(assume_yes=assume_yes):
        raise SystemExit("[-] Scan cancelled.")


def record_scan_signature_session(config: Config, stealth: bool = False) -> None:
    """Write the scan signature banner to the active per-scan log file only."""
    from .scan_log import scan_log

    for line in format_scan_signature_banner(config, stealth):
        scan_log(line, also_print=False)


def create_signed_headers(config: SignatureConfig, stealth: bool = False) -> Dict[str, str]:
    """Create SIEM-friendly HTTP headers"""
    headers = {}
    
    if stealth:
        headers["User-Agent"] = config.stealth_user_agent
        return headers
    
    headers["User-Agent"] = config.user_agent
    
    if config.enabled:
        if config.signature_header and config.signature_value:
            headers[config.signature_header] = config.signature_value
        if config.contact_header and config.contact_value:
            headers[config.contact_header] = config.contact_value
    
    return headers

def format_request_lines(method: str, path: str, host: str, headers: Dict[str, str]) -> List[str]:
    """Format HTTP request lines with proper headers"""
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
    ]
    
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    
    lines.extend([
        "Accept: */*",
        "Connection: close",
        "", ""
    ])
    
    return lines