"""Shared utility functions"""

from .network import (
    ScanTarget,
    is_valid_hostname,
    parse_target_input,
    resolve_hostname,
    reverse_dns,
    tcp_connect,
    valid_ip,
)
from .signatures import (
    begin_scan_session,
    confirm_scan_session,
    contact_configuration_issues,
    create_signed_headers,
    ensure_production_contact,
    format_scan_signature_banner,
    is_placeholder_contact,
    print_scan_signature_session,
    record_scan_signature_session,
)
from .scan_log import scan_log, scan_log_session, active_scan_log_path
from .dns_chain import build_chain_hops, resolve_forward_chain

__all__ = [
    "ScanTarget",
    "is_valid_hostname",
    "parse_target_input",
    "resolve_hostname",
    "valid_ip",
    "reverse_dns",
    "tcp_connect",
    "begin_scan_session",
    "confirm_scan_session",
    "contact_configuration_issues",
    "ensure_production_contact",
    "is_placeholder_contact",
    "create_signed_headers",
    "format_scan_signature_banner",
    "print_scan_signature_session",
    "record_scan_signature_session",
    "scan_log",
    "scan_log_session",
    "active_scan_log_path",
    "build_chain_hops",
    "resolve_forward_chain",
]