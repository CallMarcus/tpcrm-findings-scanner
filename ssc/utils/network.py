"""Network utility functions"""

import socket
import ipaddress
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ScanTarget:
    """Normalized scan target after IP or hostname resolution."""

    input: str
    ip: str
    host: Optional[str] = None


def valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def reverse_dns(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Perform reverse DNS lookup.

    Note: stdlib resolver calls have no per-call timeout; the timeout
    parameter is kept for API compatibility. Mutating the process-wide
    socket default timeout here would race across batch scan threads
    (and never applied to gethostbyaddr in the first place).
    """
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except OSError:
        return None

def tcp_connect(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Test TCP connectivity to IP:port"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def is_valid_hostname(name: str) -> bool:
    """Return True for apex and subdomain hostnames (ASCII labels)."""
    candidate = name.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        return False
    if valid_ip(candidate):
        return False
    if any(char in candidate for char in "/: #%?"):
        return False

    labels = candidate.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
    return True


def resolve_hostname(hostname: str, timeout: float = 2.0) -> str:
    """Resolve a hostname to an IP address, preferring IPv4.

    See reverse_dns for why no socket default-timeout manipulation happens here.
    """
    name = hostname.strip().rstrip(".")
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve {name}: {exc}") from exc

    if not infos:
        raise ValueError(f"No addresses found for {name}")

    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0]

    return infos[0][4][0]


def parse_target_input(
    value: str,
    explicit_host: Optional[str] = None,
    timeout: float = 2.0,
) -> ScanTarget:
    """Parse an IP or hostname target for scanning."""
    raw = value.strip()
    if not raw:
        raise ValueError("Target is empty")

    if valid_ip(raw):
        return ScanTarget(input=raw, ip=raw, host=explicit_host)

    if not is_valid_hostname(raw):
        raise ValueError(f"Invalid target (expected IP or hostname): {raw}")

    resolved_ip = resolve_hostname(raw, timeout=timeout)
    host = explicit_host or raw.rstrip(".")
    return ScanTarget(input=raw, ip=resolved_ip, host=host)