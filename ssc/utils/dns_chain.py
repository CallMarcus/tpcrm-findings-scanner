"""Forward DNS chain resolution using stdlib socket."""

import socket
from typing import Any, Callable, Dict, List, Optional, Tuple

from .network import is_valid_hostname


LookupFn = Callable[[str, float], Tuple[str, List[str], List[str]]]


def _normalize_hostname(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _default_lookup(hostname: str, timeout: float) -> Tuple[str, List[str], List[str]]:
    # Stdlib resolver calls have no per-call timeout; mutating the
    # process-wide socket default timeout here would race across batch
    # threads and never applied to gethostbyname_ex anyway.
    return socket.gethostbyname_ex(hostname)


def resolve_forward_chain(
    hostname: str,
    timeout: float = 2.0,
    lookup_fn: Optional[LookupFn] = None,
) -> Dict[str, Any]:
    """Resolve forward DNS and return canonical name, alias chain, and IPs."""
    query = hostname.strip().rstrip(".")
    result: Dict[str, Any] = {
        "query_hostname": query,
        "canonical_name": None,
        "aliases": [],
        "resolved_ips": [],
        "error": None,
    }

    if not is_valid_hostname(query):
        result["error"] = f"Invalid hostname: {query}"
        return result

    lookup = lookup_fn or _default_lookup

    try:
        canonical, aliases, ips = lookup(query, timeout)
    except (socket.gaierror, OSError) as exc:
        result["error"] = str(exc)
        return result

    result["canonical_name"] = canonical.rstrip(".") if canonical else None
    result["aliases"] = [alias.rstrip(".") for alias in aliases if alias]
    result["resolved_ips"] = list(ips)
    return result


def build_chain_hops(chain: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build ordered hostname hops from a forward DNS chain result."""
    hops: List[Dict[str, str]] = []
    seen = set()

    query = chain.get("query_hostname")
    if query:
        norm = _normalize_hostname(query)
        hops.append({"hostname": query, "position": "query"})
        seen.add(norm)

    for alias in chain.get("aliases", []) or []:
        norm = _normalize_hostname(alias)
        if norm in seen:
            continue
        hops.append({"hostname": alias, "position": "alias"})
        seen.add(norm)

    canonical = chain.get("canonical_name")
    if canonical:
        norm = _normalize_hostname(canonical)
        if norm not in seen:
            hops.append({"hostname": canonical, "position": "canonical"})
            seen.add(norm)

    return hops