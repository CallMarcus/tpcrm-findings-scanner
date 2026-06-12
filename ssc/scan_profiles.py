"""Scan profile presets for port selection and probe behavior."""

from typing import List, Optional, Tuple

from .config import Config

WEB_PORTS = [80, 443, 8080, 8443]

PROFILE_PRESETS = {
    "web": {
        "ports": WEB_PORTS,
        "only_web": True,
        "description": "Web ports only (80, 443, 8080, 8443)",
    },
    "quick": {
        "ports": [80, 443, 8080, 8443, 22, 25, 53, 3389],
        "only_web": False,
        "description": "Web ports plus common admin, mail, and DNS services",
    },
    "full": {
        "ports": None,
        "only_web": False,
        "description": "Full port list from configuration",
    },
}


def list_profiles() -> List[str]:
    """Return supported profile names in display order."""
    return ["quick", "web", "full"]


def resolve_scan_options(
    config: Config,
    profile: Optional[str] = None,
    ports: Optional[List[int]] = None,
    only_web: bool = False,
) -> Tuple[Optional[List[int]], bool, str]:
    """Resolve effective ports, web-only probing, and profile label."""
    requested = profile or getattr(config.scan, "default_profile", None)
    effective = requested or "full"

    if effective not in PROFILE_PRESETS:
        raise ValueError(
            f"Unknown scan profile '{effective}'. Choose from: {', '.join(list_profiles())}"
        )

    preset = PROFILE_PRESETS[effective]
    resolved_ports = ports if ports is not None else preset["ports"]
    resolved_only_web = only_web or bool(preset.get("only_web"))

    if ports is not None:
        profile_label = "custom"
    else:
        profile_label = effective

    return resolved_ports, resolved_only_web, profile_label