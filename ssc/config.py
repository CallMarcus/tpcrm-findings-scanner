"""Configuration management for TPCRM Findings Scanner"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

@dataclass
class SignatureConfig:
    """SIEM-friendly scan signature configuration"""
    enabled: bool = True
    user_agent: str = "TPCRM Findings Validation Scan (Contact: security@example.com)"
    signature_header: str = "X-Security-Scan"
    signature_value: str = "TPCRM Findings Validation Scan"
    contact_header: str = "X-Contact"
    contact_value: str = "security@example.com"
    stealth_user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

@dataclass
class ScanConfig:
    """Scanning configuration"""
    default_ports: List[int] = field(default_factory=lambda: [
        80, 443, 8080, 8443,
        21, 22, 25, 110, 143, 993, 995,
        389, 636, 3306, 1433, 1521, 5432,
        3389, 5900, 9200, 27017, 53
    ])
    timeout: float = 1.5
    max_workers: int = 200
    max_redirects: int = 8
    stay_on_ip: bool = False
    max_http_probes: int = 8
    max_host_candidates_per_port: int = 3
    # Optional lightweight HTTP body capture for fingerprinting
    capture_body: bool = False
    capture_body_bytes: int = 0
    default_profile: Optional[str] = None

@dataclass
class OutputConfig:
    """Output configuration"""
    base_dir: str = "outputs"
    reports_dir: str = "reports"
    evidence_dir: str = "evidence"
    logs_dir: str = "logs"
    include_markdown: bool = True
    include_json: bool = True
    include_csv: bool = False

@dataclass
class Config:
    """Main configuration class"""
    signature: SignatureConfig = field(default_factory=SignatureConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    @classmethod
    def load(cls, config_file: Optional[str] = None) -> "Config":
        """Load configuration from YAML file"""
        if config_file is None:
            config_file = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
        
        if not os.path.exists(config_file):
            return cls()
        
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        return cls(
            signature=SignatureConfig(**data.get('signature', {})),
            scan=ScanConfig(**data.get('scan', {})),
            output=OutputConfig(**data.get('output', {}))
        )
    
    def save(self, config_file: str):
        """Save configuration to YAML file"""
        data = {
            'signature': {
                'enabled': self.signature.enabled,
                'user_agent': self.signature.user_agent,
                'signature_header': self.signature.signature_header,
                'signature_value': self.signature.signature_value,
                'contact_header': self.signature.contact_header,
                'contact_value': self.signature.contact_value,
                'stealth_user_agent': self.signature.stealth_user_agent
            },
            'scan': {
                'default_ports': self.scan.default_ports,
                'timeout': self.scan.timeout,
                'max_workers': self.scan.max_workers,
                'max_redirects': self.scan.max_redirects,
                'stay_on_ip': self.scan.stay_on_ip,
                'max_http_probes': self.scan.max_http_probes,
                'max_host_candidates_per_port': self.scan.max_host_candidates_per_port,
                'capture_body': self.scan.capture_body,
                'capture_body_bytes': self.scan.capture_body_bytes,
                'default_profile': self.scan.default_profile,
            },
            'output': {
                'base_dir': self.output.base_dir,
                'reports_dir': self.output.reports_dir,
                'evidence_dir': self.output.evidence_dir,
                'logs_dir': self.output.logs_dir,
                'include_markdown': self.output.include_markdown,
                'include_json': self.output.include_json,
                'include_csv': self.output.include_csv
            }
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, indent=2)
    
    def get_output_paths(self, target_ip: str, timestamp: int) -> Dict[str, str]:
        """Get organized output file paths"""
        base_name = f"scan_{target_ip.replace(':', '_')}_{timestamp}"
        base_dir = Path(self.output.base_dir)
        
        return {
            'json': str(base_dir / self.output.reports_dir / f"{base_name}.json"),
            'markdown': str(base_dir / self.output.reports_dir / f"{base_name}.md"),
            'csv': str(base_dir / self.output.evidence_dir / f"{base_name}.csv"),
            'log': str(base_dir / self.output.logs_dir / f"{base_name}.log")
        }
