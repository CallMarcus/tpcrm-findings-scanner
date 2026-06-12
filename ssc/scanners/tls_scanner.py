"""TLS/SSL scanning and certificate analysis"""

import os
import socket
import ssl
import tempfile
import time
from typing import Dict, Any, Optional, List
from ..config import ScanConfig

class TLSScanner:
    """TLS/SSL certificate and version analyzer"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
    
    def analyze_certificate(self, ip: str, port: int = 443, server_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze TLS certificate and connection details"""
        result = {
            "ok": False,
            "error": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None
        }
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            # CERT_NONE so handshakes succeed against self-signed/untrusted chains;
            # _extract_peer_certificate decodes the DER cert since getpeercert()
            # returns an empty dict in this mode.
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                    result["ok"] = True
                    result["tls_version"] = ssock.version()
                    
                    try:
                        result["cipher"] = ssock.cipher()
                    except OSError:
                        result["cipher"] = None

                    result["certificate"] = self._extract_peer_certificate(ssock)

        except OSError as e:
            # Covers socket timeouts, connection errors, and ssl.SSLError.
            result["error"] = str(e)
        
        return result
    
    def test_tls_versions(self, ip: str, port: int = 443, server_name: Optional[str] = None) -> Dict[str, Any]:
        """Test different TLS versions for support"""
        versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        results = {}
        
        for version in versions:
            results[version] = self._test_tls_version(ip, port, version, server_name)
        
        return results
    
    def _test_tls_version(self, ip: str, port: int, tls_version: str, server_name: Optional[str]) -> Dict[str, Any]:
        """Test a specific TLS version"""
        result = {"ok": False, "error": None, "tls_version": None, "cipher": None}
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set TLS version bounds
            try:
                if tls_version == "TLSv1":
                    context.maximum_version = ssl.TLSVersion.TLSv1
                    context.minimum_version = ssl.TLSVersion.TLSv1
                elif tls_version == "TLSv1.1":
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                elif tls_version == "TLSv1.2":
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                elif tls_version == "TLSv1.3":
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
            except ValueError:
                # OpenSSL build may not support pinning this version.
                pass
            
            with socket.create_connection((ip, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                    result["ok"] = True
                    result["tls_version"] = ssock.version()
                    try:
                        result["cipher"] = ssock.cipher()
                    except OSError:
                        result["cipher"] = None

        except OSError as e:
            result["error"] = str(e)
        
        return result
    
    def get_certificate_expiry_days(self, certificate_info: Dict[str, Any]) -> Optional[int]:
        """Calculate days until certificate expiry"""
        try:
            cert = certificate_info.get("certificate", {})
            not_after = cert.get("notAfter")
            if not_after:
                expiry_timestamp = time.mktime(time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
                days_left = int((expiry_timestamp - time.time()) / 86400)
                return days_left
        except (ValueError, TypeError, AttributeError, OverflowError):
            pass
        return None
    
    def _extract_peer_certificate(self, ssock) -> Optional[Dict[str, Any]]:
        """Extract certificate fields from a TLS socket."""
        try:
            cert = ssock.getpeercert()
            if cert:
                return self._format_certificate(cert)

            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der:
                cert = self._decode_der_certificate(cert_der)
                return self._format_certificate(cert)
        except (OSError, ValueError):
            # OSError covers ssl.SSLError and the temp-file round trip.
            pass
        return None

    @staticmethod
    def _decode_der_certificate(cert_der: bytes) -> Dict[str, Any]:
        """Decode a DER certificate into getpeercert()-style fields.

        ssl._ssl._test_decode_cert only accepts a PEM file path, so the DER
        bytes are written to a temp file first (delete=False for Windows).
        """
        pem = ssl.DER_cert_to_PEM_cert(cert_der)
        handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8")
        try:
            handle.write(pem)
            handle.close()
            return ssl._ssl._test_decode_cert(handle.name)
        finally:
            os.unlink(handle.name)

    def _format_certificate(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize certificate dict for reporting and analysis."""
        return {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "serialNumber": cert.get("serialNumber"),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
            "subjectAltName": cert.get("subjectAltName"),
        }

    def extract_sans(self, certificate_info: Dict[str, Any]) -> List[str]:
        """Extract DNS Subject Alternative Names from certificate"""
        sans = []
        try:
            cert = certificate_info.get("certificate", {})
            subject_alt_names = cert.get("subjectAltName", [])
            for name_type, name_value in subject_alt_names:
                if name_type == "DNS":
                    sans.append(name_value.strip().strip("."))
        except (TypeError, ValueError, AttributeError):
            pass
        return sans