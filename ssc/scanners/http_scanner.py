"""HTTP/HTTPS scanning with security analysis"""

import socket
import ssl
from typing import Dict, Any, Optional, List
import hashlib
import re
from urllib.parse import urljoin, urlparse
from ..config import ScanConfig, SignatureConfig
from ..utils.signatures import create_signed_headers, format_request_lines

class HTTPScanner:
    """HTTP/HTTPS scanner with security analysis"""
    
    def __init__(self, scan_config: ScanConfig, signature_config: SignatureConfig):
        self.scan_config = scan_config
        self.signature_config = signature_config
    
    def probe_http(self, ip: str, port: int, host: Optional[str] = None, 
                   use_tls: bool = False, method: str = "GET", path: str = "/",
                   stealth: bool = False, capture_body: bool = False, capture_bytes: int = 0) -> Dict[str, Any]:
        """Perform HTTP/HTTPS probe with redirect following"""
        
        result = {
            "start_url": f"{'https' if use_tls else 'http'}://{ip}:{port}{path}",
            "requests": [],
            "final": None,
            "error": None,
        }
        
        current_scheme = "https" if use_tls else "http"
        current_host_header = host if host else ip
        current_server_name = host if (host and use_tls) else None
        current_ip_target = ip
        current_port = port
        current_path = path
        
        headers = create_signed_headers(self.signature_config, stealth=stealth)
        
        for redirect_count in range(self.scan_config.max_redirects + 1):
            try:
                # Create connection
                if current_scheme == "https":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    raw_sock = socket.create_connection(
                        (current_ip_target, current_port), 
                        timeout=self.scan_config.timeout
                    )
                    sock = context.wrap_socket(raw_sock, server_hostname=current_server_name)
                else:
                    sock = socket.create_connection(
                        (current_ip_target, current_port), 
                        timeout=self.scan_config.timeout
                    )
                
                sock.settimeout(self.scan_config.timeout)
                
                # Send HTTP request
                request_lines = format_request_lines(method, current_path, current_host_header, headers)
                sock.sendall("\r\n".join(request_lines).encode())
                
                # Receive response
                raw_response = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        raw_response += chunk
                finally:
                    sock.close()
                
                # Parse response
                response_info = self._parse_http_response(raw_response)
                
                # Optional lightweight body capture
                if capture_body and capture_bytes and capture_bytes > 0:
                    body_features = self._extract_body_features(raw_response, capture_bytes)
                    response_info.update(body_features)
                response_info.update({
                    "scheme": current_scheme,
                    "target_ip": current_ip_target,
                    "port": current_port,
                    "host_header": current_host_header,
                    "sni": current_server_name,
                })
                
                result["requests"].append(response_info)
                
                # Handle redirects
                status_code = response_info.get("status_code")
                location = self._get_redirect_location(response_info.get("headers", {}))
                
                if status_code and status_code in (301, 302, 303, 307, 308) and location:
                    next_url_info = self._resolve_redirect(
                        current_scheme, current_host_header, current_port, current_path, location
                    )
                    
                    # Check if we should stay on the same IP
                    if self.scan_config.stay_on_ip and next_url_info["ip"] != current_ip_target:
                        result["final"] = response_info
                        break
                    
                    # Update for next request
                    current_scheme = next_url_info["scheme"]
                    current_host_header = next_url_info["host"]
                    current_server_name = next_url_info["host"] if current_scheme == "https" else None
                    current_ip_target = next_url_info["ip"]
                    current_port = next_url_info["port"]
                    current_path = next_url_info["path"]
                    continue
                else:
                    result["final"] = response_info
                    break
                    
            except (OSError, ValueError) as e:
                # OSError covers socket timeouts, connection failures, and
                # ssl.SSLError; ValueError covers malformed redirect URLs.
                result["error"] = str(e)
                break

        if result["final"] is None:
            result["final"] = {}
        
        return result
    
    def _parse_http_response(self, raw_response: bytes) -> Dict[str, Any]:
        """Parse raw HTTP response into structured data"""
        header_end = raw_response.find(b"\r\n\r\n")
        if header_end == -1:
            header_blob = raw_response
            body = b""
        else:
            header_blob = raw_response[:header_end]
            body = raw_response[header_end + 4:]
        
        header_text = header_blob.decode(errors="replace")
        header_lines = header_text.split("\r\n")
        status_line = header_lines[0] if header_lines else ""
        
        headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                headers.setdefault(key, []).append(value)
        
        status_code = None
        try:
            parts = status_line.split()
            if len(parts) >= 2:
                status_code = int(parts[1])
        except ValueError:
            pass
        
        return {
            "status_line": status_line,
            "status_code": status_code,
            "headers": headers,
            "body_length": len(body),
        }

    def _extract_body_features(self, raw_response: bytes, capture_bytes: int) -> Dict[str, Any]:
        """Extract title, sample, and hash from response body."""
        out: Dict[str, Any] = {}
        header_end = raw_response.find(b"\r\n\r\n")
        body = raw_response[header_end + 4:] if header_end != -1 else b""
        if not body:
            return out
        # Hash of full body for stable fingerprint; decode leniently for
        # title/sample (errors="ignore" cannot raise on bytes input).
        out["body_sha256"] = hashlib.sha256(body).hexdigest()
        text = body.decode(errors="ignore")
        if text:
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            if m:
                out["title"] = m.group(1).strip()[:256]
            out["body_sample"] = text[: int(capture_bytes)]
        return out
    
    def _get_redirect_location(self, headers: Dict[str, List[str]]) -> Optional[str]:
        """Extract redirect location from headers"""
        lower_headers = {k.lower(): v for k, v in headers.items()}
        location_values = lower_headers.get("location", [])
        return location_values[0] if location_values else None
    
    def _resolve_redirect(self, current_scheme: str, current_host: str, 
                         current_port: int, current_path: str, location: str) -> Dict[str, Any]:
        """Resolve redirect location to next URL components"""
        current_url = f"{current_scheme}://{current_host}:{current_port}{current_path}"
        next_url = urljoin(current_url, location)
        parsed = urlparse(next_url)
        
        next_scheme = parsed.scheme or current_scheme
        next_host = parsed.hostname or current_host
        next_port = parsed.port or (443 if next_scheme == "https" else 80)
        next_path = parsed.path or "/"
        if parsed.query:
            next_path += "?" + parsed.query
        
        # Resolve hostname to IP
        next_ip = current_host  # Default fallback
        if next_host and not next_host.replace(".", "").isdigit():
            try:
                next_ip = socket.gethostbyname(next_host)
            except OSError:
                next_ip = current_host
        elif next_host:
            next_ip = next_host
        
        return {
            "scheme": next_scheme,
            "host": next_host,
            "ip": next_ip,
            "port": next_port,
            "path": next_path
        }
