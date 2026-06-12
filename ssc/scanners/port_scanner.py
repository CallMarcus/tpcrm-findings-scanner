"""Port scanning and banner grabbing functionality"""

import socket
import concurrent.futures
from typing import List, Dict, Optional, Any
from ..utils.network import tcp_connect
from ..config import ScanConfig

class PortScanner:
    """Port scanner with banner grabbing capabilities"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
    
    def scan_ports(self, ip: str, ports: Optional[List[int]] = None) -> List[int]:
        """Scan ports and return list of open ports"""
        if ports is None:
            ports = self.config.default_ports
        
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(tcp_connect, ip, port, self.config.timeout): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except OSError:
                    pass
        
        return sorted(open_ports)
    
    def grab_banner(self, ip: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
        """Attempt to grab service banner from port"""
        if timeout is None:
            timeout = self.config.timeout
        
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                
                # Send HTTP HEAD request for web ports
                if port in (80, 8080, 8000, 8888):
                    request = b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
                    sock.sendall(request)
                
                # Try to read response
                try:
                    data = sock.recv(4096)
                    return data.decode(errors="replace") if data else None
                except socket.timeout:
                    return None

        except OSError:
            return None
    
    def scan_with_banners(self, ip: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Scan ports and collect banners for open ports"""
        open_ports = self.scan_ports(ip, ports)
        banners = {}
        
        # Grab banners for non-HTTP ports
        for port in open_ports:
            if port not in (80, 443, 8080, 8443):  # Skip HTTP/HTTPS ports
                banner = self.grab_banner(ip, port)
                if banner:
                    banners[port] = banner
        
        return {
            "open_ports": open_ports,
            "banners": banners
        }