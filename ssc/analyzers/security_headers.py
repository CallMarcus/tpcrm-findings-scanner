"""Security header analysis"""

from typing import Dict, List, Any

class SecurityHeaderAnalyzer:
    """Analyzer for HTTP security headers"""
    
    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy", 
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
    ]
    
    def analyze(self, headers: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze security headers in HTTP response"""
        present = []
        missing = []
        values = {}
        
        # Create case-insensitive header mapping
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        for security_header in self.SECURITY_HEADERS:
            if security_header in lower_headers:
                present.append(security_header)
                values[security_header] = lower_headers[security_header]
            else:
                missing.append(security_header)
        
        return {
            "present": present,
            "missing": missing, 
            "values": values,
            "score": self._calculate_score(present, missing)
        }
    
    def _calculate_score(self, present: List[str], missing: List[str]) -> Dict[str, Any]:
        """Calculate security header score"""
        total_headers = len(self.SECURITY_HEADERS)
        present_count = len(present)
        
        score = (present_count / total_headers) * 100
        grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
        
        return {
            "percentage": round(score, 1),
            "grade": grade,
            "present_count": present_count,
            "total_count": total_headers
        }
    
    def get_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Get recommendations for missing security headers"""
        missing = analysis_result.get("missing", [])
        recommendations = []
        
        header_recommendations = {
            "strict-transport-security": "Add HSTS header to enforce HTTPS connections",
            "content-security-policy": "Implement CSP to prevent XSS attacks",
            "x-content-type-options": "Add 'nosniff' to prevent MIME type confusion",
            "x-frame-options": "Prevent clickjacking with DENY or SAMEORIGIN",
            "referrer-policy": "Control referrer information leakage",
            "permissions-policy": "Restrict browser features for enhanced security",
            "cross-origin-opener-policy": "Isolate document from cross-origin documents",
            "cross-origin-resource-policy": "Control cross-origin resource sharing",
            "cross-origin-embedder-policy": "Enable cross-origin isolation",
        }
        
        for header in missing:
            if header in header_recommendations:
                recommendations.append(f"{header}: {header_recommendations[header]}")
        
        return recommendations