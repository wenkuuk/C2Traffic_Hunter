
#!/usr/bin/env python3
"""
Signature-based detection engine for C2 traffic analysis
"""

import re
from typing import Dict, List, Tuple


class SignatureEngine:
    """Static signature-based detection engine"""
    
    def __init__(self):
        self.signatures = {
            # Known C2 signatures
            'malicious_domains': [
                r'.*\.onion$',
                r'.*dyndns\.org$',
                r'.*no-ip\.(com|org|net)$',
                r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',  # Direct IP addresses
            ],
            'suspicious_paths': [
                r'/[a-f0-9]{32}$',  # MD5 hash paths
                r'/[a-f0-9]{40}$',  # SHA1 hash paths
                r'/[A-Za-z0-9+/]{20,}={0,2}$',  # Base64 paths
                r'/(gate|panel|admin|bot|c2)\.php$',
                r'/\d{10,13}$',  # Unix timestamp paths
                r'/(check|update|beacon|ping|status)$',
            ],
            'malicious_user_agents': [
                r'Mozilla/4\.0 \(compatible; MSIE [67]\.0; Windows NT 5\.[12]\)',
                r'^$',  # Empty user agent
                r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64 encoded UA
                r'(curl|wget|python|powershell|winhttp)',
            ],
            'c2_headers': [
                r'X-Session-Token:.*',
                r'X-Bot-ID:.*',
                r'X-Campaign:.*',
                r'Authorization: Bearer [A-Za-z0-9+/]{30,}',
            ],
            'payload_signatures': [
                rb'__VIEWSTATE',  # .NET viewstate
                rb'eval\s*\(',  # Code execution
                rb'exec\s*\(',  # Code execution
                rb'system\s*\(',  # System commands
                rb'shell_exec',  # PHP shell execution
            ]
        }
    
    def detect_signatures(self, session_data: Dict, payload: bytes = b'') -> Tuple[int, List[str]]:
        """Detect known malicious signatures"""
        score = 0
        matches = []
        
        host = session_data.get('host', '')
        path = session_data.get('path', '')
        user_agent = session_data.get('user_agent', '')
        headers = session_data.get('headers', {})
        
        # Check domain signatures
        for pattern in self.signatures['malicious_domains']:
            if re.search(pattern, host, re.IGNORECASE):
                score += 5
                matches.append(f"Malicious domain pattern: {pattern}")
        
        # Check path signatures
        for pattern in self.signatures['suspicious_paths']:
            if re.search(pattern, path):
                score += 3
                matches.append(f"Suspicious path: {path}")
        
        # Check user agent signatures
        for pattern in self.signatures['malicious_user_agents']:
            if re.search(pattern, user_agent, re.IGNORECASE):
                score += 4
                matches.append(f"Malicious user agent: {user_agent}")
        
        # Check header signatures
        for header, value in headers.items():
            for pattern in self.signatures['c2_headers']:
                if re.search(pattern, f"{header}: {value}", re.IGNORECASE):
                    score += 6
                    matches.append(f"C2 header detected: {header}")
        
        # Check payload signatures
        for pattern in self.signatures['payload_signatures']:
            if re.search(pattern, payload, re.IGNORECASE):
                score += 7
                matches.append(f"Malicious payload pattern detected")
        
        return score, matches
