
#!/usr/bin/env python3
"""
Pattern detection module for C2 traffic analysis
"""

import re
import math
from collections import Counter
from typing import List


class PatternDetector:
    def __init__(self):
        self.suspicious_patterns = {
            'user_agents': [
                r'Mozilla/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)',
                r'curl/',
                r'wget/',
                r'python-requests/',
                r'Go-http-client/',
                r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64-like patterns
                r'.*bot.*',
                r'.*crawler.*',
            ],
            'url_patterns': [
                r'/[a-f0-9]{32}',  # MD5-like hashes
                r'/[a-f0-9]{40}',  # SHA1-like hashes
                r'/[A-Za-z0-9+/]{20,}={0,2}',  # Base64 encoded paths
                r'/\d{10,13}',  # Timestamps
                r'/(data|config|update|check|beacon|ping)$',
                r'/[a-z]{2,3}/[a-z]{2,3}$',  # Short path segments
                r'/admin/.*',
                r'/panel/.*',
                r'/gate\.php',
                r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',  # UUID paths
            ],
            'suspicious_headers': [
                'X-Forwarded-For',
                'X-Real-IP',
                'X-Custom-',
                'Authorization: Basic',
                'x-session-token',
                'x-auth-key', 
                'x-bot-id',
                'x-campaign-id',
            ],
            'file_extensions': [
                '.php', '.asp', '.aspx', '.jsp', '.cgi'
            ]
        }

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0
        
        # Count frequency of each character
        freq = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy

    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent matches suspicious patterns"""
        if not user_agent:
            return False
            
        for pattern in self.suspicious_patterns['user_agents']:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        return False

    def is_suspicious_url(self, url: str) -> bool:
        """Check if URL matches suspicious patterns"""
        if not url:
            return False
            
        for pattern in self.suspicious_patterns['url_patterns']:
            if re.search(pattern, url):
                return True
        return False

    def has_suspicious_header(self, header: str) -> bool:
        """Check if header name matches suspicious patterns"""
        if not header:
            return False
            
        return any(suspicious_header.lower() in header.lower() 
                   for suspicious_header in self.suspicious_patterns['suspicious_headers'])

    def has_suspicious_file_extension(self, path: str) -> bool:
        """Check if path has suspicious file extension"""
        if not path:
            return False
            
        for ext in self.suspicious_patterns['file_extensions']:
            if path.endswith(ext):
                return True
        return False

    def has_base64_content(self, content: str) -> bool:
        """Check for base64-like patterns in content"""
        return bool(re.search(r'[A-Za-z0-9+/]{50,}={0,2}', content))
