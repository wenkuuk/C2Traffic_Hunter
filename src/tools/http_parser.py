
#!/usr/bin/env python3
"""
HTTP parsing module for C2 traffic analysis
"""

from typing import Dict


class HTTPParser:
    @staticmethod
    def is_http_traffic(payload: str) -> bool:
        """Check if packet contains HTTP traffic"""
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        http_responses = ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']
        
        for method in http_methods:
            if payload.startswith(method + ' '):
                return True
        
        for response in http_responses:
            if payload.startswith(response):
                return True
                
        return False

    @staticmethod
    def parse_http_request(payload: bytes) -> Dict:
        """Parse HTTP request from raw payload"""
        try:
            # Decode payload
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')
            
            if not lines:
                return {}
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return {}
            
            method = parts[0]
            path = parts[1]
            
            # Parse headers
            headers = {}
            body = ""
            body_start = 0
            
            for i, line in enumerate(lines[1:], 1):
                if line == '':  # Empty line indicates start of body
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return {
                'method': method,
                'path': path,
                'headers': headers,
                'host': headers.get('host', ''),
                'user_agent': headers.get('user-agent', ''),
                'body': body,
                'full_payload': payload_str
            }
            
        except Exception as e:
            return {}

    @staticmethod
    def parse_http_response(payload: bytes) -> Dict:
        """Parse HTTP response from raw payload"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')
            
            if not lines:
                return {}
            
            # Parse status line
            status_line = lines[0]
            parts = status_line.split(' ')
            if len(parts) < 3:
                return {}
            
            status_code = parts[1] if len(parts) > 1 else ''
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':  # Empty line indicates start of body
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return {
                'status_code': status_code,
                'headers': headers,
                'body': body,
                'content_length': len(body)
            }
            
        except Exception as e:
            return {}
