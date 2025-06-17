
#!/usr/bin/env python3
"""
Machine learning feature extraction for C2 traffic analysis
"""

import math
import re
import statistics
from collections import Counter
from typing import Dict, Tuple


class MLFeatureExtractor:
    """Machine learning feature extraction engine"""
    
    @staticmethod
    def extract_features(session_data: Dict, payload: bytes = b'') -> Dict:
        """Extract ML features from HTTP session"""
        features = {}
        
        # Get session data
        path = session_data.get('path', '')
        host = session_data.get('host', '')
        user_agent = session_data.get('user_agent', '')
        headers = session_data.get('headers', {})
        method = session_data.get('method', '')
        request_size = session_data.get('request_size', 0)
        response_size = session_data.get('response_size', 0)
        response_code = session_data.get('response_code', '')
        dst_port = session_data.get('dst_port', 80)
        request_interval = session_data.get('request_interval', 0)
        session_duration = session_data.get('session_duration', 0)
        
        # Statistical features
        features['path_length'] = len(path)
        features['host_length'] = len(host)
        features['ua_length'] = len(user_agent)
        features['header_count'] = len(headers)
        features['request_size'] = request_size
        features['response_size'] = response_size
        features['size_ratio'] = response_size / max(request_size, 1)
        
        # Entropy calculations
        features['path_entropy'] = MLFeatureExtractor._calculate_entropy(path)
        features['host_entropy'] = MLFeatureExtractor._calculate_entropy(host)
        features['ua_entropy'] = MLFeatureExtractor._calculate_entropy(user_agent)
        
        # Character frequency analysis
        features['path_alpha_ratio'] = sum(c.isalpha() for c in path) / max(len(path), 1)
        features['path_digit_ratio'] = sum(c.isdigit() for c in path) / max(len(path), 1)
        features['path_special_ratio'] = sum(not c.isalnum() for c in path) / max(len(path), 1)
        
        # Domain analysis
        features['is_ip_address'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', host) else 0
        features['subdomain_count'] = len(host.split('.')) - 1
        features['has_port'] = 1 if ':' in host else 0
        
        # Timing features
        features['request_interval'] = request_interval
        features['session_duration'] = session_duration
        
        # Protocol features
        features['is_encrypted'] = 1 if dst_port in [443, 8443] else 0
        features['method_post'] = 1 if method == 'POST' else 0
        features['method_get'] = 1 if method == 'GET' else 0
        
        # Response analysis
        features['response_2xx'] = 1 if response_code.startswith('2') else 0
        features['response_3xx'] = 1 if response_code.startswith('3') else 0
        features['response_4xx'] = 1 if response_code.startswith('4') else 0
        features['response_5xx'] = 1 if response_code.startswith('5') else 0
        
        # Advanced payload analysis
        if payload:
            payload_str = payload.decode('utf-8', errors='ignore')
            features['payload_entropy'] = MLFeatureExtractor._calculate_entropy(payload_str)
            features['has_base64'] = 1 if re.search(rb'[A-Za-z0-9+/]{50,}={0,2}', payload) else 0
            features['has_hex'] = 1 if re.search(rb'[0-9a-fA-F]{32,}', payload) else 0
        else:
            features['payload_entropy'] = 0
            features['has_base64'] = 0
            features['has_hex'] = 0
        
        return features
    
    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        freq = Counter(data)
        length = len(data)
        entropy = 0
        
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def classify_session(features: Dict) -> Tuple[float, str]:
        """Simple heuristic-based classification (placeholder for ML model)"""
        score = 0
        reasons = []
        
        # High entropy indicators
        if features.get('path_entropy', 0) > 4.5:
            score += 0.3
            reasons.append("High path entropy")
        
        if features.get('host_entropy', 0) > 3.5:
            score += 0.2
            reasons.append("High host entropy")
        
        # Suspicious characteristics
        if features.get('is_ip_address', 0):
            score += 0.4
            reasons.append("Direct IP communication")
        
        if features.get('path_digit_ratio', 0) > 0.7:
            score += 0.3
            reasons.append("High digit ratio in path")
        
        if features.get('size_ratio', 0) > 100:
            score += 0.2
            reasons.append("Large response ratio")
        
        if features.get('request_interval', 0) > 0 and features.get('request_interval', 0) < 60:
            score += 0.25
            reasons.append("Short request interval")
        
        if features.get('payload_entropy', 0) > 7.0:
            score += 0.3
            reasons.append("High payload entropy")
        
        # Cap the score at 1.0
        score = min(score, 1.0)
        
        return score, "; ".join(reasons)
