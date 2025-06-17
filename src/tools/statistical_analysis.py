
#!/usr/bin/env python3
"""
Statistical analysis module for C2 traffic analysis
"""

import math
from typing import Dict, List
from collections import defaultdict


class StatisticalAnalyzer:
    @staticmethod
    def analyze_beaconing(host: str, timestamps: List[float]) -> Dict:
        """Analyze timing patterns for potential beaconing"""
        if len(timestamps) < 3:
            return {}
            
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        if not intervals:
            return {}
            
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # Check for regular beaconing (low variance in intervals)
        coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 0
        
        return {
            'host': host,
            'request_count': len(timestamps),
            'avg_interval': avg_interval,
            'std_deviation': std_dev,
            'coefficient_of_variation': coefficient_of_variation,
            'is_regular': coefficient_of_variation < 0.3 and len(timestamps) > 5
        }

    @staticmethod
    def analyze_host_behavior(host_key: str, stats: Dict) -> List[str]:
        """Analyze host behavior patterns for suspicious indicators"""
        suspicion_indicators = []
        
        # Multiple different user agents (potential evasion)
        if len(stats['user_agents']) > 3:
            suspicion_indicators.append(f"Multiple user agents: {len(stats['user_agents'])}")
        
        # High request frequency
        if stats['request_count'] > 100:
            suspicion_indicators.append(f"High request count: {stats['request_count']}")
        
        # Consistent path patterns (could indicate automated behavior)
        unique_paths = set(stats['paths'])
        if len(unique_paths) < len(stats['paths']) * 0.1 and len(stats['paths']) > 10:  # Less than 10% unique paths
            suspicion_indicators.append("Repetitive path patterns")
        
        # Check for regular intervals (simple beaconing detection)
        if len(stats['intervals']) > 5:
            avg_interval = sum(stats['intervals']) / len(stats['intervals'])
            variance = sum((x - avg_interval) ** 2 for x in stats['intervals']) / len(stats['intervals'])
            if variance < (avg_interval * 0.1) ** 2:  # Low variance
                suspicion_indicators.append(f"Regular intervals detected (avg: {avg_interval:.2f}s)")
        
        return suspicion_indicators

    @staticmethod
    def calculate_suspicion_score(http_data: Dict, dst_port: int, pattern_detector) -> tuple:
        """Calculate suspicion score for an HTTP request"""
        suspicion_score = 0
        reasons = []
        
        user_agent = http_data.get('user_agent', '')
        path = http_data.get('path', '')
        
        # Check user agent
        if pattern_detector.is_suspicious_user_agent(user_agent):
            suspicion_score += 3
            reasons.append(f"Suspicious user agent: {user_agent}")
        
        # Check URL patterns
        if pattern_detector.is_suspicious_url(path):
            suspicion_score += 2
            reasons.append(f"Suspicious URL pattern: {path}")
        
        # Check for high entropy in path (potential encryption)
        path_entropy = pattern_detector.calculate_entropy(path)
        if path_entropy > 4.5:
            suspicion_score += 2
            reasons.append(f"High entropy in path: {path_entropy:.2f}")
        
        # Check for suspicious headers
        for header, value in http_data.get('headers', {}).items():
            if pattern_detector.has_suspicious_header(header):
                suspicion_score += 1
                reasons.append(f"Suspicious header: {header}")
        
        # Check for base64 patterns in payload
        if pattern_detector.has_base64_content(http_data.get('full_payload', '')):
            suspicion_score += 1
            reasons.append("Base64-like content detected")
        
        # Check for non-standard ports
        if dst_port not in [80, 443, 8080, 8443]:
            suspicion_score += 1
            reasons.append(f"Non-standard HTTP port: {dst_port}")
        
        # Check for suspicious file extensions
        if pattern_detector.has_suspicious_file_extension(path):
            suspicion_score += 1
            reasons.append(f"Suspicious file extension detected")
        
        return suspicion_score, reasons
