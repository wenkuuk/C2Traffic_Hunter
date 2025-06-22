
#!/usr/bin/env python3
"""
Enhanced Statistical Analysis module with advanced C2 detection techniques
"""

import math
import statistics
import logging
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

class EnhancedStatisticalAnalyzer:
    """Enhanced statistical analyzer with advanced C2 detection capabilities"""
    
    def __init__(self):
        # Configuration parameters
        self.cert_size_threshold = 1200
        self.cert_validity_days = 365
        self.min_packets_for_analysis = 3
        self.periodicity_threshold = 0.7
        self.entropy_threshold = 2.0
        
    def calculate_entropy(self, data: List[float]) -> float:
        """Calculate Shannon entropy of data"""
        if not data or len(data) <= 1:
            return 0.0
        
        try:
            # Create frequency distribution
            unique_values = list(set(data))
            if len(unique_values) <= 1:
                return 0.0
            
            total = len(data)
            entropy = 0.0
            
            for value in unique_values:
                frequency = data.count(value)
                probability = frequency / total
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
        except Exception as e:
            logger.warning(f"Entropy calculation failed: {e}")
            return 0.0
    
    def detect_periodicity(self, times: List[float]) -> float:
        """Detect periodicity in inter-arrival times using autocorrelation"""
        if len(times) < 3:
            return 0.0
        
        try:
            # Calculate autocorrelation at lag 1
            mean_time = statistics.mean(times)
            numerator = sum((times[i] - mean_time) * (times[i+1] - mean_time) 
                          for i in range(len(times)-1))
            denominator = sum((t - mean_time) ** 2 for t in times)
            
            if denominator == 0:
                return 0.0
            
            autocorr = numerator / denominator
            return abs(autocorr)  # Return absolute value as periodicity measure
        except Exception as e:
            logger.warning(f"Periodicity detection failed: {e}")
            return 0.0
    
    def analyze_packet_timing_patterns(self, timestamps: List[float]) -> Dict:
        """Enhanced packet timing analysis with multiple techniques"""
        if len(timestamps) < 3:
            return {'is_regular': False, 'confidence': 0.0}
        
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        if not intervals:
            return {'is_regular': False, 'confidence': 0.0}
        
        # Basic statistics
        avg_interval = statistics.mean(intervals)
        variance = statistics.variance(intervals) if len(intervals) > 1 else 0
        std_dev = math.sqrt(variance)
        
        # Coefficient of variation for regularity detection
        coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 0
        
        # Periodicity detection
        periodicity = self.detect_periodicity(intervals)
        
        # Jitter calculation
        jitter = std_dev
        jitter_score = min(1.0, jitter / 5.0) if jitter > 2.0 else 0.0
        
        # Enhanced regularity detection
        regularity_indicators = 0
        confidence_factors = []
        
        # Low coefficient of variation indicates regular beaconing
        if coefficient_of_variation < 0.3:
            regularity_indicators += 1
            confidence_factors.append(1 - coefficient_of_variation)
        
        # High periodicity indicates beaconing
        if periodicity > self.periodicity_threshold:
            regularity_indicators += 1
            confidence_factors.append(periodicity)
        
        # Very low variance in timing
        if variance < 0.1 and len(intervals) > 5:
            regularity_indicators += 1
            confidence_factors.append(0.8)
        
        # Calculate overall confidence
        confidence = statistics.mean(confidence_factors) if confidence_factors else 0.0
        
        # Enhanced beaconing detection
        is_regular = (regularity_indicators >= 2 and len(timestamps) > 5) or \
                    (coefficient_of_variation < 0.2 and periodicity > 0.8)
        
        return {
            'host': f"enhanced_analysis_{len(timestamps)}_packets",
            'request_count': len(timestamps),
            'avg_interval': avg_interval,
            'std_deviation': std_dev,
            'coefficient_of_variation': coefficient_of_variation,
            'periodicity': periodicity,
            'jitter': jitter,
            'jitter_score': jitter_score,
            'variance': variance,
            'regularity_indicators': regularity_indicators,
            'is_regular': is_regular,
            'confidence': confidence,
            'duration': timestamps[-1] - timestamps[0] if timestamps else 0,
            'strength': confidence * (1 + regularity_indicators * 0.2)
        }
    
    def analyze_packet_sizes(self, packet_sizes: List[int]) -> Dict:
        """Enhanced packet size analysis"""
        if not packet_sizes:
            return {}
        
        features = {}
        suspicion_score = 0.0
        
        # Basic statistics
        features['packet_count'] = len(packet_sizes)
        features['avg_packet_size'] = statistics.mean(packet_sizes)
        features['max_packet_size'] = max(packet_sizes)
        features['min_packet_size'] = min(packet_sizes)
        features['median_packet_size'] = statistics.median(packet_sizes)
        
        # Advanced analysis
        packet_entropy = self.calculate_entropy([float(x) for x in packet_sizes])
        features['packet_entropy'] = packet_entropy
        
        # Low entropy (uniform sizes) is suspicious for C2
        if packet_entropy < self.entropy_threshold:
            entropy_factor = (self.entropy_threshold - packet_entropy) / self.entropy_threshold
            suspicion_score += 0.3 * entropy_factor
            features['low_entropy_score'] = entropy_factor
        
        # Small average packet sizes
        avg_size = statistics.mean(packet_sizes)
        if avg_size < 200:
            size_factor = (200 - avg_size) / 200
            suspicion_score += 0.25 * size_factor
            features['small_packets_score'] = size_factor
        
        # All packets being consistently small
        if max(packet_sizes) < 500:
            suspicion_score += 0.2
            features['all_small_packets'] = 1.0
        
        # Variance analysis for uniformity detection
        if len(packet_sizes) > 1:
            packet_variance = statistics.variance(packet_sizes)
            features['packet_variance'] = packet_variance
            
            # Very uniform packet sizes are suspicious
            if packet_variance < 100:
                suspicion_score += 0.15
                features['uniform_packets'] = 1.0
        
        features['suspicion_score'] = min(1.0, suspicion_score)
        return features
    
    def analyze_certificate_features(self, cert_data: Dict) -> Dict:
        """Analyze certificate features for C2 indicators"""
        features = {}
        suspicion_score = 0.0
        
        if not cert_data:
            return {'suspicion_score': 0.0}
        
        # Certificate size analysis
        if 'size' in cert_data and cert_data['size']:
            cert_size = float(cert_data['size'])
            features['cert_size'] = cert_size
            
            # Small certificates are suspicious
            if cert_size < self.cert_size_threshold:
                size_factor = (self.cert_size_threshold - cert_size) / self.cert_size_threshold
                suspicion_score += 0.4 * size_factor
                features['size_suspicion'] = size_factor
        
        # Self-signed certificate analysis
        if 'self_signed' in cert_data:
            is_self_signed = bool(cert_data['self_signed'])
            features['self_signed'] = float(is_self_signed)
            
            if is_self_signed:
                suspicion_score += 0.4
        
        # Validity period analysis
        if 'validity_days' in cert_data and cert_data['validity_days']:
            validity_days = float(cert_data['validity_days'])
            features['validity_days'] = validity_days
            
            # Short validity periods are suspicious
            if validity_days < self.cert_validity_days:
                validity_factor = (self.cert_validity_days - validity_days) / self.cert_validity_days
                suspicion_score += 0.3 * validity_factor
                features['validity_suspicion'] = validity_factor
            
            # Extremely long validity periods are also suspicious
            if validity_days > 3650:  # > 10 years
                suspicion_score += 0.2
                features['excessive_validity'] = 1.0
        
        features['suspicion_score'] = min(1.0, suspicion_score)
        return features
    
    def calculate_enhanced_confidence(self, detection_scores: Dict, feature_count: int) -> float:
        """Calculate enhanced confidence based on multiple factors"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on number of available features
        confidence += min(0.3, feature_count * 0.03)
        
        # Check score consistency across detection methods
        scores = [v for v in detection_scores.values() if isinstance(v, (int, float))]
        if len(scores) >= 2:
            score_variance = statistics.variance(scores)
            # Low variance means consistent detection across methods
            if score_variance < 0.1:
                confidence += 0.2
            # High variance reduces confidence
            elif score_variance > 0.5:
                confidence -= 0.15
        
        # Boost confidence if multiple high scores
        high_scores = [s for s in scores if s > 0.7]
        if len(high_scores) >= 2:
            confidence += 0.15
        
        return max(0.1, min(1.0, confidence))
    
    def analyze_beaconing(self, host: str, timestamps: List[float]) -> Dict:
        """Enhanced beaconing analysis using multiple techniques"""
        return self.analyze_packet_timing_patterns(timestamps)
    
    def analyze_host_behavior(self, host_key: str, stats: Dict) -> List[str]:
        """Enhanced host behavior analysis with more sophisticated detection"""
        suspicion_indicators = []
        
        # Enhanced user agent analysis
        user_agents = stats.get('user_agents', set())
        if len(user_agents) > 3:
            suspicion_indicators.append(f"Multiple user agents: {len(user_agents)} (potential evasion)")
        elif len(user_agents) == 1 and stats.get('request_count', 0) > 50:
            suspicion_indicators.append("Single user agent with high request count (automated behavior)")
        
        # Enhanced request frequency analysis
        request_count = stats.get('request_count', 0)
        if request_count > 100:
            suspicion_indicators.append(f"High request frequency: {request_count}")
        
        # Path pattern analysis with entropy
        paths = stats.get('paths', [])
        if paths:
            unique_paths = set(paths)
            path_entropy = self.calculate_entropy([float(hash(p) % 1000) for p in paths])
            
            # Low path diversity
            if len(unique_paths) < len(paths) * 0.1 and len(paths) > 10:
                suspicion_indicators.append("Repetitive path patterns (low diversity)")
            
            # Low path entropy
            if path_entropy < 3.0 and len(paths) > 20:
                suspicion_indicators.append(f"Low path entropy: {path_entropy:.2f} (predictable patterns)")
        
        # Enhanced timing analysis
        intervals = stats.get('intervals', [])
        if len(intervals) > 5:
            timing_analysis = self.analyze_packet_timing_patterns(
                [sum(intervals[:i+1]) for i in range(len(intervals))]
            )
            
            if timing_analysis.get('is_regular', False):
                confidence = timing_analysis.get('confidence', 0)
                suspicion_indicators.append(
                    f"Regular timing pattern detected (confidence: {confidence:.2f})"
                )
            
            if timing_analysis.get('jitter_score', 0) > 0.5:
                suspicion_indicators.append("High jitter detected (potential randomization)")
        
        # Response size analysis
        response_sizes = stats.get('response_sizes', [])
        if response_sizes:
            size_features = self.analyze_packet_sizes(response_sizes)
            if size_features.get('suspicion_score', 0) > 0.3:
                suspicion_indicators.append(
                    f"Suspicious response size patterns (score: {size_features['suspicion_score']:.2f})"
                )
        
        return suspicion_indicators
    
    def calculate_suspicion_score(self, http_data: Dict, dst_port: int, pattern_detector) -> tuple:
        """Enhanced suspicion scoring with multiple detection techniques"""
        suspicion_score = 0
        reasons = []
        
        user_agent = http_data.get('user_agent', '')
        path = http_data.get('path', '')
        
        # Enhanced user agent analysis
        if pattern_detector.is_suspicious_user_agent(user_agent):
            suspicion_score += 3
            reasons.append(f"Suspicious user agent: {user_agent}")
        
        # Enhanced URL pattern analysis
        if pattern_detector.is_suspicious_url(path):
            suspicion_score += 2
            reasons.append(f"Suspicious URL pattern: {path}")
        
        # Enhanced entropy analysis
        path_entropy = pattern_detector.calculate_entropy(path)
        if path_entropy > 4.5:
            suspicion_score += 2
            reasons.append(f"High entropy in path: {path_entropy:.2f}")
        elif path_entropy < 1.0 and len(path) > 10:
            suspicion_score += 1
            reasons.append(f"Very low entropy in path: {path_entropy:.2f} (potential pattern)")
        
        # Certificate analysis if available
        cert_data = http_data.get('certificate', {})
        if cert_data:
            cert_features = self.analyze_certificate_features(cert_data)
            cert_suspicion = cert_features.get('suspicion_score', 0)
            if cert_suspicion > 0.3:
                suspicion_score += int(cert_suspicion * 3)
                reasons.append(f"Suspicious certificate features (score: {cert_suspicion:.2f})")
        
        # Enhanced header analysis
        headers = http_data.get('headers', {})
        suspicious_header_count = 0
        for header, value in headers.items():
            if pattern_detector.has_suspicious_header(header):
                suspicious_header_count += 1
                reasons.append(f"Suspicious header: {header}")
        
        if suspicious_header_count > 2:
            suspicion_score += suspicious_header_count
        
        # Enhanced payload analysis
        full_payload = http_data.get('full_payload', '')
        if pattern_detector.has_base64_content(full_payload):
            suspicion_score += 1
            reasons.append("Base64-like content detected")
        
        # Payload entropy analysis
        if full_payload:
            payload_entropy = self.calculate_entropy([float(ord(c)) for c in full_payload[:1000]])
            if payload_entropy > 7.0:
                suspicion_score += 2
                reasons.append(f"High payload entropy: {payload_entropy:.2f} (potential encryption)")
        
        # Enhanced port analysis
        if dst_port not in [80, 443, 8080, 8443]:
            suspicion_score += 1
            reasons.append(f"Non-standard HTTP port: {dst_port}")
        
        # File extension analysis
        if pattern_detector.has_suspicious_file_extension(path):
            suspicion_score += 1
            reasons.append("Suspicious file extension detected")
        
        return suspicion_score, reasons

