
#!/usr/bin/env python3
"""
Enhanced Statistical Analysis with Advanced C2 Detection Techniques
"""

import statistics
import math
import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter

logger = logging.getLogger(__name__)

class EnhancedStatisticalAnalyzer:
    """Enhanced statistical analyzer with advanced C2 detection techniques"""
    
    def __init__(self):
        self.entropy_threshold = 2.0
        self.periodicity_threshold = 0.7
        self.regularity_threshold = 0.8
        self.uniformity_variance_threshold = 100
    
    def calculate_entropy(self, data: List[float]) -> float:
        """Calculate Shannon entropy of data with improved algorithm"""
        if not data or len(data) <= 1:
            return 0.0
        
        try:
            # Create frequency distribution with binning for continuous data
            if len(set(data)) == len(data):  # All unique values
                # Bin continuous data for entropy calculation
                min_val, max_val = min(data), max(data)
                if max_val == min_val:
                    return 0.0
                
                num_bins = min(10, int(math.sqrt(len(data))))
                bin_size = (max_val - min_val) / num_bins
                bins = [int((x - min_val) / bin_size) for x in data]
                bins = [min(b, num_bins - 1) for b in bins]  # Ensure within bounds
                data_for_entropy = bins
            else:
                data_for_entropy = data
            
            # Calculate entropy
            counter = Counter(data_for_entropy)
            total = len(data_for_entropy)
            entropy = 0.0
            
            for count in counter.values():
                probability = count / total
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.warning(f"Entropy calculation failed: {e}")
            return 0.0
    
    def detect_periodicity(self, times: List[float]) -> float:
        """Detect periodicity in inter-arrival times with autocorrelation"""
        if len(times) < 3:
            return 0.0
        
        try:
            # Calculate autocorrelation at lag 1
            mean_time = statistics.mean(times)
            
            # Handle case where all values are the same
            variance = sum((t - mean_time) ** 2 for t in times)
            if variance == 0:
                return 1.0  # Perfect regularity
            
            numerator = sum((times[i] - mean_time) * (times[i+1] - mean_time) 
                          for i in range(len(times)-1))
            
            autocorr = numerator / variance
            return abs(autocorr)  # Return absolute value as periodicity measure
            
        except Exception as e:
            logger.warning(f"Periodicity detection failed: {e}")
            return 0.0
    
    def analyze_packet_uniformity(self, packet_sizes: List[float]) -> Dict[str, float]:
        """Analyze packet size uniformity with advanced metrics"""
        if not packet_sizes:
            return {}
        
        analysis = {}
        
        try:
            # Basic statistics
            analysis['avg_packet_size'] = statistics.mean(packet_sizes)
            analysis['max_packet_size'] = max(packet_sizes)
            analysis['min_packet_size'] = min(packet_sizes)
            analysis['packet_count'] = len(packet_sizes)
            
            # Variance and standard deviation
            if len(packet_sizes) > 1:
                analysis['packet_variance'] = statistics.variance(packet_sizes)
                analysis['packet_std'] = statistics.stdev(packet_sizes)
                
                # Coefficient of variation
                if analysis['avg_packet_size'] > 0:
                    analysis['coefficient_of_variation'] = analysis['packet_std'] / analysis['avg_packet_size']
            
            # Entropy analysis
            analysis['packet_entropy'] = self.calculate_entropy(packet_sizes)
            
            # Uniformity indicators
            unique_sizes = len(set(packet_sizes))
            analysis['unique_size_ratio'] = unique_sizes / len(packet_sizes)
            
            # Small packet analysis
            small_packets = sum(1 for size in packet_sizes if size < 200)
            analysis['small_packet_ratio'] = small_packets / len(packet_sizes)
            
            # Suspicious uniformity flags
            analysis['very_uniform'] = (
                analysis.get('packet_variance', float('inf')) < self.uniformity_variance_threshold
            )
            analysis['low_entropy'] = (
                analysis.get('packet_entropy', float('inf')) < self.entropy_threshold
            )
            analysis['all_small_packets'] = max(packet_sizes) < 500
            
        except Exception as e:
            logger.error(f"Packet uniformity analysis failed: {e}")
        
        return analysis
    
    def analyze_timing_patterns(self, inter_arrival_times: List[float]) -> Dict[str, float]:
        """Analyze timing patterns with advanced statistical methods"""
        if not inter_arrival_times or len(inter_arrival_times) < 2:
            return {}
        
        analysis = {}
        
        try:
            # Basic timing statistics
            analysis['avg_inter_arrival'] = statistics.mean(inter_arrival_times)
            analysis['max_inter_arrival'] = max(inter_arrival_times)
            analysis['min_inter_arrival'] = min(inter_arrival_times)
            
            # Jitter analysis
            if len(inter_arrival_times) > 1:
                analysis['jitter'] = statistics.stdev(inter_arrival_times)
                analysis['time_variance'] = statistics.variance(inter_arrival_times)
                
                # Coefficient of variation for timing
                if analysis['avg_inter_arrival'] > 0:
                    analysis['timing_cov'] = analysis['jitter'] / analysis['avg_inter_arrival']
            
            # Periodicity detection
            analysis['periodicity'] = self.detect_periodicity(inter_arrival_times)
            
            # Timing entropy
            analysis['timing_entropy'] = self.calculate_entropy(inter_arrival_times)
            
            # Regularity analysis
            analysis['very_regular'] = (
                analysis.get('time_variance', float('inf')) < 0.1
            )
            analysis['high_periodicity'] = (
                analysis.get('periodicity', 0) > self.periodicity_threshold
            )
            analysis['high_jitter'] = (
                analysis.get('jitter', 0) > 2.0
            )
            
        except Exception as e:
            logger.error(f"Timing pattern analysis failed: {e}")
        
        return analysis
    
    def analyze_certificate_features(self, cert: Dict) -> Dict[str, float]:
        """Analyze certificate features with enhanced detection"""
        analysis = {}
        
        try:
            # Size analysis
            if 'size' in cert and cert['size'] is not None:
                cert_size = float(cert['size'])
                analysis['cert_size'] = cert_size
                
                # Small certificate suspicion (< 1200 bytes)
                if cert_size < 1200:
                    analysis['small_cert_factor'] = max(0, (1200 - cert_size) / 1200)
                
                # Very small certificates are highly suspicious
                if cert_size < 800:
                    analysis['very_small_cert'] = 1.0
            
            # Self-signed analysis
            if 'self_signed' in cert:
                analysis['self_signed'] = float(bool(cert['self_signed']))
            
            # Validity period analysis
            if 'validity_days' in cert and cert['validity_days'] is not None:
                validity_days = float(cert['validity_days'])
                analysis['validity_days'] = validity_days
                
                # Short validity suspicion (< 365 days)
                if validity_days < 365:
                    analysis['short_validity_factor'] = max(0, (365 - validity_days) / 365)
                
                # Very short validity is highly suspicious
                if validity_days < 90:
                    analysis['very_short_validity'] = 1.0
                
                # Extremely long validity is also suspicious (> 10 years)
                if validity_days > 3650:
                    analysis['excessive_validity'] = 1.0
            
        except Exception as e:
            logger.error(f"Certificate analysis failed: {e}")
        
        return analysis
    
    def calculate_behavioral_score(self, packet_analysis: Dict[str, float], 
                                 timing_analysis: Dict[str, float],
                                 cert_analysis: Dict[str, float]) -> float:
        """Calculate comprehensive behavioral score"""
        score = 0.0
        
        try:
            # Packet-based scoring
            if packet_analysis.get('low_entropy', False):
                entropy_factor = max(0, (self.entropy_threshold - packet_analysis.get('packet_entropy', 2.0)) / self.entropy_threshold)
                score += 0.2 * entropy_factor
            
            if packet_analysis.get('very_uniform', False):
                score += 0.15
            
            if packet_analysis.get('all_small_packets', False):
                score += 0.15
            
            small_packet_ratio = packet_analysis.get('small_packet_ratio', 0)
            if small_packet_ratio > 0.8:
                score += 0.1 * small_packet_ratio
            
            # Timing-based scoring
            if timing_analysis.get('high_periodicity', False):
                periodicity = timing_analysis.get('periodicity', 0)
                score += 0.2 * periodicity
            
            if timing_analysis.get('very_regular', False):
                score += 0.1
            
            if timing_analysis.get('high_jitter', False):
                jitter_factor = min(1.0, timing_analysis.get('jitter', 0) / 5.0)
                score += 0.1 * jitter_factor
            
            # Certificate-based scoring
            if cert_analysis.get('self_signed', 0) > 0:
                score += 0.3
            
            if 'small_cert_factor' in cert_analysis:
                score += 0.2 * cert_analysis['small_cert_factor']
            
            if 'short_validity_factor' in cert_analysis:
                score += 0.15 * cert_analysis['short_validity_factor']
            
            if cert_analysis.get('very_small_cert', 0) > 0:
                score += 0.1
            
            if cert_analysis.get('very_short_validity', 0) > 0:
                score += 0.1
            
        except Exception as e:
            logger.error(f"Behavioral score calculation failed: {e}")
        
        return min(1.0, score)
    
    def calculate_confidence_score(self, cert_score: float, behavioral_score: float,
                                 available_features: int, score_consistency: float) -> float:
        """Calculate enhanced confidence score"""
        confidence = 0.5  # Base confidence
        
        try:
            # Feature completeness bonus
            feature_bonus = min(0.3, available_features * 0.02)
            confidence += feature_bonus
            
            # Score consistency bonus
            if cert_score > 0.6 and behavioral_score > 0.6:
                confidence += 0.2
            
            # Penalize inconsistent scores
            score_diff = abs(cert_score - behavioral_score)
            if score_diff > 0.5:
                confidence -= 0.15
            elif score_diff > 0.3:
                confidence -= 0.1
            
            # High score bonus
            combined_score = (cert_score + behavioral_score) / 2
            if combined_score > 0.8:
                confidence += 0.1
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {e}")
        
        return max(0.1, min(1.0, confidence))

