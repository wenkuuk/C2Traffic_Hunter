
#!/usr/bin/env python3
"""
Enhanced Threat Assessment Engine with Improved Detection Accuracy v3.0
"""

import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class DetectionCorrelation:
    """Enhanced detection correlation analysis"""
    host_correlations: Dict[str, int]
    time_correlations: List[Tuple[datetime, str]]
    pattern_correlations: Dict[str, float]
    cross_detection_score: float
    temporal_clustering: float
    behavioral_consistency: float


class AdvancedPatternAnalyzer:
    """Advanced pattern analysis with machine learning insights"""
    
    def __init__(self):
        self.beacon_thresholds = {
            'min_intervals': 3,
            'regularity_threshold': 0.65,
            'jitter_tolerance': 0.4,
            'persistence_hours': 2.0
        }
    
    def calculate_beaconing_strength(self, pattern: Dict[str, Any]) -> float:
        """Enhanced beaconing strength with advanced statistical analysis"""
        timestamps = pattern.get('timestamps', [])
        if len(timestamps) < 3:
            return 0.15
        
        # Convert timestamps and calculate intervals
        intervals = self._calculate_intervals(timestamps)
        if not intervals:
            return 0.2
        
        # Multi-dimensional regularity analysis
        regularity_score = self._analyze_regularity(intervals)
        consistency_score = self._analyze_consistency(intervals)
        persistence_score = self._analyze_persistence(pattern, timestamps)
        frequency_score = self._analyze_frequency(pattern, timestamps)
        
        # Weighted combination with non-linear scaling
        base_strength = (
            regularity_score * 0.35 +
            consistency_score * 0.25 +
            persistence_score * 0.25 +
            frequency_score * 0.15
        )
        
        # Apply correlation bonus
        correlation_bonus = min(0.25, pattern.get('correlated_detections', 0) * 0.08)
        
        # Non-linear enhancement for strong patterns
        final_strength = base_strength + correlation_bonus
        if final_strength > 0.7:
            final_strength = 0.7 + (final_strength - 0.7) * 0.5  # Diminishing returns
        
        return min(0.92, max(0.1, final_strength))
    
    def _calculate_intervals(self, timestamps: List) -> List[float]:
        """Calculate time intervals with error handling"""
        intervals = []
        for i in range(1, len(timestamps)):
            try:
                if isinstance(timestamps[i], (int, float)) and isinstance(timestamps[i-1], (int, float)):
                    interval = timestamps[i] - timestamps[i-1]
                    if 0 < interval < 86400:  # Filter unrealistic intervals
                        intervals.append(interval)
            except (TypeError, ValueError):
                continue
        return intervals
    
    def _analyze_regularity(self, intervals: List[float]) -> float:
        """Advanced regularity analysis with outlier detection"""
        if len(intervals) < 2:
            return 0.3
        
        # Remove outliers using IQR method
        sorted_intervals = sorted(intervals)
        q1 = sorted_intervals[len(sorted_intervals)//4]
        q3 = sorted_intervals[3*len(sorted_intervals)//4]
        iqr = q3 - q1
        
        filtered_intervals = [
            x for x in intervals 
            if q1 - 1.5*iqr <= x <= q3 + 1.5*iqr
        ]
        
        if not filtered_intervals:
            return 0.2
        
        mean_interval = statistics.mean(filtered_intervals)
        if mean_interval == 0:
            return 0.2
        
        # Calculate coefficient of variation
        std_dev = statistics.stdev(filtered_intervals) if len(filtered_intervals) > 1 else 0
        cv = std_dev / mean_interval
        
        # Non-linear regularity scoring
        regularity = max(0.1, 1 - min(cv, 2.0))
        
        # Bonus for very regular patterns
        if cv < 0.1:
            regularity *= 1.2
        
        return min(0.95, regularity)
    
    def _analyze_consistency(self, intervals: List[float]) -> float:
        """Analyze temporal consistency patterns"""
        if len(intervals) < 3:
            return 0.4
        
        # Look for patterns in interval sequences
        pattern_scores = []
        
        # Exact repetition detection
        unique_intervals = set(intervals)
        repetition_score = 1 - (len(unique_intervals) / len(intervals))
        pattern_scores.append(repetition_score)
        
        # Harmonic pattern detection
        if len(intervals) >= 4:
            harmonic_score = self._detect_harmonic_patterns(intervals)
            pattern_scores.append(harmonic_score)
        
        # Trend analysis
        trend_score = self._analyze_trend_consistency(intervals)
        pattern_scores.append(trend_score)
        
        return statistics.mean(pattern_scores)
    
    def _detect_harmonic_patterns(self, intervals: List[float]) -> float:
        """Detect harmonic patterns in intervals"""
        if len(intervals) < 4:
            return 0.3
        
        # Check for multiples/divisors pattern
        base_interval = statistics.median(intervals)
        harmonic_matches = 0
        
        for interval in intervals:
            # Check if interval is a harmonic of base (within tolerance)
            for multiplier in [0.5, 1.0, 2.0, 3.0, 0.33, 1.5]:
                expected = base_interval * multiplier
                if abs(interval - expected) / expected < 0.2:
                    harmonic_matches += 1
                    break
        
        return harmonic_matches / len(intervals)
    
    def _analyze_trend_consistency(self, intervals: List[float]) -> float:
        """Analyze consistency in interval trends"""
        if len(intervals) < 4:
            return 0.4
        
        # Calculate moving averages to smooth trends
        window_size = min(3, len(intervals) // 2)
        moving_avgs = []
        
        for i in range(len(intervals) - window_size + 1):
            avg = sum(intervals[i:i+window_size]) / window_size
            moving_avgs.append(avg)
        
        if len(moving_avgs) < 2:
            return 0.4
        
        # Calculate trend stability
        trend_changes = []
        for i in range(1, len(moving_avgs)):
            change = abs(moving_avgs[i] - moving_avgs[i-1]) / moving_avgs[i-1]
            trend_changes.append(change)
        
        avg_change = statistics.mean(trend_changes) if trend_changes else 1.0
        stability = max(0.1, 1 - min(avg_change, 1.0))
        
        return stability
    
    def _analyze_persistence(self, pattern: Dict, timestamps: List) -> float:
        """Analyze pattern persistence over time"""
        duration_hours = pattern.get('duration_hours', 1)
        
        # Base persistence score
        if duration_hours < 0.5:
            base_score = 0.2
        elif duration_hours < 2:
            base_score = 0.4
        elif duration_hours < 8:
            base_score = 0.6
        elif duration_hours < 24:
            base_score = 0.8
        else:
            base_score = 0.9
        
        # Consistency over time bonus
        if len(timestamps) > 10:
            time_consistency = self._calculate_time_consistency(timestamps)
            base_score *= (0.8 + time_consistency * 0.4)
        
        return min(0.9, base_score)
    
    def _calculate_time_consistency(self, timestamps: List) -> float:
        """Calculate consistency of timing over the full duration"""
        if len(timestamps) < 5:
            return 0.5
        
        # Divide timeline into segments and analyze consistency
        segments = 3
        segment_size = len(timestamps) // segments
        segment_scores = []
        
        for i in range(segments):
            start_idx = i * segment_size
            end_idx = start_idx + segment_size if i < segments - 1 else len(timestamps)
            segment_timestamps = timestamps[start_idx:end_idx]
            
            if len(segment_timestamps) >= 2:
                segment_intervals = self._calculate_intervals(segment_timestamps)
                if segment_intervals:
                    cv = statistics.stdev(segment_intervals) / statistics.mean(segment_intervals)
                    segment_scores.append(max(0.1, 1 - cv))
        
        return statistics.mean(segment_scores) if segment_scores else 0.5
    
    def _analyze_frequency(self, pattern: Dict, timestamps: List) -> float:
        """Analyze frequency characteristics"""
        frequency_per_hour = pattern.get('frequency_per_hour', len(timestamps))
        
        # Optimal frequency range for C2 (not too high, not too low)
        if 0.5 <= frequency_per_hour <= 120:  # 30 seconds to 2 hours
            frequency_score = 0.8
        elif 0.1 <= frequency_per_hour <= 300:  # 12 seconds to 10 hours  
            frequency_score = 0.6
        else:
            frequency_score = 0.3
        
        # Bonus for sustained frequency
        if len(timestamps) > 20:
            frequency_score *= 1.1
        
        return min(0.9, frequency_score)


class AdvancedAnomalyAnalyzer:
    """Advanced anomaly detection with multiple statistical methods"""
    
    def calculate_anomaly_strength(self, anomaly: Dict[str, Any]) -> float:
        """Enhanced anomaly strength with multiple detection methods"""
        baseline = anomaly.get('baseline', 0)
        current = anomaly.get('current', 0)
        anomaly_type = anomaly.get('type', 'unknown')
        
        # Statistical significance analysis
        z_score = anomaly.get('z_score', 0)
        p_value = anomaly.get('p_value', 0.5)
        
        # Multi-method scoring
        scores = []
        
        # Z-score based scoring
        if z_score >= 3:
            scores.append(0.9)
        elif z_score >= 2.5:
            scores.append(0.8)
        elif z_score >= 2:
            scores.append(0.7)
        elif z_score >= 1.5:
            scores.append(0.5)
        else:
            scores.append(max(0.1, z_score / 3))
        
        # P-value based scoring
        if p_value <= 0.01:
            scores.append(0.9)
        elif p_value <= 0.05:
            scores.append(0.7)
        elif p_value <= 0.1:
            scores.append(0.5)
        else:
            scores.append(0.2)
        
        # Relative deviation scoring
        if baseline > 0:
            relative_dev = abs(current - baseline) / baseline
            if relative_dev >= 5:
                scores.append(0.9)
            elif relative_dev >= 2:
                scores.append(0.7)
            elif relative_dev >= 1:
                scores.append(0.5)
            else:
                scores.append(relative_dev * 0.5)
        else:
            scores.append(0.6 if current > 0 else 0.2)
        
        # Type-specific adjustments
        type_multipliers = {
            'frequency_anomaly': 1.3,
            'size_anomaly': 1.1,
            'timing_anomaly': 1.4,
            'behavioral_anomaly': 1.2,
            'communication_anomaly': 1.25
        }
        
        base_strength = statistics.mean(scores)
        multiplier = type_multipliers.get(anomaly_type, 1.0)
        
        # Persistence and recency factors
        persistence_hours = anomaly.get('persistence_hours', 1)
        persistence_factor = min(1.4, 1 + math.log(persistence_hours + 1) * 0.1)
        
        recency_hours = anomaly.get('recency_hours', 0)
        recency_factor = max(0.7, 1 - recency_hours / 168)  # Decay over week
        
        final_strength = base_strength * multiplier * persistence_factor * recency_factor
        
        return min(0.92, max(0.05, final_strength))


class EnhancedThreatAssessor:
    """Main enhanced threat assessment engine with improved accuracy"""
    
    def __init__(self):
        self.pattern_analyzer = AdvancedPatternAnalyzer()
        self.anomaly_analyzer = AdvancedAnomalyAnalyzer()
        
        # Refined threat weights for better balance
        self.threat_weights = {
            'signature_detections': {'base': 0.35, 'max_contribution': 0.45},
            'ml_classifications': {'base': 0.30, 'max_contribution': 0.40},
            'beaconing_patterns': {'base': 0.25, 'max_contribution': 0.35},
            'behavioral_anomalies': {'base': 0.10, 'max_contribution': 0.25}
        }
        
        # Enhanced threat thresholds with confidence consideration
        self.threat_thresholds = {
            'CRITICAL': {'score': 0.8, 'confidence': 0.75},
            'HIGH': {'score': 0.6, 'confidence': 0.65},
            'MEDIUM-HIGH': {'score': 0.45, 'confidence': 0.55},
            'MEDIUM': {'score': 0.3, 'confidence': 0.45},
            'LOW-MEDIUM': {'score': 0.18, 'confidence': 0.35},
            'LOW': {'score': 0.0, 'confidence': 0.0}
        }
    
    def generate_threat_assessment(self, results: Dict[str, List]) -> Dict[str, Any]:
        """Generate comprehensive threat assessment with enhanced accuracy"""
        
        # Advanced correlation analysis
        correlation_data = self._analyze_advanced_correlations(results)
        
        # Enhanced component scoring
        component_scores = self._calculate_advanced_component_scores(results, correlation_data)
        
        # Sophisticated confidence calculation
        confidence_metrics = self._calculate_advanced_confidence(results, correlation_data)
        
        # Risk factor assessment with correlation
        risk_factors = self._assess_comprehensive_risk_factors(results, component_scores, correlation_data)
        
        # Final threat score with advanced correlation bonus
        raw_threat_score = sum(component_scores.values())
        correlation_bonus = self._calculate_advanced_correlation_bonus(results, correlation_data)
        
        # Apply non-linear scaling for extreme scores
        scaled_threat_score = self._apply_threat_scaling(raw_threat_score + correlation_bonus)
        
        # Determine threat level with enhanced logic
        threat_level, confidence_level = self._determine_advanced_threat_level(
            scaled_threat_score, confidence_metrics['overall_confidence']
        )
        
        return {
            'threat_score': scaled_threat_score,
            'threat_level': threat_level,
            'confidence_score': confidence_metrics['overall_confidence'],
            'confidence_level': confidence_level,
            'component_scores': component_scores,
            'detection_breakdown': {
                'signature_detections': len(results.get('signature_detections', [])),
                'ml_classifications': len(results.get('ml_classifications', [])),
                'beaconing_patterns': len(results.get('beaconing_patterns', [])),
                'behavioral_anomalies': len(results.get('behavioral_anomalies', []))
            },
            'risk_factors': risk_factors,
            'correlation_bonus': correlation_bonus,
            'total_detections': sum(len(results.get(key, [])) for key in 
                                  ['signature_detections', 'ml_classifications', 
                                   'beaconing_patterns', 'behavioral_anomalies']),
            'correlation_analysis': {
                'host_correlations': correlation_data.host_correlations,
                'temporal_clustering': correlation_data.temporal_clustering,
                'behavioral_consistency': correlation_data.behavioral_consistency,
                'cross_detection_score': correlation_data.cross_detection_score
            },
            'confidence_breakdown': confidence_metrics,
            'assessment_metadata': {
                'version': '3.0',
                'timestamp': datetime.now().isoformat(),
                'analysis_depth': 'comprehensive'
            }
        }
    
    def _analyze_advanced_correlations(self, results: Dict) -> DetectionCorrelation:
        """Advanced correlation analysis with temporal and behavioral clustering"""
        host_correlations = defaultdict(int)
        time_correlations = []
        pattern_correlations = defaultdict(float)
        
        # Collect all detections with metadata
        all_detections = []
        for detection_type, detections in results.items():
            if detection_type.endswith(('_detections', '_patterns', '_anomalies', '_classifications')):
                for detection in detections:
                    host_key = self._extract_host_key(detection)
                    timestamp = self._extract_timestamp(detection)
                    
                    if host_key:
                        host_correlations[host_key] += 1
                        all_detections.append({
                            'host': host_key,
                            'type': detection_type,
                            'timestamp': timestamp,
                            'detection': detection
                        })
        
        # Temporal clustering analysis
        temporal_clustering = self._analyze_temporal_clustering(all_detections)
        
        # Behavioral consistency analysis
        behavioral_consistency = self._analyze_behavioral_consistency(all_detections)
        
        # Cross-detection scoring with advanced weighting
        cross_detection_score = self._calculate_cross_detection_score(host_correlations, all_detections)
        
        return DetectionCorrelation(
            host_correlations=dict(host_correlations),
            time_correlations=time_correlations,
            pattern_correlations=dict(pattern_correlations),
            cross_detection_score=cross_detection_score,
            temporal_clustering=temporal_clustering,
            behavioral_consistency=behavioral_consistency
        )
    
    def _analyze_temporal_clustering(self, detections: List[Dict]) -> float:
        """Analyze temporal clustering of detections"""
        if len(detections) < 2:
            return 0.1
        
        # Sort by timestamp
        sorted_detections = sorted(detections, key=lambda x: x.get('timestamp', ''))
        
        # Calculate time gaps between consecutive detections
        time_gaps = []
        for i in range(1, len(sorted_detections)):
            gap = self._calculate_time_diff(
                sorted_detections[i]['timestamp'],
                sorted_detections[i-1]['timestamp']
            )
            if gap > 0:
                time_gaps.append(gap)
        
        if not time_gaps:
            return 0.2
        
        # Analyze clustering (smaller gaps = more clustering)
        median_gap = statistics.median(time_gaps)
        
        # High clustering if many detections within short timeframes
        short_gap_count = sum(1 for gap in time_gaps if gap < 300)  # 5 minutes
        clustering_ratio = short_gap_count / len(time_gaps)
        
        # Bonus for sustained clustering
        if clustering_ratio > 0.5 and len(time_gaps) > 5:
            clustering_score = min(0.9, clustering_ratio * 1.2)
        else:
            clustering_score = clustering_ratio * 0.8
        
        return clustering_score
    
    def _analyze_behavioral_consistency(self, detections: List[Dict]) -> float:
        """Analyze behavioral consistency across detections"""
        if len(detections) < 3:
            return 0.3
        
        # Group by host for consistency analysis
        host_behaviors = defaultdict(list)
        for detection in detections:
            host = detection['host']
            detection_type = detection['type']
            host_behaviors[host].append(detection_type)
        
        consistency_scores = []
        for host, behaviors in host_behaviors.items():
            if len(behaviors) < 2:
                continue
            
            # Calculate behavior diversity (lower = more consistent)
            unique_behaviors = set(behaviors)
            consistency = 1 - (len(unique_behaviors) - 1) / max(len(behaviors), 1)
            consistency_scores.append(consistency)
        
        if not consistency_scores:
            return 0.3
        
        avg_consistency = statistics.mean(consistency_scores)
        
        # Bonus for multi-host consistent behavior
        if len(host_behaviors) > 1:
            avg_consistency *= 1.1
        
        return min(0.85, avg_consistency)
    
    def _calculate_cross_detection_score(self, host_correlations: Dict, all_detections: List) -> float:
        """Calculate cross-detection correlation score"""
        if not host_correlations:
            return 0.1
        
        # Multi-host correlation bonus
        multi_host_count = sum(1 for count in host_correlations.values() if count > 1)
        multi_host_score = min(0.4, multi_host_count * 0.15)
        
        # Detection type diversity score
        detection_types = set(d['type'] for d in all_detections)
        diversity_score = min(0.3, len(detection_types) * 0.1)
        
        # High-correlation host bonus
        max_correlations = max(host_correlations.values()) if host_correlations else 0
        if max_correlations >= 5:
            correlation_intensity = min(0.3, max_correlations * 0.05)
        else:
            correlation_intensity = max_correlations * 0.02
        
        total_score = multi_host_score + diversity_score + correlation_intensity
        return min(0.8, total_score)
    
    def _calculate_advanced_component_scores(self, results: Dict, correlation_data: DetectionCorrelation) -> Dict[str, float]:
        """Calculate component scores with advanced correlation weighting"""
        scores = {}
        
        # Enhanced signature scoring
        sig_detections = results.get('signature_detections', [])
        if sig_detections:
            # Quality-weighted scoring
            signature_scores = []
            for detection in sig_detections:
                base_score = detection.get('signature_score', 5) / 10.0
                confidence = detection.get('confidence', 0.8)
                quality_score = (base_score + confidence) / 2
                signature_scores.append(quality_score)
            
            max_sig_score = max(signature_scores) if signature_scores else 0.5
            correlation_boost = correlation_data.cross_detection_score * 0.15
            
            scores['signature'] = min(
                self.threat_weights['signature_detections']['max_contribution'],
                max_sig_score * self.threat_weights['signature_detections']['base'] + correlation_boost
            )
        else:
            scores['signature'] = 0.0
        
        # Enhanced ML classification scoring
        ml_detections = results.get('ml_classifications', [])
        if ml_detections:
            ml_scores = []
            for detection in ml_detections:
                ml_confidence = detection.get('ml_score', 0.5)
                feature_quality = detection.get('feature_quality', 0.7)
                combined_score = (ml_confidence * 0.7 + feature_quality * 0.3)
                ml_scores.append(combined_score)
            
            max_ml_score = max(ml_scores) if ml_scores else 0.5
            temporal_boost = correlation_data.temporal_clustering * 0.1
            
            scores['ml'] = min(
                self.threat_weights['ml_classifications']['max_contribution'],
                max_ml_score * self.threat_weights['ml_classifications']['base'] + temporal_boost
            )
        else:
            scores['ml'] = 0.0
        
        # Enhanced beaconing pattern scoring
        beacon_patterns = results.get('beaconing_patterns', [])
        if beacon_patterns:
            pattern_strengths = []
            for pattern in beacon_patterns:
                strength = self.pattern_analyzer.calculate_beaconing_strength(pattern)
                pattern_strengths.append(strength)
            
            max_beacon_strength = max(pattern_strengths) if pattern_strengths else 0.4
            behavioral_boost = correlation_data.behavioral_consistency * 0.08
            
            scores['beaconing'] = min(
                self.threat_weights['beaconing_patterns']['max_contribution'],
                max_beacon_strength * self.threat_weights['beaconing_patterns']['base'] + behavioral_boost
            )
        else:
            scores['beaconing'] = 0.0
        
        # Enhanced behavioral anomaly scoring
        behavioral_anomalies = results.get('behavioral_anomalies', [])
        if behavioral_anomalies:
            anomaly_strengths = []
            for anomaly in behavioral_anomalies:
                strength = self.anomaly_analyzer.calculate_anomaly_strength(anomaly)
                anomaly_strengths.append(strength)
            
            max_anomaly_strength = max(anomaly_strengths) if anomaly_strengths else 0.3
            
            scores['behavioral'] = min(
                self.threat_weights['behavioral_anomalies']['max_contribution'],
                max_anomaly_strength * self.threat_weights['behavioral_anomalies']['base']
            )
        else:
            scores['behavioral'] = 0.0
        
        return scores
    
    def _calculate_advanced_confidence(self, results: Dict, correlation_data: DetectionCorrelation) -> Dict[str, float]:
        """Calculate advanced confidence metrics"""
        # Base confidence from detection diversity
        active_types = sum(1 for key in ['signature_detections', 'ml_classifications', 
                                      'beaconing_patterns', 'behavioral_anomalies'] 
                          if len(results.get(key, [])) > 0)
        
        base_confidence = 0.25 + (active_types * 0.15)
        
        # Quality-based confidence
        quality_factors = []
        
        # Signature quality
        sig_detections = results.get('signature_detections', [])
        if sig_detections:
            sig_confidences = [d.get('confidence', 0.8) for d in sig_detections]
            quality_factors.append(statistics.mean(sig_confidences))
        
        # ML quality
        ml_detections = results.get('ml_classifications', [])
        if ml_detections:
            ml_confidences = [d.get('ml_score', 0.5) for d in ml_detections]
            quality_factors.append(statistics.mean(ml_confidences))
        
        quality_confidence = statistics.mean(quality_factors) * 0.3 if quality_factors else 0.1
        
        # Correlation confidence
        correlation_confidence = (
            correlation_data.cross_detection_score * 0.2 +
            correlation_data.temporal_clustering * 0.15 +
            correlation_data.behavioral_consistency * 0.1
        )
        
        # Detection count confidence with diminishing returns
        total_detections = sum(len(results.get(key, [])) for key in 
                             ['signature_detections', 'ml_classifications', 
                              'beaconing_patterns', 'behavioral_anomalies'])
        
        count_confidence = min(0.25, math.log(total_detections + 1) * 0.08)
        
        overall_confidence = min(0.92, 
            base_confidence + quality_confidence + correlation_confidence + count_confidence
        )
        
        return {
            'overall_confidence': overall_confidence,
            'base_confidence': base_confidence,
            'quality_confidence': quality_confidence,
            'correlation_confidence': correlation_confidence,
            'count_confidence': count_confidence
        }
    
    def _assess_comprehensive_risk_factors(self, results: Dict, component_scores: Dict, 
                                         correlation_data: DetectionCorrelation) -> Dict[str, bool]:
        """Comprehensive risk factor assessment"""
        risk_factors = {
            'persistence': False,
            'lateral_movement': False,
            'data_exfiltration': False,
            'command_control': False,
            'privilege_escalation': False,
            'steganography': False,
            'dns_tunneling': False,
            'advanced_evasion': False
        }
        
        # Enhanced persistence detection
        if (component_scores.get('beaconing', 0) > 0.15 or 
            len(results.get('behavioral_anomalies', [])) >= 2 or
            correlation_data.temporal_clustering > 0.6):
            risk_factors['persistence'] = True
        
        # Command and control indicators
        if (component_scores.get('beaconing', 0) > 0.12 or 
            component_scores.get('signature', 0) > 0.25 or
            correlation_data.behavioral_consistency > 0.7):
            risk_factors['command_control'] = True
        
        # Data exfiltration indicators
        if (component_scores.get('signature', 0) > 0.2 or 
            component_scores.get('ml', 0) > 0.15 or
            len(results.get('ml_classifications', [])) >= 3):
            risk_factors['data_exfiltration'] = True
        
        # Advanced evasion techniques
        if (component_scores.get('ml', 0) > 0.25 and 
            correlation_data.cross_detection_score > 0.5):
            risk_factors['advanced_evasion'] = True
        
        # Steganography detection
        if component_scores.get('ml', 0) > 0.3:
            risk_factors['steganography'] = True
        
        # DNS tunneling
        if len(results.get('signature_detections', [])) > 3:
            risk_factors['dns_tunneling'] = True
        
        # Lateral movement
        if len(correlation_data.host_correlations) > 2:
            risk_factors['lateral_movement'] = True
        
        return risk_factors
    
    def _calculate_advanced_correlation_bonus(self, results: Dict, 
                                            correlation_data: DetectionCorrelation) -> float:
        """Advanced correlation bonus calculation"""
        base_bonus = correlation_data.cross_detection_score * 0.12
        
        # Temporal clustering bonus
        temporal_bonus = correlation_data.temporal_clustering * 0.08
        
        # Behavioral consistency bonus
        behavioral_bonus = correlation_data.behavioral_consistency * 0.06
        
        # Multi-host correlation bonus
        multi_host_bonus = min(0.08, len([h for h, c in correlation_data.host_correlations.items() if c > 1]) * 0.02)
        
        # Detection diversity bonus
        active_types = sum(1 for key in ['signature_detections', 'ml_classifications', 
                                       'beaconing_patterns', 'behavioral_anomalies'] 
                          if len(results.get(key, [])) > 0)
        diversity_bonus = min(0.06, (active_types - 1) * 0.02)
        
        total_bonus = base_bonus + temporal_bonus + behavioral_bonus + multi_host_bonus + diversity_bonus
        return min(0.2, total_bonus)
    
    def _apply_threat_scaling(self, raw_score: float) -> float:
        """Apply non-linear threat scaling for better discrimination"""
        if raw_score <= 0.3:
            return raw_score
        elif raw_score <= 0.7:
            # Gentle enhancement in medium range
            return 0.3 + (raw_score - 0.3) * 1.1
        else:
            # Stronger enhancement for high threats
            return 0.74 + (raw_score - 0.7) * 0.7
    
    def _determine_advanced_threat_level(self, threat_score: float, confidence: float) -> Tuple[str, str]:
        """Advanced threat level determination with confidence weighting"""
        # Confidence-adjusted threat score
        confidence_weight = 0.8 + confidence * 0.4  # Scale from 0.8 to 1.2
        adjusted_score = threat_score * confidence_weight
        
        # Primary classification
        primary_level = "LOW"
        for level, thresholds in sorted(self.threat_thresholds.items(), 
                                       key=lambda x: x[1]['score'], reverse=True):
            if adjusted_score >= thresholds['score']:
                primary_level = level
                break
        
        # Confidence level classification
        if confidence >= 0.85:
            confidence_level = "VERY_HIGH"
        elif confidence >= 0.7:
            confidence_level = "HIGH"  
        elif confidence >= 0.5:
            confidence_level = "MEDIUM"
        elif confidence >= 0.3:
            confidence_level = "LOW"
        else:
            confidence_level = "VERY_LOW"
        
        # Final adjustments based on confidence
        if confidence < 0.3 and primary_level in ["CRITICAL", "HIGH"]:
            primary_level = "MEDIUM"
        elif confidence >= 0.85 and primary_level in ["MEDIUM", "LOW-MEDIUM"]:
            if threat_score >= 0.4:
                primary_level = "MEDIUM-HIGH"
        
        return primary_level, confidence_level
    
    # ... keep existing code (helper methods for extracting host keys, timestamps, etc.)
    
    def _extract_host_key(self, detection: Dict) -> Optional[str]:
        """Extract host key from detection"""
        if 'session_data' in detection:
            session = detection['session_data']
            return f"{session.get('src_ip', '')}->{session.get('dst_ip', '')}"
        elif 'host_key' in detection:
            return detection['host_key']
        elif 'src_ip' in detection and 'dst_ip' in detection:
            return f"{detection['src_ip']}->{detection['dst_ip']}"
        return None
    
    def _extract_timestamp(self, detection: Dict) -> str:
        """Extract timestamp from detection"""
        return detection.get('timestamp', datetime.now().isoformat())
    
    def _calculate_time_diff(self, time1: str, time2: str) -> float:
        """Calculate time difference in seconds"""
        try:
            if isinstance(time1, str) and isinstance(time2, str):
                dt1 = datetime.fromisoformat(time1.replace('Z', '+00:00'))
                dt2 = datetime.fromisoformat(time2.replace('Z', '+00:00'))
                return abs((dt1 - dt2).total_seconds())
        except:
            pass
        return 0.0
