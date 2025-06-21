
#!/usr/bin/env python3
"""
Enhanced Threat Assessment Engine with Improved Detection Accuracy
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


class PatternAnalyzer:
    """Advanced pattern analysis for beaconing and behavioral detection"""
    
    def __init__(self):
        self.beacon_thresholds = {
            'min_intervals': 3,
            'regularity_threshold': 0.7,
            'jitter_tolerance': 0.3
        }
    
    def calculate_beaconing_strength(self, pattern: Dict[str, Any]) -> float:
        """Enhanced beaconing strength calculation with statistical analysis"""
        timestamps = pattern.get('timestamps', [])
        if len(timestamps) < 3:
            return 0.2
        
        # Convert to intervals
        intervals = []
        for i in range(1, len(timestamps)):
            if isinstance(timestamps[i], (int, float)) and isinstance(timestamps[i-1], (int, float)):
                intervals.append(timestamps[i] - timestamps[i-1])
        
        if not intervals:
            return 0.3
        
        # Statistical regularity analysis
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return 0.2
        
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        coefficient_of_variation = std_dev / mean_interval if mean_interval > 0 else 1
        
        # Regularity score (lower CV = more regular = higher score)
        regularity_score = max(0.1, 1 - coefficient_of_variation)
        
        # Frequency analysis
        frequency_per_hour = len(timestamps) / max(1, pattern.get('duration_hours', 1))
        frequency_factor = min(1.5, 1 + math.log(frequency_per_hour + 1) * 0.1)
        
        # Persistence bonus
        duration_hours = pattern.get('duration_hours', 1)
        persistence_factor = min(1.3, 1 + math.log(duration_hours + 1) * 0.05)
        
        # Calculate final strength
        strength = regularity_score * frequency_factor * persistence_factor
        
        # Apply correlation bonus
        correlation_bonus = pattern.get('correlated_detections', 0) * 0.1
        strength += correlation_bonus
        
        return min(0.95, max(0.1, strength))
    
    def analyze_behavioral_patterns(self, sessions: List[Dict]) -> List[Dict]:
        """Enhanced behavioral pattern analysis"""
        patterns = []
        
        if not sessions:
            return patterns
        
        # Group by host
        host_sessions = defaultdict(list)
        for session in sessions:
            host_key = f"{session.get('src_ip', '')}->{session.get('dst_ip', '')}"
            host_sessions[host_key].append(session)
        
        for host_key, host_session_list in host_sessions.items():
            if len(host_session_list) < 2:
                continue
            
            # Analyze timing patterns
            timestamps = [s.get('timestamp', 0) for s in host_session_list]
            timestamps.sort()
            
            # Check for suspicious patterns
            suspicious_indicators = self._detect_suspicious_patterns(host_session_list)
            
            if suspicious_indicators['score'] > 0.3:
                patterns.append({
                    'host_key': host_key,
                    'type': 'behavioral_anomaly',
                    'indicators': suspicious_indicators,
                    'strength': suspicious_indicators['score'],
                    'session_count': len(host_session_list),
                    'timespan_hours': (max(timestamps) - min(timestamps)) / 3600 if timestamps else 0
                })
        
        return patterns
    
    def _detect_suspicious_patterns(self, sessions: List[Dict]) -> Dict:
        """Detect suspicious behavioral patterns"""
        indicators = {
            'score': 0.0,
            'patterns': []
        }
        
        # User agent analysis
        user_agents = [s.get('user_agent', '') for s in sessions if s.get('user_agent')]
        unique_agents = set(user_agents)
        
        if len(unique_agents) == 1 and len(sessions) > 3:
            indicators['score'] += 0.2
            indicators['patterns'].append('consistent_user_agent')
        
        # Request size analysis
        request_sizes = [s.get('request_size', 0) for s in sessions]
        if request_sizes and statistics.stdev(request_sizes) < 50:
            indicators['score'] += 0.15
            indicators['patterns'].append('consistent_request_size')
        
        # Path pattern analysis
        paths = [s.get('path', '') for s in sessions if s.get('path')]
        unique_paths = set(paths)
        
        if len(unique_paths) < len(paths) * 0.3:  # High repetition
            indicators['score'] += 0.25
            indicators['patterns'].append('repetitive_paths')
        
        return indicators


class AnomalyAnalyzer:
    """Advanced anomaly detection and scoring"""
    
    def calculate_anomaly_strength(self, anomaly: Dict[str, Any]) -> float:
        """Enhanced anomaly strength calculation"""
        baseline = anomaly.get('baseline', 0)
        current = anomaly.get('current', 0)
        anomaly_type = anomaly.get('type', 'unknown')
        
        if baseline == 0:
            return 0.6 if current > 0 else 0.2
        
        # Calculate relative deviation
        relative_deviation = abs(current - baseline) / baseline
        
        # Type-specific scoring
        type_multipliers = {
            'frequency_anomaly': 1.2,
            'size_anomaly': 1.0,
            'timing_anomaly': 1.3,
            'behavioral_anomaly': 1.1
        }
        
        multiplier = type_multipliers.get(anomaly_type, 1.0)
        
        # Statistical significance
        z_score = anomaly.get('z_score', relative_deviation)
        
        if z_score >= 3:
            strength = 0.85
        elif z_score >= 2:
            strength = 0.65
        elif z_score >= 1:
            strength = 0.45
        else:
            strength = max(0.15, z_score / 3)
        
        # Apply type multiplier
        strength *= multiplier
        
        # Persistence factor
        persistence_hours = anomaly.get('persistence_hours', 1)
        persistence_factor = min(1.3, 1 + math.log(persistence_hours + 1) * 0.08)
        
        return min(0.9, strength * persistence_factor)


class EnhancedThreatAssessor:
    """Main enhanced threat assessment engine"""
    
    def __init__(self):
        self.pattern_analyzer = PatternAnalyzer()
        self.anomaly_analyzer = AnomalyAnalyzer()
        
        # Enhanced threat weights with better balance
        self.threat_weights = {
            'signature_detections': {'base': 0.4, 'max_contribution': 0.5},
            'ml_classifications': {'base': 0.3, 'max_contribution': 0.4},
            'beaconing_patterns': {'base': 0.2, 'max_contribution': 0.35},
            'behavioral_anomalies': {'base': 0.1, 'max_contribution': 0.25}
        }
        
        # Refined threat thresholds
        self.threat_thresholds = {
            'CRITICAL': {'score': 0.75, 'confidence': 0.7},
            'HIGH': {'score': 0.55, 'confidence': 0.6},
            'MEDIUM-HIGH': {'score': 0.4, 'confidence': 0.5},
            'MEDIUM': {'score': 0.25, 'confidence': 0.4},
            'LOW-MEDIUM': {'score': 0.15, 'confidence': 0.3},
            'LOW': {'score': 0.0, 'confidence': 0.0}
        }
    
    def generate_threat_assessment(self, results: Dict[str, List]) -> Dict[str, Any]:
        """Generate comprehensive threat assessment with improved accuracy"""
        
        # Enhanced correlation analysis
        correlation_data = self._analyze_cross_correlations(results)
        
        # Calculate component scores with improved logic
        component_scores = self._calculate_enhanced_component_scores(results, correlation_data)
        
        # Enhanced confidence calculation
        confidence_metrics = self._calculate_enhanced_confidence(results, correlation_data)
        
        # Risk factor assessment
        risk_factors = self._assess_enhanced_risk_factors(results, component_scores)
        
        # Final threat score with correlation bonus
        raw_threat_score = sum(component_scores.values())
        correlation_bonus = self._calculate_correlation_bonus(results, correlation_data)
        final_threat_score = min(0.95, raw_threat_score + correlation_bonus)
        
        # Determine threat and confidence levels
        threat_level, confidence_level = self._determine_enhanced_threat_level(
            final_threat_score, confidence_metrics['overall_confidence']
        )
        
        return {
            'threat_score': final_threat_score,
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
            'correlation_analysis': correlation_data,
            'confidence_metrics': confidence_metrics
        }
    
    def _analyze_cross_correlations(self, results: Dict) -> DetectionCorrelation:
        """Enhanced cross-correlation analysis"""
        host_correlations = defaultdict(int)
        time_correlations = []
        pattern_correlations = defaultdict(float)
        
        # Analyze host-based correlations
        all_detections = []
        for detection_type, detections in results.items():
            if detection_type.endswith('_detections') or detection_type.endswith('_patterns') or detection_type.endswith('_anomalies'):
                for detection in detections:
                    host_key = self._extract_host_key(detection)
                    if host_key:
                        host_correlations[host_key] += 1
                        all_detections.append({
                            'host': host_key,
                            'type': detection_type,
                            'timestamp': detection.get('timestamp', ''),
                            'detection': detection
                        })
        
        # Time-based correlation analysis
        all_detections.sort(key=lambda x: x.get('timestamp', ''))
        for i, detection in enumerate(all_detections):
            if i > 0:
                prev_detection = all_detections[i-1]
                time_diff = self._calculate_time_diff(detection['timestamp'], prev_detection['timestamp'])
                if time_diff < 300:  # Within 5 minutes
                    time_correlations.append((detection['timestamp'], detection['type']))
        
        # Pattern correlation scoring
        for host, count in host_correlations.items():
            if count > 1:
                pattern_correlations[host] = min(1.0, count * 0.2)
        
        # Cross-detection score
        cross_detection_score = min(1.0, len([h for h, c in host_correlations.items() if c > 1]) * 0.3)
        
        return DetectionCorrelation(
            host_correlations=dict(host_correlations),
            time_correlations=time_correlations,
            pattern_correlations=dict(pattern_correlations),
            cross_detection_score=cross_detection_score
        )
    
    def _calculate_enhanced_component_scores(self, results: Dict, correlation_data: DetectionCorrelation) -> Dict[str, float]:
        """Calculate component scores with enhanced logic"""
        scores = {}
        
        # Signature detections
        sig_detections = results.get('signature_detections', [])
        if sig_detections:
            base_score = min(len(sig_detections) * 0.15, 0.8)
            correlation_boost = correlation_data.cross_detection_score * 0.2
            scores['signature'] = min(self.threat_weights['signature_detections']['max_contribution'], 
                                    base_score + correlation_boost)
        else:
            scores['signature'] = 0.0
        
        # ML classifications
        ml_detections = results.get('ml_classifications', [])
        if ml_detections:
            confidence_scores = [d.get('ml_score', 0.5) for d in ml_detections]
            avg_confidence = statistics.mean(confidence_scores)
            base_score = avg_confidence * 0.4
            correlation_boost = correlation_data.cross_detection_score * 0.15
            scores['ml'] = min(self.threat_weights['ml_classifications']['max_contribution'],
                             base_score + correlation_boost)
        else:
            scores['ml'] = 0.0
        
        # Beaconing patterns
        beacon_patterns = results.get('beaconing_patterns', [])
        if beacon_patterns:
            pattern_strengths = []
            for pattern in beacon_patterns:
                strength = self.pattern_analyzer.calculate_beaconing_strength(pattern)
                pattern_strengths.append(strength)
            
            max_strength = max(pattern_strengths) if pattern_strengths else 0.5
            base_score = max_strength * 0.25
            scores['beaconing'] = min(self.threat_weights['beaconing_patterns']['max_contribution'],
                                   base_score)
        else:
            scores['beaconing'] = 0.0
        
        # Behavioral anomalies
        behavioral_anomalies = results.get('behavioral_anomalies', [])
        if behavioral_anomalies:
            anomaly_strengths = []
            for anomaly in behavioral_anomalies:
                strength = self.anomaly_analyzer.calculate_anomaly_strength(anomaly)
                anomaly_strengths.append(strength)
            
            max_strength = max(anomaly_strengths) if anomaly_strengths else 0.4
            base_score = max_strength * 0.2
            scores['behavioral'] = min(self.threat_weights['behavioral_anomalies']['max_contribution'],
                                     base_score)
        else:
            scores['behavioral'] = 0.0
        
        return scores
    
    def _calculate_enhanced_confidence(self, results: Dict, correlation_data: DetectionCorrelation) -> Dict[str, float]:
        """Enhanced confidence calculation"""
        confidences = []
        
        # Base confidence from detection quality
        detection_types = ['signature_detections', 'ml_classifications', 'beaconing_patterns', 'behavioral_anomalies']
        active_types = sum(1 for dt in detection_types if len(results.get(dt, [])) > 0)
        
        base_confidence = 0.3 + (active_types * 0.15)
        
        # Correlation confidence boost
        correlation_confidence = correlation_data.cross_detection_score * 0.3
        
        # Detection count confidence
        total_detections = sum(len(results.get(dt, [])) for dt in detection_types)
        count_confidence = min(0.3, total_detections * 0.05)
        
        overall_confidence = min(0.9, base_confidence + correlation_confidence + count_confidence)
        
        return {
            'overall_confidence': overall_confidence,
            'base_confidence': base_confidence,
            'correlation_confidence': correlation_confidence,
            'count_confidence': count_confidence
        }
    
    def _assess_enhanced_risk_factors(self, results: Dict, component_scores: Dict) -> Dict[str, bool]:
        """Enhanced risk factor assessment"""
        risk_factors = {
            'persistence': False,
            'lateral_movement': False,
            'data_exfiltration': False,
            'command_control': False,
            'privilege_escalation': False,
            'steganography': False,
            'dns_tunneling': False
        }
        
        # Persistence indicators
        if component_scores.get('beaconing', 0) > 0.2 or len(results.get('behavioral_anomalies', [])) >= 2:
            risk_factors['persistence'] = True
        
        # Command and control
        if component_scores.get('beaconing', 0) > 0.15 or component_scores.get('signature', 0) > 0.3:
            risk_factors['command_control'] = True
        
        # Data exfiltration
        if component_scores.get('signature', 0) > 0.25 or component_scores.get('ml', 0) > 0.2:
            risk_factors['data_exfiltration'] = True
        
        # Steganography detection
        if component_scores.get('ml', 0) > 0.3:
            risk_factors['steganography'] = True
        
        # DNS tunneling
        if len(results.get('signature_detections', [])) > 2:
            risk_factors['dns_tunneling'] = True
        
        return risk_factors
    
    def _calculate_correlation_bonus(self, results: Dict, correlation_data: DetectionCorrelation) -> float:
        """Calculate correlation bonus with enhanced logic"""
        base_bonus = correlation_data.cross_detection_score * 0.15
        
        # Time correlation bonus
        time_bonus = min(0.1, len(correlation_data.time_correlations) * 0.02)
        
        # Host correlation bonus
        multi_host_bonus = min(0.08, len([h for h, c in correlation_data.host_correlations.items() if c > 1]) * 0.02)
        
        return base_bonus + time_bonus + multi_host_bonus
    
    def _determine_enhanced_threat_level(self, threat_score: float, confidence: float) -> Tuple[str, str]:
        """Enhanced threat level determination"""
        # Primary classification
        primary_level = "LOW"
        for level, thresholds in sorted(self.threat_thresholds.items(), 
                                       key=lambda x: x[1]['score'], reverse=True):
            if threat_score >= thresholds['score']:
                primary_level = level
                break
        
        # Confidence classification
        if confidence >= 0.8:
            confidence_level = "HIGH"
        elif confidence >= 0.6:
            confidence_level = "MEDIUM"
        elif confidence >= 0.4:
            confidence_level = "LOW-MEDIUM"
        else:
            confidence_level = "LOW"
        
        # Adjust based on confidence
        if confidence < 0.4 and primary_level in ["CRITICAL", "HIGH"]:
            primary_level = "MEDIUM-HIGH"
        elif confidence >= 0.8 and primary_level == "MEDIUM":
            primary_level = "MEDIUM-HIGH"
        
        return primary_level, confidence_level
    
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
