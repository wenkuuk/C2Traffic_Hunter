
#!/usr/bin/env python3
"""
Enhanced C2 Traffic Threat Detection System
Advanced threat assessment with multi-layered analysis and adaptive scoring
"""

import math
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import statistics


class ThreatLevel(Enum):
    """Threat level enumeration for better type safety"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM_HIGH = "MEDIUM-HIGH"
    MEDIUM = "MEDIUM"
    LOW_MEDIUM = "LOW-MEDIUM"
    LOW = "LOW"


class ConfidenceLevel(Enum):
    """Confidence level enumeration"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW_MEDIUM = "LOW-MEDIUM"
    LOW = "LOW"


@dataclass
class DetectionResult:
    """Structured detection result with metadata"""
    detection_type: str
    confidence: float
    severity: int
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlated_detections: int = 0
    correlation_types: List[str] = field(default_factory=list)


@dataclass
class ThreatAssessment:
    """Comprehensive threat assessment result"""
    threat_score: float
    threat_level: ThreatLevel
    confidence_score: float
    confidence_level: ConfidenceLevel
    component_scores: Dict[str, float]
    detection_breakdown: Dict[str, int]
    risk_factors: Dict[str, bool]
    correlation_bonus: float
    total_detections: int
    assessment_metadata: Dict[str, Any]


class ThreatWeightingConfig:
    """Configuration for threat scoring weights and thresholds"""
    
    THREAT_WEIGHTS = {
        'signature_detections': {'base': 0.45, 'max_weight': 0.6},
        'ml_classifications': {'base': 0.35, 'max_weight': 0.5},
        'beaconing_patterns': {'base': 0.15, 'max_weight': 0.3},
        'behavioral_anomalies': {'base': 0.05, 'max_weight': 0.2}
    }
    
    THREAT_THRESHOLDS = {
        ThreatLevel.CRITICAL: {'score': 0.8, 'confidence': 0.7},
        ThreatLevel.HIGH: {'score': 0.6, 'confidence': 0.6},
        ThreatLevel.MEDIUM_HIGH: {'score': 0.4, 'confidence': 0.5},
        ThreatLevel.MEDIUM: {'score': 0.25, 'confidence': 0.4},
        ThreatLevel.LOW_MEDIUM: {'score': 0.15, 'confidence': 0.3},
        ThreatLevel.LOW: {'score': 0.0, 'confidence': 0.0}
    }
    
    CONFIDENCE_THRESHOLDS = {
        ConfidenceLevel.HIGH: 0.8,
        ConfidenceLevel.MEDIUM: 0.6,
        ConfidenceLevel.LOW_MEDIUM: 0.4,
        ConfidenceLevel.LOW: 0.0
    }


class ConfidenceCalculator:
    """Handles confidence scoring calculations"""
    
    @staticmethod
    def calculate_enhanced_confidence(detection: DetectionResult) -> float:
        """Calculate enhanced confidence score with multiple factors"""
        base_confidence = 0.5
        
        # Detection type confidence
        type_confidence = ConfidenceCalculator._get_type_confidence(detection)
        base_confidence += type_confidence
        
        # Temporal recency factor
        recency_factor = ConfidenceCalculator._calculate_recency_factor(detection.timestamp)
        base_confidence *= recency_factor
        
        # Frequency amplification
        frequency_factor = ConfidenceCalculator._calculate_frequency_factor(
            detection.metadata.get('frequency', 1)
        )
        base_confidence *= frequency_factor
        
        # Correlation factor
        correlation_factor = ConfidenceCalculator._calculate_correlation_factor(detection)
        base_confidence *= correlation_factor
        
        # Severity factor
        severity_factor = 0.8 + (detection.severity / 10) * 0.4
        base_confidence *= severity_factor
        
        # Source reliability factor
        source_reliability = detection.metadata.get('source_reliability', 0.8)
        base_confidence *= source_reliability
        
        return min(1.0, max(0.1, base_confidence))
    
    @staticmethod
    def _get_type_confidence(detection: DetectionResult) -> float:
        """Get confidence boost based on detection type"""
        type_confidence_map = {
            'signature': 0.3,
            'ml': lambda d: d.metadata.get('ml_confidence', 0.2) * 0.4,
            'behavioral': 0.25,
            'beaconing': 0.2
        }
        
        confidence_boost = type_confidence_map.get(detection.detection_type, 0.1)
        if callable(confidence_boost):
            return confidence_boost(detection)
        return confidence_boost
    
    @staticmethod
    def _calculate_recency_factor(timestamp: datetime) -> float:
        """Calculate recency factor based on detection age"""
        now = datetime.now()
        age_hours = (now - timestamp).total_seconds() / 3600
        
        if age_hours <= 1:
            return 1.0
        elif age_hours <= 24:
            return 1 - (age_hours - 1) / 23 * 0.3
        else:
            return max(0.2, 1 - age_hours / 168 * 0.5)
    
    @staticmethod
    def _calculate_frequency_factor(frequency: int) -> float:
        """Calculate frequency amplification factor"""
        if frequency <= 1:
            return 1.0
        return min(1.8, 1 + math.log(frequency) * 0.2)
    
    @staticmethod
    def _calculate_correlation_factor(detection: DetectionResult) -> float:
        """Calculate correlation factor based on correlated detections"""
        if detection.correlated_detections == 0:
            return 1.0
        
        # Diversity bonus for different correlation types
        correlation_diversity = len(set(detection.correlation_types)) / 4.0
        correlation_multiplier = 1 + (detection.correlated_detections * 0.15 + 
                                    correlation_diversity * 0.2)
        return min(2.0, correlation_multiplier)


class PatternAnalyzer:
    """Analyzes patterns in network traffic for threat detection"""
    
    @staticmethod
    def calculate_beaconing_strength(pattern: Dict[str, Any]) -> float:
        """Calculate beaconing pattern strength based on timing consistency"""
        timestamps = pattern.get('timestamps', [])
        if len(timestamps) < 3:
            return 0.5
        
        # Calculate statistical properties of intervals
        intervals = PatternAnalyzer._calculate_intervals(timestamps)
        if not intervals:
            return 0.5
        
        regularity_score = PatternAnalyzer._calculate_regularity_score(intervals)
        duration_factor = PatternAnalyzer._calculate_duration_factor(
            pattern.get('duration_hours', 1)
        )
        frequency_factor = PatternAnalyzer._calculate_frequency_factor(
            pattern.get('frequency_per_hour', 1)
        )
        
        strength = regularity_score * duration_factor * frequency_factor
        return min(1.0, max(0.3, strength))
    
    @staticmethod
    def _calculate_intervals(timestamps: List[float]) -> List[float]:
        """Calculate time intervals between timestamps"""
        return [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    
    @staticmethod
    def _calculate_regularity_score(intervals: List[float]) -> float:
        """Calculate regularity score based on interval consistency"""
        if not intervals:
            return 0.5
        
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return 0.3
        
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = std_dev / mean_interval if mean_interval > 0 else 1
        
        # Lower coefficient of variation indicates more regular intervals
        return max(0.3, 1 - cv)
    
    @staticmethod
    def _calculate_duration_factor(duration_hours: float) -> float:
        """Calculate duration factor (longer beaconing = higher threat)"""
        return min(1.5, 1 + math.log(max(1, duration_hours)) * 0.1)
    
    @staticmethod
    def _calculate_frequency_factor(frequency_per_hour: float) -> float:
        """Calculate frequency factor"""
        return min(1.3, 1 + math.log(max(1, frequency_per_hour)) * 0.05)


class AnomalyAnalyzer:
    """Analyzes behavioral anomalies in network traffic"""
    
    @staticmethod
    def calculate_anomaly_strength(anomaly: Dict[str, Any]) -> float:
        """Calculate behavioral anomaly strength"""
        baseline = anomaly.get('baseline', 0)
        current = anomaly.get('current', 0)
        
        if baseline == 0:
            return 0.7 if current > 0 else 0.3
        
        # Calculate statistical significance
        z_score = anomaly.get('z_score', abs(current - baseline) / baseline)
        strength = AnomalyAnalyzer._z_score_to_strength(z_score)
        
        # Apply persistence factor
        persistence_hours = anomaly.get('persistence_hours', 1)
        persistence_factor = min(1.4, 1 + math.log(max(1, persistence_hours)) * 0.1)
        
        return min(1.0, strength * persistence_factor)
    
    @staticmethod
    def _z_score_to_strength(z_score: float) -> float:
        """Convert z-score to strength score"""
        if z_score >= 3:
            return 0.9
        elif z_score >= 2:
            return 0.7
        elif z_score >= 1:
            return 0.5
        else:
            return max(0.2, z_score / 2)


class RiskAssessment:
    """Assesses various risk factors from detection results"""
    
    @staticmethod
    def assess_risk_factors(results: Dict[str, List], 
                          detection_details: Dict[str, Dict]) -> Dict[str, bool]:
        """Assess additional risk factors from detection patterns"""
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
        beacon_count = detection_details.get('beaconing', {}).get('count', 0)
        behavioral_count = detection_details.get('behavioral', {}).get('count', 0)
        risk_factors['persistence'] = beacon_count > 0 or behavioral_count >= 2
        
        # Command and control indicators
        risk_factors['command_control'] = beacon_count > 0
        
        # Data exfiltration indicators
        sig_count = detection_details.get('signature', {}).get('count', 0)
        ml_count = detection_details.get('ml', {}).get('count', 0)
        risk_factors['data_exfiltration'] = sig_count >= 3 or ml_count >= 2
        
        # Advanced threat indicators
        risk_factors['steganography'] = RiskAssessment._check_steganography_indicators(results)
        risk_factors['dns_tunneling'] = RiskAssessment._check_dns_tunneling_indicators(results)
        risk_factors['lateral_movement'] = RiskAssessment._check_lateral_movement_indicators(results)
        
        return risk_factors
    
    @staticmethod
    def _check_steganography_indicators(results: Dict[str, List]) -> bool:
        """Check for steganography indicators in traffic patterns"""
        # Look for unusual payload sizes or patterns
        ml_detections = results.get('ml_classifications', [])
        for detection in ml_detections:
            if detection.get('category') == 'steganography':
                return True
        return False
    
    @staticmethod
    def _check_dns_tunneling_indicators(results: Dict[str, List]) -> bool:
        """Check for DNS tunneling indicators"""
        sig_detections = results.get('signature_detections', [])
        for detection in sig_detections:
            if 'dns_tunnel' in detection.get('signature_name', '').lower():
                return True
        return False
    
    @staticmethod
    def _check_lateral_movement_indicators(results: Dict[str, List]) -> bool:
        """Check for lateral movement indicators"""
        behavioral_anomalies = results.get('behavioral_anomalies', [])
        for anomaly in behavioral_anomalies:
            if anomaly.get('anomaly_type') == 'lateral_movement':
                return True
        return False


class EnhancedThreatAssessor:
    """Main threat assessment engine with enhanced capabilities"""
    
    def __init__(self, config: Optional[ThreatWeightingConfig] = None):
        self.config = config or ThreatWeightingConfig()
        self.confidence_calculator = ConfidenceCalculator()
        self.pattern_analyzer = PatternAnalyzer()
        self.anomaly_analyzer = AnomalyAnalyzer()
        self.risk_assessment = RiskAssessment()
        self.logger = logging.getLogger(__name__)
    
    def generate_threat_assessment(self, results: Dict[str, List]) -> Dict[str, Any]:
        """Generate comprehensive threat assessment with enhanced scoring"""
        try:
            # Process all detection types
            component_scores = {}
            confidence_scores = {}
            detection_details = {}
            
            # Process each detection type
            self._process_signature_detections(results, component_scores, 
                                             confidence_scores, detection_details)
            self._process_ml_classifications(results, component_scores, 
                                           confidence_scores, detection_details)
            self._process_beaconing_patterns(results, component_scores, 
                                           confidence_scores, detection_details)
            self._process_behavioral_anomalies(results, component_scores, 
                                              confidence_scores, detection_details)
            
            # Calculate composite scores
            raw_threat_score = sum(component_scores.values())
            overall_confidence = self._calculate_overall_confidence(confidence_scores)
            
            # Calculate correlation bonus
            active_detection_types = sum(1 for score in component_scores.values() if score > 0)
            correlation_bonus = self._calculate_correlation_bonus(active_detection_types, results)
            
            # Finalize threat score
            final_threat_score = min(1.0, raw_threat_score + correlation_bonus)
            
            # Determine threat and confidence levels
            threat_level, confidence_level = self._determine_levels(
                final_threat_score, overall_confidence
            )
            
            # Assess risk factors
            risk_factors = self.risk_assessment.assess_risk_factors(results, detection_details)
            
            # Create assessment result (converted to dict for JSON serialization)
            return {
                'threat_score': final_threat_score,
                'threat_level': threat_level.value,
                'confidence_score': overall_confidence,
                'confidence_level': confidence_level.value,
                'component_scores': component_scores,
                'detection_breakdown': self._create_detection_breakdown(results),
                'risk_factors': risk_factors,
                'correlation_bonus': correlation_bonus,
                'total_detections': self._count_total_detections(results),
                'assessment_metadata': {
                    'active_detection_types': active_detection_types,
                    'timestamp': datetime.now().isoformat(),
                    'analysis_version': '3.0',
                    'detection_details': detection_details
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in threat assessment: {e}")
            raise
    
    def _process_signature_detections(self, results: Dict[str, List], 
                                    component_scores: Dict[str, float],
                                    confidence_scores: Dict[str, float],
                                    detection_details: Dict[str, Dict]) -> None:
        """Process signature-based detections"""
        sig_detections = results.get('signature_detections', [])
        if not sig_detections:
            component_scores['signature'] = 0
            confidence_scores['signature'] = 0
            detection_details['signature'] = {'count': 0}
            return
        
        confidences = []
        for detection_data in sig_detections:
            detection = DetectionResult(
                detection_type='signature',
                confidence=0.0,  # Will be calculated
                severity=detection_data.get('signature_score', 5),
                timestamp=datetime.now(),
                metadata={
                    'frequency': 1,
                    'source_reliability': 0.9
                }
            )
            confidence = self.confidence_calculator.calculate_enhanced_confidence(detection)
            confidences.append(confidence)
        
        component_scores['signature'] = (max(confidences) * 
                                       self.config.THREAT_WEIGHTS['signature_detections']['base'])
        confidence_scores['signature'] = statistics.mean(confidences)
        detection_details['signature'] = {
            'count': len(sig_detections),
            'max_confidence': max(confidences),
            'avg_confidence': statistics.mean(confidences),
            'high_confidence_count': sum(1 for c in confidences if c > 0.7)
        }
    
    def _process_ml_classifications(self, results: Dict[str, List], 
                                  component_scores: Dict[str, float],
                                  confidence_scores: Dict[str, float],
                                  detection_details: Dict[str, Dict]) -> None:
        """Process ML-based classifications"""
        ml_detections = results.get('ml_classifications', [])
        if not ml_detections:
            component_scores['ml'] = 0
            confidence_scores['ml'] = 0
            detection_details['ml'] = {'count': 0}
            return
        
        ml_confidences = []
        for detection_data in ml_detections:
            ml_score = detection_data.get('ml_score', 0.5)
            detection = DetectionResult(
                detection_type='ml',
                confidence=ml_score,
                severity=int(ml_score * 10),
                timestamp=datetime.now(),
                metadata={
                    'ml_confidence': ml_score,
                    'frequency': 1,
                    'source_reliability': 0.8
                }
            )
            enhanced_confidence = self.confidence_calculator.calculate_enhanced_confidence(detection)
            combined_confidence = (enhanced_confidence + ml_score) / 2
            ml_confidences.append(combined_confidence)
        
        component_scores['ml'] = (max(ml_confidences) * 
                                self.config.THREAT_WEIGHTS['ml_classifications']['base'])
        confidence_scores['ml'] = statistics.mean(ml_confidences)
        detection_details['ml'] = {
            'count': len(ml_detections),
            'max_confidence': max(ml_confidences),
            'avg_confidence': statistics.mean(ml_confidences)
        }
    
    def _process_beaconing_patterns(self, results: Dict[str, List], 
                                  component_scores: Dict[str, float],
                                  confidence_scores: Dict[str, float],
                                  detection_details: Dict[str, Dict]) -> None:
        """Process beaconing pattern detections"""
        beacon_patterns = results.get('beaconing_patterns', [])
        if not beacon_patterns:
            component_scores['beaconing'] = 0
            confidence_scores['beaconing'] = 0
            detection_details['beaconing'] = {'count': 0}
            return
        
        beacon_strengths = []
        for pattern in beacon_patterns:
            if 'strength' not in pattern:
                pattern['strength'] = self.pattern_analyzer.calculate_beaconing_strength(pattern)
            beacon_strengths.append(pattern['strength'])
        
        component_scores['beaconing'] = (max(beacon_strengths) * 
                                       self.config.THREAT_WEIGHTS['beaconing_patterns']['base'])
        confidence_scores['beaconing'] = statistics.mean(beacon_strengths)
        detection_details['beaconing'] = {
            'count': len(beacon_patterns),
            'max_strength': max(beacon_strengths),
            'avg_strength': statistics.mean(beacon_strengths)
        }
    
    def _process_behavioral_anomalies(self, results: Dict[str, List], 
                                    component_scores: Dict[str, float],
                                    confidence_scores: Dict[str, float],
                                    detection_details: Dict[str, Dict]) -> None:
        """Process behavioral anomaly detections"""
        behavioral_anomalies = results.get('behavioral_anomalies', [])
        if not behavioral_anomalies:
            component_scores['behavioral'] = 0
            confidence_scores['behavioral'] = 0
            detection_details['behavioral'] = {'count': 0}
            return
        
        anomaly_strengths = []
        for anomaly in behavioral_anomalies:
            if 'anomaly_score' not in anomaly:
                anomaly['anomaly_score'] = self.anomaly_analyzer.calculate_anomaly_strength(anomaly)
            anomaly_strengths.append(anomaly['anomaly_score'])
        
        component_scores['behavioral'] = (max(anomaly_strengths) * 
                                        self.config.THREAT_WEIGHTS['behavioral_anomalies']['base'])
        confidence_scores['behavioral'] = statistics.mean(anomaly_strengths)
        detection_details['behavioral'] = {
            'count': len(behavioral_anomalies),
            'max_strength': max(anomaly_strengths),
            'avg_strength': statistics.mean(anomaly_strengths)
        }
    
    def _calculate_overall_confidence(self, confidence_scores: Dict[str, float]) -> float:
        """Calculate overall confidence score"""
        active_confidences = [score for score in confidence_scores.values() if score > 0]
        return statistics.mean(active_confidences) if active_confidences else 0.0
    
    def _calculate_correlation_bonus(self, active_types: int, results: Dict) -> float:
        """Calculate correlation bonus with enhanced logic"""
        if active_types <= 1:
            return 0.0
        
        base_bonus = {2: 0.05, 3: 0.12, 4: 0.20}.get(active_types, 0.20)
        
        # Additional bonus for high-confidence detections
        total_detections = self._count_total_detections(results)
        high_conf_bonus = min(0.08, total_detections * 0.01) if total_detections >= 5 else 0.0
        
        return base_bonus + high_conf_bonus
    
    def _determine_levels(self, threat_score: float, confidence: float) -> Tuple[ThreatLevel, ConfidenceLevel]:
        """Determine threat and confidence levels"""
        # Determine primary threat level
        threat_level = ThreatLevel.LOW
        for level, thresholds in sorted(self.config.THREAT_THRESHOLDS.items(), 
                                       key=lambda x: x[1]['score'], reverse=True):
            if threat_score >= thresholds['score']:
                threat_level = level
                break
        
        # Determine confidence level
        confidence_level = ConfidenceLevel.LOW
        for level, threshold in sorted(self.config.CONFIDENCE_THRESHOLDS.items(), 
                                     key=lambda x: x[1], reverse=True):
            if confidence >= threshold:
                confidence_level = level
                break
        
        # Adjust threat level based on confidence
        if confidence < 0.4 and threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            threat_level = ThreatLevel.MEDIUM_HIGH
        elif confidence >= 0.8 and threat_level == ThreatLevel.MEDIUM:
            threat_level = ThreatLevel.MEDIUM_HIGH
        
        return threat_level, confidence_level
    
    def _create_detection_breakdown(self, results: Dict[str, List]) -> Dict[str, int]:
        """Create detection breakdown summary"""
        return {
            'signature_detections': len(results.get('signature_detections', [])),
            'ml_classifications': len(results.get('ml_classifications', [])),
            'beaconing_patterns': len(results.get('beaconing_patterns', [])),
            'behavioral_anomalies': len(results.get('behavioral_anomalies', []))
        }
    
    def _count_total_detections(self, results: Dict[str, List]) -> int:
        """Count total detections across all types"""
        return sum(len(results.get(key, [])) for key in 
                  ['signature_detections', 'ml_classifications', 
                   'beaconing_patterns', 'behavioral_anomalies'])
