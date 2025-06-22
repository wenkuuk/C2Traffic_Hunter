#!/usr/bin/env python3
"""
Enhanced Threat Assessment Engine with Remediation Integration
"""

import logging
import statistics
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
import json

# Import remediation engine
from .threat_remediation import ThreatRemediationEngine, RemediationReport

logger = logging.getLogger(__name__)

@dataclass
class EnhancedThreatAssessment:
    """Enhanced threat assessment with remediation planning"""
    threat_score: float
    threat_level: str
    confidence_score: float
    confidence_level: str
    component_scores: Dict[str, float]
    detection_breakdown: Dict[str, int]
    risk_factors: Dict[str, bool]
    correlation_analysis: Dict[str, Any]
    remediation_report: Optional[Dict[str, Any]]
    assessment_confidence: float
    correlation_bonus: float
    total_detections: int

class EnhancedThreatAssessor:
    """Enhanced threat assessment with correlation analysis and remediation"""
    
    def __init__(self):
        self.remediation_engine = ThreatRemediationEngine()
        
        # Enhanced correlation weights - correlation is crucial for accuracy
        self.correlation_weights = {
            'signature_ml': 0.25,      # Signature + ML agreement = high confidence
            'beaconing_behavioral': 0.22,  # Pattern + behavior = strong indicator
            'signature_beaconing': 0.20,   # Known malware + beaconing = C2
            'ml_behavioral': 0.18,     # ML + behavior = sophisticated detection
            'cross_temporal': 0.15,    # Same threat across time = persistence
        }
        
        # Enhanced threat level thresholds with correlation consideration
        self.threat_thresholds = {
            'CRITICAL': 0.85,
            'HIGH': 0.70,
            'MEDIUM-HIGH': 0.55,
            'MEDIUM': 0.40,
            'LOW-MEDIUM': 0.25,
            'LOW': 0.0
        }
    
    def assess_threat(self, analysis_results: Dict[str, Any], 
                     confidence_metrics: Optional[Dict] = None) -> EnhancedThreatAssessment:
        """Enhanced threat assessment with correlation and remediation"""
        
        # Extract detection data
        detections = {
            'signature_detections': len(analysis_results.get('signature_detections', [])),
            'ml_classifications': len(analysis_results.get('ml_classifications', [])),
            'beaconing_patterns': len(analysis_results.get('beaconing_patterns', [])),
            'behavioral_anomalies': len(analysis_results.get('behavioral_anomalies', []))
        }
        
        total_detections = sum(detections.values())
        
        # Calculate component scores with enhanced algorithms
        component_scores = self._calculate_enhanced_component_scores(analysis_results)
        
        # Analyze correlations - this is critical for accuracy
        correlation_analysis = self._analyze_correlations(analysis_results, detections)
        correlation_bonus = correlation_analysis['correlation_bonus']
        
        # Calculate base threat score
        base_threat_score = self._calculate_base_threat_score(component_scores, detections)
        
        # Apply correlation bonus - crucial for reducing false positives
        threat_score = min(0.95, base_threat_score + correlation_bonus)
        
        # Determine threat level with correlation consideration
        threat_level = self._determine_threat_level(threat_score, correlation_analysis)
        
        # Calculate assessment confidence (how sure we are of this assessment)
        assessment_confidence = self._calculate_assessment_confidence(
            detections, correlation_analysis, confidence_metrics
        )
        
        # Determine overall confidence level
        confidence_level = self._map_confidence_level(assessment_confidence)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(analysis_results)
        
        # Generate remediation report if threat is significant
        remediation_report = None
        if threat_score >= 0.3:  # Generate remediation for medium+ threats
            remediation_data = {
                'threat_level': threat_level,
                'threat_score': threat_score,
                'confidence_score': assessment_confidence,
                'risk_factors': risk_factors,
                'detection_breakdown': detections
            }
            remediation_report = self._generate_remediation_report(remediation_data)
        
        return EnhancedThreatAssessment(
            threat_score=threat_score,
            threat_level=threat_level,
            confidence_score=assessment_confidence,
            confidence_level=confidence_level,
            component_scores=component_scores,
            detection_breakdown=detections,
            risk_factors=risk_factors,
            correlation_analysis=correlation_analysis,
            remediation_report=remediation_report,
            assessment_confidence=assessment_confidence,
            correlation_bonus=correlation_bonus,
            total_detections=total_detections
        )
    
    def _analyze_correlations(self, analysis_results: Dict[str, Any], 
                            detections: Dict[str, int]) -> Dict[str, Any]:
        """
        Enhanced correlation analysis - WHY CORRELATION MATTERS:
        
        Correlation bonus is essential because:
        1. Reduces false positives - multiple detection types agreeing = higher confidence
        2. Detects sophisticated attacks - advanced malware often triggers multiple detection types
        3. Temporal correlation - persistent threats show patterns over time
        4. Cross-validation - different detection methods validate each other
        """
        
        active_detection_types = [k for k, v in detections.items() if v > 0]
        correlation_strength = 0.0
        correlation_details = {}
        
        # Multi-method correlation (most important)
        if len(active_detection_types) >= 2:
            # Signature + ML correlation (very strong indicator)
            if detections['signature_detections'] > 0 and detections['ml_classifications'] > 0:
                correlation_strength += self.correlation_weights['signature_ml']
                correlation_details['signature_ml'] = True
            
            # Beaconing + Behavioral correlation (pattern + anomaly = C2)
            if detections['beaconing_patterns'] > 0 and detections['behavioral_anomalies'] > 0:
                correlation_strength += self.correlation_weights['beaconing_behavioral']
                correlation_details['beaconing_behavioral'] = True
            
            # Signature + Beaconing (known malware + communication pattern)
            if detections['signature_detections'] > 0 and detections['beaconing_patterns'] > 0:
                correlation_strength += self.correlation_weights['signature_beaconing']
                correlation_details['signature_beaconing'] = True
            
            # ML + Behavioral (sophisticated detection)
            if detections['ml_classifications'] > 0 and detections['behavioral_anomalies'] > 0:
                correlation_strength += self.correlation_weights['ml_behavioral']
                correlation_details['ml_behavioral'] = True
        
        # Temporal correlation analysis
        temporal_patterns = self._analyze_temporal_correlations(analysis_results)
        if temporal_patterns['has_temporal_correlation']:
            correlation_strength += self.correlation_weights['cross_temporal']
            correlation_details['temporal'] = temporal_patterns
        
        # Host-based correlation
        host_correlation = self._analyze_host_correlations(analysis_results)
        if host_correlation['multi_host_activity']:
            correlation_strength += 0.1  # Bonus for multi-host correlation
            correlation_details['host_correlation'] = host_correlation
        
        return {
            'correlation_bonus': min(0.3, correlation_strength),  # Cap at 30% bonus
            'correlation_strength': correlation_strength,
            'correlation_details': correlation_details,
            'active_detection_types': len(active_detection_types),
            'correlation_confidence': min(1.0, correlation_strength / 0.5)
        }
    
    def _analyze_temporal_correlations(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal patterns in detections"""
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        
        has_correlation = False
        persistence_score = 0.0
        
        if beaconing_patterns:
            # Check for long-duration patterns
            durations = [p.get('duration', 0) for p in beaconing_patterns]
            avg_duration = statistics.mean(durations) if durations else 0
            
            if avg_duration > 3600:  # More than 1 hour
                has_correlation = True
                persistence_score = min(1.0, avg_duration / 86400)  # Normalize by day
        
        return {
            'has_temporal_correlation': has_correlation,
            'persistence_score': persistence_score,
            'pattern_duration': avg_duration if 'avg_duration' in locals() else 0
        }
    
    def _analyze_host_correlations(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze correlations across different hosts"""
        suspicious_hosts = analysis_results.get('suspicious_hosts', [])
        unique_hosts = len(set(host.get('host', '') for host in suspicious_hosts))
        
        return {
            'multi_host_activity': unique_hosts > 1,
            'unique_host_count': unique_hosts,
            'lateral_movement_indicator': unique_hosts > 2
        }
    
    def _calculate_enhanced_component_scores(self, analysis_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate enhanced component scores with quality weighting"""
        scores = {}
        
        # Signature score - based on quality and quantity
        signature_detections = analysis_results.get('signature_detections', [])
        if signature_detections:
            # Quality-weighted signature score
            signature_scores = [det.get('signature_score', 0.5) for det in signature_detections]
            avg_signature_quality = statistics.mean(signature_scores)
            signature_count_factor = min(1.0, len(signature_detections) / 5)
            scores['signature'] = avg_signature_quality * (0.6 + signature_count_factor * 0.4)
        else:
            scores['signature'] = 0.0
        
        # ML score - based on confidence and model reliability
        ml_classifications = analysis_results.get('ml_classifications', [])
        if ml_classifications:
            ml_scores = [cls.get('ml_score', 0.5) for cls in ml_classifications]
            avg_ml_score = statistics.mean(ml_scores)
            model_confidence = statistics.mean([cls.get('confidence', 0.8) for cls in ml_classifications])
            scores['ml'] = avg_ml_score * model_confidence
        else:
            scores['ml'] = 0.0
        
        # Beaconing score - based on pattern strength and consistency
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        if beaconing_patterns:
            pattern_strengths = [p.get('confidence', 0.5) for p in beaconing_patterns]
            regularity_scores = [1 - p.get('coefficient_of_variation', 0.5) for p in beaconing_patterns]
            avg_strength = statistics.mean(pattern_strengths + regularity_scores)
            scores['beaconing'] = avg_strength
        else:
            scores['beaconing'] = 0.0
        
        # Behavioral score - based on anomaly severity and statistical significance
        behavioral_anomalies = analysis_results.get('behavioral_anomalies', [])
        if behavioral_anomalies:
            anomaly_scores = [anom.get('confidence', 0.5) for anom in behavioral_anomalies]
            severity_scores = [anom.get('severity', 0.5) for anom in behavioral_anomalies]
            combined_scores = [(a + s) / 2 for a, s in zip(anomaly_scores, severity_scores)]
            scores['behavioral'] = statistics.mean(combined_scores)
        else:
            scores['behavioral'] = 0.0
        
        return scores
    
    def _calculate_base_threat_score(self, component_scores: Dict[str, float], 
                                   detections: Dict[str, int]) -> float:
        """Calculate base threat score with enhanced weighting"""
        
        # Component weights - balanced for different threat types
        weights = {
            'signature': 0.30,    # Known threats = high weight
            'ml': 0.25,          # ML detection = good weight
            'beaconing': 0.25,   # C2 patterns = high weight for C2 detection
            'behavioral': 0.20   # Anomalies = supporting evidence
        }
        
        # Calculate weighted score
        weighted_score = sum(component_scores[comp] * weights[comp] 
                           for comp in weights.keys())
        
        # Volume boost - more detections = higher confidence
        total_detections = sum(detections.values())
        volume_factor = 1.0 + min(0.3, total_detections * 0.05)
        
        return min(0.95, weighted_score * volume_factor)
    
    def _calculate_assessment_confidence(self, detections: Dict[str, int], 
                                       correlation_analysis: Dict[str, Any],
                                       confidence_metrics: Optional[Dict] = None) -> float:
        """Calculate how confident we are in our threat assessment"""
        
        confidence_factors = []
        
        # Detection diversity factor
        active_types = sum(1 for count in detections.values() if count > 0)
        diversity_factor = min(1.0, active_types / 4.0)
        confidence_factors.append(diversity_factor)
        
        # Correlation confidence
        correlation_confidence = correlation_analysis.get('correlation_confidence', 0.5)
        confidence_factors.append(correlation_confidence)
        
        # Volume confidence
        total_detections = sum(detections.values())
        volume_confidence = min(1.0, total_detections / 10.0)
        confidence_factors.append(volume_confidence)
        
        # External confidence metrics if available
        if confidence_metrics:
            external_confidence = confidence_metrics.get('final_score', 0.5)
            confidence_factors.append(external_confidence)
        
        # Calculate final confidence
        return statistics.mean(confidence_factors)
    
    def _generate_remediation_report(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate remediation report using the remediation engine"""
        try:
            remediation_report = self.remediation_engine.generate_remediation_report(threat_data)
            
            # Convert to dictionary for JSON serialization
            return {
                'threat_id': remediation_report.threat_id,
                'threat_type': remediation_report.threat_type,
                'threat_level': remediation_report.threat_level,
                'confidence_score': remediation_report.confidence_score,
                'generated_at': remediation_report.generated_at.isoformat(),
                'immediate_actions': [self._serialize_action(action) for action in remediation_report.immediate_actions],
                'short_term_actions': [self._serialize_action(action) for action in remediation_report.short_term_actions],
                'long_term_actions': [self._serialize_action(action) for action in remediation_report.long_term_actions],
                'monitoring_recommendations': remediation_report.monitoring_recommendations,
                'prevention_measures': remediation_report.prevention_measures,
                'estimated_total_time': remediation_report.estimated_total_time,
                'business_impact_assessment': remediation_report.business_impact_assessment,
                'compliance_considerations': remediation_report.compliance_considerations
            }
        except Exception as e:
            logger.error(f"Failed to generate remediation report: {e}")
            return None
    
    def _serialize_action(self, action) -> Dict[str, Any]:
        """Serialize RemediationAction to dictionary"""
        return {
            'title': action.title,
            'description': action.description,
            'category': action.category.value,
            'priority': action.priority.value,
            'estimated_time': action.estimated_time,
            'prerequisites': action.prerequisites,
            'steps': action.steps,
            'verification': action.verification,
            'automation_possible': action.automation_possible,
            'impact_level': action.impact_level
        }
    
    def _determine_threat_level(self, threat_score: float, correlation_analysis: Dict[str, Any]) -> str:
        """Determine threat level with correlation consideration"""
        # Adjust thresholds based on correlation strength
        correlation_confidence = correlation_analysis.get('correlation_confidence', 0.5)
        
        # Lower thresholds slightly if we have strong correlation
        if correlation_confidence > 0.8:
            adjustment = -0.05
        elif correlation_confidence > 0.6:
            adjustment = -0.02
        else:
            adjustment = 0.0
        
        adjusted_thresholds = {
            level: threshold + adjustment 
            for level, threshold in self.threat_thresholds.items()
        }
        
        for level, threshold in adjusted_thresholds.items():
            if threat_score >= threshold:
                return level
        
        return 'LOW'
    
    def _identify_risk_factors(self, analysis_results: Dict[str, Any]) -> Dict[str, bool]:
        """Identify specific risk factors from analysis results"""
        risk_factors = {
            'persistence': False,
            'lateral_movement': False,
            'data_exfiltration': False,
            'command_control': False,
            'privilege_escalation': False,
            'steganography': False,
            'dns_tunneling': False
        }
        
        # Check for persistence indicators
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        if beaconing_patterns:
            long_duration_patterns = [p for p in beaconing_patterns if p.get('duration', 0) > 3600]
            risk_factors['persistence'] = len(long_duration_patterns) > 0
            risk_factors['command_control'] = True  # Beaconing implies C2
        
        # Check for data exfiltration
        file_transfers = analysis_results.get('file_transfers', [])
        large_transfers = [t for t in file_transfers if t.get('size', 0) > 1000000]  # > 1MB
        risk_factors['data_exfiltration'] = len(large_transfers) > 0
        
        # Check for lateral movement
        suspicious_hosts = analysis_results.get('suspicious_hosts', [])
        unique_hosts = len(set(host.get('host', '') for host in suspicious_hosts))
        risk_factors['lateral_movement'] = unique_hosts > 2
        
        # Check signature-based risk factors
        signature_detections = analysis_results.get('signature_detections', [])
        for detection in signature_detections:
            matches = detection.get('signature_matches', [])
            if any('privilege' in match.lower() for match in matches):
                risk_factors['privilege_escalation'] = True
            if any('dns' in match.lower() and 'tunnel' in match.lower() for match in matches):
                risk_factors['dns_tunneling'] = True
            if any('steganography' in match.lower() for match in matches):
                risk_factors['steganography'] = True
        
        return risk_factors
    
    def _map_confidence_level(self, confidence_score: float) -> str:
        """Map confidence score to descriptive level"""
        if confidence_score >= 0.8:
            return "HIGH"
        elif confidence_score >= 0.6:
            return "MEDIUM-HIGH"
        elif confidence_score >= 0.4:
            return "MEDIUM"
        elif confidence_score >= 0.2:
            return "LOW-MEDIUM"
        else:
            return "LOW"
