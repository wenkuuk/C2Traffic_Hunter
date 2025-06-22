
#!/usr/bin/env python3
"""
Enhanced Threat Assessment Engine with Advanced C2 Detection
"""

import logging
import statistics
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
import json

# Import enhanced components
from .enhanced_statistical_analyzer import EnhancedStatisticalAnalyzer
from .advanced_confidence_calculator import AdvancedConfidenceCalculator
from .threat_remediation import ThreatRemediationEngine, RemediationReport

logger = logging.getLogger(__name__)

@dataclass
class AdvancedThreatAssessment:
    """Advanced threat assessment with enhanced detection capabilities"""
    threat_score: float
    threat_level: str
    confidence_score: float
    confidence_level: str
    component_scores: Dict[str, float]
    detection_breakdown: Dict[str, int]
    enhanced_analysis: Dict[str, Any]
    risk_factors: Dict[str, bool]
    remediation_report: Optional[Dict[str, Any]]
    correlation_analysis: Dict[str, Any]
    statistical_analysis: Dict[str, Any]
    behavioral_analysis: Dict[str, Any]
    total_detections: int

class AdvancedThreatAssessor:
    """Advanced threat assessor with sophisticated C2 detection algorithms"""
    
    def __init__(self):
        self.statistical_analyzer = EnhancedStatisticalAnalyzer()
        self.confidence_calculator = AdvancedConfidenceCalculator()
        self.remediation_engine = ThreatRemediationEngine()
        
        # Enhanced threat scoring weights with sophisticated algorithms
        self.component_weights = {
            'signature': 0.25,      # Known threats
            'ml': 0.25,            # Machine learning classification
            'beaconing': 0.30,     # Critical for C2 detection
            'behavioral': 0.20     # Behavioral anomalies
        }
        
        # Advanced threat level thresholds with dynamic adjustment
        self.base_thresholds = {
            'CRITICAL': 0.80,
            'HIGH': 0.65,
            'MEDIUM-HIGH': 0.50,
            'MEDIUM': 0.35,
            'LOW-MEDIUM': 0.20,
            'LOW': 0.0
        }
    
    def generate_threat_assessment(self, analysis_results: Dict[str, Any]) -> AdvancedThreatAssessment:
        """Generate comprehensive threat assessment with advanced analysis"""
        
        # Extract and enhance detection data
        detections = {
            'signature_detections': len(analysis_results.get('signature_detections', [])),
            'ml_classifications': len(analysis_results.get('ml_classifications', [])),
            'beaconing_patterns': len(analysis_results.get('beaconing_patterns', [])),
            'behavioral_anomalies': len(analysis_results.get('behavioral_anomalies', []))
        }
        
        total_detections = sum(detections.values())
        
        # Enhanced component scoring with sophisticated algorithms
        component_scores = self._calculate_advanced_component_scores(analysis_results)
        
        # Advanced correlation analysis
        correlation_analysis = self._perform_advanced_correlation_analysis(analysis_results, detections)
        
        # Enhanced statistical analysis
        statistical_analysis = self._perform_statistical_analysis(analysis_results)
        
        # Advanced behavioral analysis
        behavioral_analysis = self._perform_behavioral_analysis(analysis_results)
        
        # Calculate sophisticated threat score
        threat_score = self._calculate_sophisticated_threat_score(
            component_scores, correlation_analysis, statistical_analysis, behavioral_analysis
        )
        
        # Dynamic threat level determination
        threat_level = self._determine_dynamic_threat_level(threat_score, correlation_analysis)
        
        # Advanced confidence calculation
        confidence_metrics = self._calculate_advanced_confidence(
            analysis_results, component_scores, correlation_analysis
        )
        
        # Enhanced risk factor identification
        risk_factors = self._identify_advanced_risk_factors(analysis_results, statistical_analysis)
        
        # Generate enhanced remediation report
        remediation_report = None
        if threat_score >= 0.25:
            remediation_data = {
                'threat_level': threat_level,
                'threat_score': threat_score,
                'confidence_score': confidence_metrics.final_score,
                'risk_factors': risk_factors,
                'detection_breakdown': detections,
                'correlation_analysis': correlation_analysis,
                'statistical_analysis': statistical_analysis,
                'behavioral_analysis': behavioral_analysis
            }
            remediation_report = self._generate_enhanced_remediation_report(remediation_data)
        
        # Create enhanced analysis summary
        enhanced_analysis = {
            'detection_sophistication': self._assess_detection_sophistication(detections),
            'pattern_complexity': self._assess_pattern_complexity(statistical_analysis),
            'evasion_indicators': self._detect_evasion_techniques(behavioral_analysis),
            'persistence_analysis': self._analyze_persistence_indicators(analysis_results),
            'impact_assessment': self._assess_potential_impact(risk_factors, threat_score)
        }
        
        return AdvancedThreatAssessment(
            threat_score=threat_score,
            threat_level=threat_level,
            confidence_score=confidence_metrics.final_score,
            confidence_level=confidence_metrics.confidence_level,
            component_scores=component_scores,
            detection_breakdown=detections,
            enhanced_analysis=enhanced_analysis,
            risk_factors=risk_factors,
            remediation_report=remediation_report,
            correlation_analysis=correlation_analysis,
            statistical_analysis=statistical_analysis,
            behavioral_analysis=behavioral_analysis,
            total_detections=total_detections
        )
    
    def _calculate_advanced_component_scores(self, analysis_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate advanced component scores with quality weighting"""
        scores = {}
        
        # Advanced signature scoring
        signature_detections = analysis_results.get('signature_detections', [])
        if signature_detections:
            # Quality-weighted with confidence intervals
            signature_scores = []
            for det in signature_detections:
                base_score = det.get('signature_score', 0.5)
                confidence = det.get('confidence', 0.8)
                matches = len(det.get('signature_matches', []))
                
                # Weight by confidence and match quality
                weighted_score = base_score * confidence * min(1.0, matches / 3)
                signature_scores.append(weighted_score)
            
            scores['signature'] = min(1.0, statistics.mean(signature_scores) * 1.2)
        else:
            scores['signature'] = 0.0
        
        # Advanced ML scoring with model reliability
        ml_classifications = analysis_results.get('ml_classifications', [])
        if ml_classifications:
            ml_scores = []
            for cls in ml_classifications:
                base_score = cls.get('ml_score', 0.5)
                model_confidence = cls.get('model_confidence', 0.8)
                feature_quality = cls.get('feature_quality', 0.7)
                
                # Advanced weighting with feature quality
                weighted_score = base_score * model_confidence * feature_quality
                ml_scores.append(weighted_score)
            
            scores['ml'] = min(1.0, statistics.mean(ml_scores) * 1.1)
        else:
            scores['ml'] = 0.0
        
        # Advanced beaconing scoring with pattern analysis
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        if beaconing_patterns:
            beaconing_scores = []
            for pattern in beaconing_patterns:
                base_confidence = pattern.get('confidence', 0.5)
                regularity = 1 - pattern.get('coefficient_of_variation', 0.5)
                periodicity = pattern.get('periodicity', 0.0)
                duration_factor = min(1.0, pattern.get('duration', 0) / 3600)
                
                # Sophisticated beaconing score calculation
                pattern_score = (base_confidence * 0.4 + 
                               regularity * 0.3 + 
                               periodicity * 0.2 + 
                               duration_factor * 0.1)
                beaconing_scores.append(pattern_score)
            
            scores['beaconing'] = min(1.0, statistics.mean(beaconing_scores) * 1.3)
        else:
            scores['beaconing'] = 0.0
        
        # Advanced behavioral scoring
        behavioral_anomalies = analysis_results.get('behavioral_anomalies', [])
        if behavioral_anomalies:
            behavioral_scores = []
            for anomaly in behavioral_anomalies:
                confidence = anomaly.get('confidence', 0.5)
                severity = anomaly.get('severity', 0.5)
                statistical_significance = anomaly.get('statistical_significance', 0.7)
                
                # Weight by statistical significance
                anomaly_score = (confidence + severity) / 2 * statistical_significance
                behavioral_scores.append(anomaly_score)
            
            scores['behavioral'] = min(1.0, statistics.mean(behavioral_scores))
        else:
            scores['behavioral'] = 0.0
        
        return scores
    
    def _perform_advanced_correlation_analysis(self, analysis_results: Dict[str, Any], 
                                             detections: Dict[str, int]) -> Dict[str, Any]:
        """Perform sophisticated correlation analysis"""
        # ... keep existing code (correlation analysis implementation) the same ...
        
        active_detection_types = [k for k, v in detections.items() if v > 0]
        correlation_strength = 0.0
        correlation_details = {}
        
        # Enhanced multi-method correlation with weighted scoring
        correlation_weights = {
            'signature_ml': 0.30,      # Strongest correlation
            'beaconing_behavioral': 0.25,
            'signature_beaconing': 0.22,
            'ml_behavioral': 0.18,
            'temporal_patterns': 0.15,
            'host_correlation': 0.10
        }
        
        if len(active_detection_types) >= 2:
            # Calculate each correlation type with enhanced algorithms
            for correlation_type, weight in correlation_weights.items():
                if self._has_correlation_type(detections, correlation_type):
                    correlation_strength += weight
                    correlation_details[correlation_type] = True
        
        # Advanced temporal correlation
        temporal_analysis = self._analyze_advanced_temporal_correlations(analysis_results)
        if temporal_analysis['strong_temporal_correlation']:
            correlation_strength += 0.15
            correlation_details['temporal'] = temporal_analysis
        
        # Enhanced host correlation
        host_correlation = self._analyze_enhanced_host_correlations(analysis_results)
        if host_correlation['sophisticated_lateral_movement']:
            correlation_strength += 0.12
            correlation_details['host_correlation'] = host_correlation
        
        return {
            'correlation_strength': correlation_strength,
            'correlation_bonus': min(0.35, correlation_strength),  # Increased cap
            'correlation_details': correlation_details,
            'active_detection_types': len(active_detection_types),
            'correlation_confidence': min(1.0, correlation_strength / 0.6)
        }
    
    def _calculate_sophisticated_threat_score(self, component_scores: Dict[str, float],
                                            correlation_analysis: Dict[str, Any],
                                            statistical_analysis: Dict[str, Any],
                                            behavioral_analysis: Dict[str, Any]) -> float:
        """Calculate sophisticated threat score with advanced weighting"""
        
        # Base weighted score
        base_score = sum(component_scores[comp] * self.component_weights[comp] 
                        for comp in self.component_weights.keys())
        
        # Correlation bonus with sophisticated calculation
        correlation_bonus = correlation_analysis.get('correlation_bonus', 0.0)
        
        # Statistical significance bonus
        statistical_bonus = 0.0
        if statistical_analysis.get('high_statistical_significance', False):
            statistical_bonus = 0.08
        
        # Behavioral sophistication bonus
        behavioral_bonus = 0.0
        if behavioral_analysis.get('sophisticated_evasion', False):
            behavioral_bonus = 0.06
        
        # Pattern complexity bonus
        pattern_complexity = statistical_analysis.get('pattern_complexity_score', 0.0)
        complexity_bonus = min(0.1, pattern_complexity * 0.15)
        
        # Calculate final score with all enhancements
        final_score = (base_score + correlation_bonus + statistical_bonus + 
                      behavioral_bonus + complexity_bonus)
        
        # Apply sophisticated bounds and normalization
        return max(0.05, min(0.95, final_score))
    
    def _calculate_advanced_confidence(self, analysis_results: Dict[str, Any],
                                     component_scores: Dict[str, float],
                                     correlation_analysis: Dict[str, Any]) -> Any:
        """Calculate advanced confidence using the enhanced calculator"""
        
        # Prepare data for confidence calculation
        confidence_data = {
            'detection_scores': component_scores,
            'features': self._extract_all_features(analysis_results),
            'timestamps': self._extract_timestamps(analysis_results),
            'behavioral_features': self._extract_behavioral_features(analysis_results),
            'correlation_data': correlation_analysis,
            'statistical_metrics': self._extract_statistical_metrics(analysis_results),
            'detection_age_hours': 0  # Assuming recent detection
        }
        
        return self.confidence_calculator.calculate_comprehensive_confidence(confidence_data)
    
    # ... keep existing code (helper methods) the same ...
    
    def _perform_statistical_analysis(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform advanced statistical analysis"""
        statistical_results = {}
        
        # Analyze beaconing patterns with advanced statistics
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        if beaconing_patterns:
            pattern_entropies = []
            regularities = []
            
            for pattern in beaconing_patterns:
                if 'intervals' in pattern:
                    intervals = pattern['intervals']
                    entropy = self.statistical_analyzer.calculate_entropy(intervals)
                    pattern_entropies.append(entropy)
                    
                    regularity = 1 - pattern.get('coefficient_of_variation', 0.5)
                    regularities.append(regularity)
            
            if pattern_entropies:
                statistical_results['pattern_entropy_avg'] = statistics.mean(pattern_entropies)
                statistical_results['pattern_regularity_avg'] = statistics.mean(regularities)
                statistical_results['high_statistical_significance'] = (
                    statistics.mean(pattern_entropies) < 2.0 and
                    statistics.mean(regularities) > 0.7
                )
        
        # Calculate pattern complexity
        all_scores = [s for s in analysis_results.values() if isinstance(s, (int, float))]
        if all_scores:
            statistical_results['pattern_complexity_score'] = statistics.stdev(all_scores) if len(all_scores) > 1 else 0.0
        
        return statistical_results
    
    def _perform_behavioral_analysis(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform advanced behavioral analysis"""
        behavioral_results = {}
        
        # Analyze evasion techniques
        behavioral_anomalies = analysis_results.get('behavioral_anomalies', [])
        evasion_indicators = 0
        
        for anomaly in behavioral_anomalies:
            if 'user_agent_rotation' in anomaly.get('indicators', []):
                evasion_indicators += 1
            if 'timing_randomization' in anomaly.get('indicators', []):
                evasion_indicators += 1
            if 'payload_obfuscation' in anomaly.get('indicators', []):
                evasion_indicators += 1
        
        behavioral_results['evasion_indicator_count'] = evasion_indicators
        behavioral_results['sophisticated_evasion'] = evasion_indicators >= 2
        
        return behavioral_results
    
    def _has_correlation_type(self, detections: Dict[str, int], correlation_type: str) -> bool:
        """Check if specific correlation type exists"""
        if correlation_type == 'signature_ml':
            return detections['signature_detections'] > 0 and detections['ml_classifications'] > 0
        elif correlation_type == 'beaconing_behavioral':
            return detections['beaconing_patterns'] > 0 and detections['behavioral_anomalies'] > 0
        elif correlation_type == 'signature_beaconing':
            return detections['signature_detections'] > 0 and detections['beaconing_patterns'] > 0
        elif correlation_type == 'ml_behavioral':
            return detections['ml_classifications'] > 0 and detections['behavioral_anomalies'] > 0
        return False
    
    def _analyze_advanced_temporal_correlations(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze advanced temporal correlation patterns"""
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        
        strong_correlation = False
        persistence_score = 0.0
        
        if beaconing_patterns:
            long_patterns = [p for p in beaconing_patterns if p.get('duration', 0) > 7200]  # 2+ hours
            if long_patterns:
                strong_correlation = True
                durations = [p.get('duration', 0) for p in long_patterns]
                persistence_score = min(1.0, statistics.mean(durations) / 86400)  # Normalize by day
        
        return {
            'strong_temporal_correlation': strong_correlation,
            'persistence_score': persistence_score,
            'long_duration_patterns': len([p for p in beaconing_patterns if p.get('duration', 0) > 3600])
        }
    
    def _analyze_enhanced_host_correlations(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze enhanced host correlation patterns"""
        suspicious_hosts = analysis_results.get('suspicious_hosts', {})
        unique_hosts = len(suspicious_hosts)
        
        sophisticated_movement = False
        if unique_hosts > 3:  # Multiple hosts involved
            # Check for coordinated activity
            host_activities = list(suspicious_hosts.values())
            if len(host_activities) > 1:
                # Analyze activity patterns across hosts
                activity_scores = [len(activity) if isinstance(activity, list) else 1 
                                 for activity in host_activities]
                if statistics.variance(activity_scores) < 2:  # Similar activity levels
                    sophisticated_movement = True
        
        return {
            'unique_host_count': unique_hosts,
            'sophisticated_lateral_movement': sophisticated_movement,
            'coordinated_activity': unique_hosts > 2 and sophisticated_movement
        }
    
    def _extract_all_features(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all available features for confidence calculation"""
        all_features = {}
        
        # Combine features from all detection types
        for detection_type in ['signature_detections', 'ml_classifications', 'beaconing_patterns', 'behavioral_anomalies']:
            detections = analysis_results.get(detection_type, [])
            for detection in detections:
                if isinstance(detection, dict) and 'features' in detection:
                    all_features.update(detection['features'])
        
        return all_features
    
    def _extract_timestamps(self, analysis_results: Dict[str, Any]) -> List[float]:
        """Extract timestamps for temporal analysis"""
        timestamps = []
        
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        for pattern in beaconing_patterns:
            if 'timestamps' in pattern:
                timestamps.extend(pattern['timestamps'])
        
        return sorted(timestamps)
    
    def _extract_behavioral_features(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract behavioral features for confidence calculation"""
        behavioral_features = {}
        
        behavioral_anomalies = analysis_results.get('behavioral_anomalies', [])
        if behavioral_anomalies:
            # Count user agents
            user_agents = set()
            for anomaly in behavioral_anomalies:
                if 'user_agent' in anomaly:
                    user_agents.add(anomaly['user_agent'])
            
            behavioral_features['user_agent_count'] = len(user_agents)
            behavioral_features['anomaly_count'] = len(behavioral_anomalies)
        
        return behavioral_features
    
    def _extract_statistical_metrics(self, analysis_results: Dict[str, Any]) -> Dict[str, float]:
        """Extract statistical metrics for confidence calculation"""
        metrics = {}
        
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        if beaconing_patterns:
            entropies = []
            variances = []
            
            for pattern in beaconing_patterns:
                if 'entropy' in pattern:
                    entropies.append(pattern['entropy'])
                if 'variance' in pattern:
                    variances.append(pattern['variance'])
            
            if entropies:
                metrics['entropy'] = statistics.mean(entropies)
            if variances:
                metrics['variance'] = statistics.mean(variances)
            
            metrics['sample_size'] = len(beaconing_patterns)
        
        return metrics
    
    def _determine_dynamic_threat_level(self, threat_score: float, 
                                      correlation_analysis: Dict[str, Any]) -> str:
        """Determine threat level with dynamic adjustment based on correlation"""
        correlation_confidence = correlation_analysis.get('correlation_confidence', 0.5)
        
        # Adjust thresholds based on correlation strength
        if correlation_confidence > 0.8:
            adjustment = -0.08  # Lower thresholds with strong correlation
        elif correlation_confidence > 0.6:
            adjustment = -0.04
        else:
            adjustment = 0.02   # Raise thresholds with weak correlation
        
        adjusted_thresholds = {
            level: threshold + adjustment 
            for level, threshold in self.base_thresholds.items()
        }
        
        for level, threshold in adjusted_thresholds.items():
            if threat_score >= threshold:
                return level
        
        return 'LOW'
    
    def _identify_advanced_risk_factors(self, analysis_results: Dict[str, Any],
                                      statistical_analysis: Dict[str, Any]) -> Dict[str, bool]:
        """Identify advanced risk factors with sophisticated analysis"""
        # ... keep existing code (risk factor identification) the same ...
        
        risk_factors = {
            'persistence': False,
            'lateral_movement': False,
            'data_exfiltration': False,
            'command_control': False,
            'privilege_escalation': False,
            'steganography': False,
            'dns_tunneling': False,
            'evasion_techniques': False,
            'coordinated_attack': False
        }
        
        # Enhanced persistence detection
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        if beaconing_patterns:
            long_duration_patterns = [p for p in beaconing_patterns if p.get('duration', 0) > 7200]
            risk_factors['persistence'] = len(long_duration_patterns) > 0
            risk_factors['command_control'] = True
        
        # Enhanced evasion detection
        if statistical_analysis.get('sophisticated_evasion', False):
            risk_factors['evasion_techniques'] = True
        
        # Coordinated attack detection
        host_correlation = analysis_results.get('suspicious_hosts', {})
        if len(host_correlation) > 3:
            risk_factors['coordinated_attack'] = True
            risk_factors['lateral_movement'] = True
        
        # ... keep existing code (other risk factors) the same ...
        
        return risk_factors
    
    def _generate_enhanced_remediation_report(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate enhanced remediation report with advanced threat data"""
        try:
            # Enhance threat data with advanced analysis
            enhanced_threat_data = {
                **threat_data,
                'advanced_indicators': {
                    'correlation_strength': threat_data.get('correlation_analysis', {}).get('correlation_strength', 0),
                    'statistical_significance': threat_data.get('statistical_analysis', {}).get('high_statistical_significance', False),
                    'behavioral_sophistication': threat_data.get('behavioral_analysis', {}).get('sophisticated_evasion', False)
                }
            }
            
            remediation_report = self.remediation_engine.generate_remediation_report(enhanced_threat_data)
            
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
            logger.error(f"Failed to generate enhanced remediation report: {e}")
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
    
    # Additional helper methods for enhanced analysis
    def _assess_detection_sophistication(self, detections: Dict[str, int]) -> Dict[str, Any]:
        """Assess the sophistication of detected threats"""
        active_types = sum(1 for count in detections.values() if count > 0)
        total_detections = sum(detections.values())
        
        return {
            'detection_diversity': active_types,
            'detection_volume': total_detections,
            'sophistication_level': 'HIGH' if active_types >= 3 else 'MEDIUM' if active_types >= 2 else 'LOW'
        }
    
    def _assess_pattern_complexity(self, statistical_analysis: Dict[str, Any]) -> float:
        """Assess the complexity of detected patterns"""
        complexity_score = 0.0
        
        if statistical_analysis.get('high_statistical_significance', False):
            complexity_score += 0.4
        
        pattern_entropy = statistical_analysis.get('pattern_entropy_avg', 0.0)
        if pattern_entropy > 0:
            complexity_score += min(0.3, pattern_entropy / 10)
        
        return min(1.0, complexity_score)
    
    def _detect_evasion_techniques(self, behavioral_analysis: Dict[str, Any]) -> List[str]:
        """Detect specific evasion techniques"""
        evasion_techniques = []
        
        if behavioral_analysis.get('sophisticated_evasion', False):
            evasion_count = behavioral_analysis.get('evasion_indicator_count', 0)
            
            if evasion_count >= 3:
                evasion_techniques.append('Advanced multi-vector evasion')
            elif evasion_count >= 2:
                evasion_techniques.append('Moderate evasion techniques')
            else:
                evasion_techniques.append('Basic evasion detected')
        
        return evasion_techniques
    
    def _analyze_persistence_indicators(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze indicators of threat persistence"""
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        
        persistence_indicators = {
            'long_duration_sessions': 0,
            'regular_callback_patterns': 0,
            'persistence_score': 0.0
        }
        
        for pattern in beaconing_patterns:
            duration = pattern.get('duration', 0)
            if duration > 7200:  # > 2 hours
                persistence_indicators['long_duration_sessions'] += 1
            
            regularity = 1 - pattern.get('coefficient_of_variation', 1.0)
            if regularity > 0.8:
                persistence_indicators['regular_callback_patterns'] += 1
        
        if beaconing_patterns:
            avg_duration = statistics.mean([p.get('duration', 0) for p in beaconing_patterns])
            persistence_indicators['persistence_score'] = min(1.0, avg_duration / 86400)  # Normalize by day
        
        return persistence_indicators
    
    def _assess_potential_impact(self, risk_factors: Dict[str, bool], threat_score: float) -> Dict[str, str]:
        """Assess potential impact of the threat"""
        impact_levels = {
            'data_confidentiality': 'LOW',
            'system_availability': 'LOW',
            'network_integrity': 'LOW',
            'business_operations': 'LOW'
        }
        
        # Assess based on risk factors and threat score
        high_risk_factors = sum(1 for factor in risk_factors.values() if factor)
        
        if threat_score > 0.7 or high_risk_factors >= 4:
            impact_levels['data_confidentiality'] = 'HIGH'
            impact_levels['system_availability'] = 'HIGH'
            impact_levels['network_integrity'] = 'HIGH'
            impact_levels['business_operations'] = 'HIGH'
        elif threat_score > 0.5 or high_risk_factors >= 2:
            impact_levels['data_confidentiality'] = 'MEDIUM'
            impact_levels['system_availability'] = 'MEDIUM'
            impact_levels['network_integrity'] = 'MEDIUM'
            impact_levels['business_operations'] = 'MEDIUM'
        
        return impact_levels

