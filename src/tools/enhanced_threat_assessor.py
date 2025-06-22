
#!/usr/bin/env python3
"""
Enhanced Threat Assessment Engine with Advanced C2 Detection
"""

import logging
import statistics
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass

# Import enhanced components
from .enhanced_statistical_analyzer import EnhancedStatisticalAnalyzer
from .advanced_confidence_calculator import AdvancedConfidenceCalculator
from .threat_remediation import ThreatRemediationEngine, RemediationReport
from .threat_scoring import ThreatScorer
from .correlation_analyzer import CorrelationAnalyzer
from .risk_assessor import RiskAssessor
from .threat_classifier import ThreatClassifier

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
        self.threat_scorer = ThreatScorer()
        self.correlation_analyzer = CorrelationAnalyzer()
        self.risk_assessor = RiskAssessor()
        self.threat_classifier = ThreatClassifier()
    
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
        component_scores = self.threat_scorer.calculate_advanced_component_scores(analysis_results)
        
        # Advanced correlation analysis
        correlation_analysis = self.correlation_analyzer.perform_advanced_correlation_analysis(analysis_results, detections)
        
        # Enhanced statistical analysis
        statistical_analysis = self._perform_statistical_analysis(analysis_results)
        
        # Advanced behavioral analysis
        behavioral_analysis = self._perform_behavioral_analysis(analysis_results)
        
        # Calculate sophisticated threat score
        threat_score = self.threat_scorer.calculate_sophisticated_threat_score(
            component_scores, correlation_analysis, statistical_analysis, behavioral_analysis
        )
        
        # Dynamic threat level determination
        threat_level = self.threat_classifier.determine_dynamic_threat_level(threat_score, correlation_analysis)
        
        # Advanced confidence calculation
        confidence_metrics = self._calculate_advanced_confidence(
            analysis_results, component_scores, correlation_analysis
        )
        
        # Enhanced risk factor identification
        risk_factors = self.risk_assessor.identify_advanced_risk_factors(analysis_results, statistical_analysis)
        
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
            'detection_sophistication': self.threat_classifier.assess_detection_sophistication(detections),
            'pattern_complexity': self.threat_classifier.assess_pattern_complexity(statistical_analysis),
            'evasion_indicators': self.threat_classifier.detect_evasion_techniques(behavioral_analysis),
            'persistence_analysis': self._analyze_persistence_indicators(analysis_results),
            'impact_assessment': self.risk_assessor.assess_potential_impact(risk_factors, threat_score)
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
    
    # Helper methods for data extraction
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
