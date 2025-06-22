
#!/usr/bin/env python3
"""
Correlation analysis for threat detection
"""

import statistics
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class CorrelationAnalyzer:
    """Advanced correlation analysis for threat detection"""
    
    def __init__(self):
        # Enhanced multi-method correlation with weighted scoring
        self.correlation_weights = {
            'signature_ml': 0.30,      # Strongest correlation
            'beaconing_behavioral': 0.25,
            'signature_beaconing': 0.22,
            'ml_behavioral': 0.18,
            'temporal_patterns': 0.15,
            'host_correlation': 0.10
        }
    
    def perform_advanced_correlation_analysis(self, analysis_results: Dict[str, Any], 
                                            detections: Dict[str, int]) -> Dict[str, Any]:
        """Perform sophisticated correlation analysis"""
        active_detection_types = [k for k, v in detections.items() if v > 0]
        correlation_strength = 0.0
        correlation_details = {}
        
        if len(active_detection_types) >= 2:
            # Calculate each correlation type with enhanced algorithms
            for correlation_type, weight in self.correlation_weights.items():
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
