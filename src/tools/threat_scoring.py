
#!/usr/bin/env python3
"""
Threat scoring algorithms for C2 detection
"""

import statistics
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatScorer:
    """Advanced threat scoring with sophisticated algorithms"""
    
    def __init__(self):
        # Enhanced threat scoring weights with sophisticated algorithms
        self.component_weights = {
            'signature': 0.25,      # Known threats
            'ml': 0.25,            # Machine learning classification
            'beaconing': 0.30,     # Critical for C2 detection
            'behavioral': 0.20     # Behavioral anomalies
        }
    
    def calculate_advanced_component_scores(self, analysis_results: Dict[str, Any]) -> Dict[str, float]:
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
    
    def calculate_sophisticated_threat_score(self, component_scores: Dict[str, float],
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
