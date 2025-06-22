
#!/usr/bin/env python3
"""
Enhanced threat scoring algorithms for C2 detection
"""

import statistics
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatScorer:
    """Advanced threat scoring with sophisticated algorithms and enhanced correlation"""
    
    def __init__(self):
        # Enhanced threat scoring weights with sophisticated algorithms
        self.component_weights = {
            'signature': 0.25,      # Known threats
            'ml': 0.25,            # Machine learning classification
            'beaconing': 0.30,     # Critical for C2 detection
            'behavioral': 0.20     # Behavioral anomalies
        }
        
        # Correlation bonus weights - this is crucial for accuracy
        self.correlation_weights = {
            'two_methods': 0.10,     # Bonus when 2 methods agree
            'three_methods': 0.15,   # Bonus when 3 methods agree
            'all_methods': 0.20,     # Bonus when all 4 methods agree
            'high_confidence_agreement': 0.05  # Extra bonus for high-confidence agreement
        }
    
    def calculate_advanced_component_scores(self, analysis_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate advanced component scores with quality weighting"""
        scores = {}
        
        # Advanced signature scoring with confidence weighting
        signature_detections = analysis_results.get('signature_detections', [])
        if signature_detections:
            signature_scores = []
            for det in signature_detections:
                base_score = det.get('signature_score', 0.5)
                confidence = det.get('confidence', 0.8)
                matches = len(det.get('signature_matches', []))
                
                # Enhanced weighting: confidence × base_score × match_quality
                match_quality = min(1.0, matches / 3)  # Normalize match count
                weighted_score = base_score * confidence * (0.7 + 0.3 * match_quality)
                signature_scores.append(weighted_score)
            
            scores['signature'] = min(1.0, statistics.mean(signature_scores) * 1.1)
        else:
            scores['signature'] = 0.0
        
        # Advanced ML scoring with model reliability and feature quality
        ml_classifications = analysis_results.get('ml_classifications', [])
        if ml_classifications:
            ml_scores = []
            for cls in ml_classifications:
                base_score = cls.get('ml_score', 0.5)
                model_confidence = cls.get('model_confidence', 0.8)
                feature_quality = cls.get('feature_quality', 0.7)
                
                # Enhanced ML scoring with feature completeness consideration
                feature_completeness = cls.get('feature_completeness', 0.8)
                weighted_score = (base_score * model_confidence * 
                                feature_quality * (0.8 + 0.2 * feature_completeness))
                ml_scores.append(weighted_score)
            
            scores['ml'] = min(1.0, statistics.mean(ml_scores) * 1.05)
        else:
            scores['ml'] = 0.0
        
        # Enhanced beaconing scoring with advanced pattern analysis
        beaconing_patterns = analysis_results.get('beaconing_patterns', [])
        beacon_candidates = analysis_results.get('beacon_candidates', [])
        all_beaconing = beaconing_patterns + beacon_candidates
        
        if all_beaconing:
            beaconing_scores = []
            for pattern in all_beaconing:
                base_confidence = pattern.get('confidence', 0.5)
                
                # Enhanced beaconing factors
                regularity = 1 - pattern.get('coefficient_of_variation', 0.5)
                periodicity = pattern.get('periodicity', 0.0)
                duration = pattern.get('duration', 0)
                duration_factor = min(1.0, duration / 3600)  # Normalize by hour
                
                # Pattern strength from timing analysis
                timing_score = 0.0
                if pattern.get('very_regular', False):
                    timing_score += 0.3
                if pattern.get('high_periodicity', False):
                    timing_score += 0.3
                if pattern.get('timing_cov', 1.0) < 0.2:  # Very consistent timing
                    timing_score += 0.2
                
                # Sophisticated beaconing score calculation
                pattern_score = (base_confidence * 0.3 + 
                               regularity * 0.25 + 
                               periodicity * 0.2 + 
                               duration_factor * 0.1 +
                               timing_score * 0.15)
                
                beaconing_scores.append(pattern_score)
            
            scores['beaconing'] = min(1.0, statistics.mean(beaconing_scores) * 1.2)
        else:
            scores['beaconing'] = 0.0
        
        # Enhanced behavioral scoring with advanced anomaly detection
        behavioral_anomalies = analysis_results.get('behavioral_anomalies', [])
        if behavioral_anomalies:
            behavioral_scores = []
            for anomaly in behavioral_anomalies:
                confidence = anomaly.get('confidence', 0.5)
                severity = anomaly.get('severity', 0.5)
                statistical_significance = anomaly.get('statistical_significance', 0.7)
                
                # Additional behavioral factors
                anomaly_score_base = anomaly.get('anomaly_score', 0.5)
                evasion_indicators = len(anomaly.get('evasion_indicators', []))
                evasion_factor = min(1.0, evasion_indicators * 0.2)
                
                # Weight by statistical significance and evasion sophistication
                anomaly_score = ((confidence + severity) / 2 * statistical_significance * 
                               (1.0 + evasion_factor * 0.3))
                behavioral_scores.append(anomaly_score)
            
            scores['behavioral'] = min(1.0, statistics.mean(behavioral_scores))
        else:
            scores['behavioral'] = 0.0
        
        return scores
    
    def calculate_correlation_bonus(self, component_scores: Dict[str, float], 
                                   correlation_analysis: Dict[str, Any]) -> float:
        """
        Calculate correlation bonus - CRITICAL for reducing false positives
        
        The correlation bonus is ESSENTIAL because:
        1. Multiple independent detection methods agreeing significantly reduces false positives
        2. C2 traffic often exhibits patterns detectable by multiple approaches
        3. Sophisticated attackers may evade single detection methods but struggle with multiple
        4. It provides mathematical validation that the threat is real, not noise
        """
        
        # Count active detection methods (score > threshold)
        detection_threshold = 0.3
        active_methods = sum(1 for score in component_scores.values() if score > detection_threshold)
        high_confidence_methods = sum(1 for score in component_scores.values() if score > 0.7)
        
        correlation_bonus = 0.0
        
        # Base correlation bonuses based on method agreement
        if active_methods >= 4:  # All methods detect something
            correlation_bonus += self.correlation_weights['all_methods']
            logger.info("All detection methods active - high confidence correlation bonus")
        elif active_methods >= 3:  # Three methods agree
            correlation_bonus += self.correlation_weights['three_methods']
            logger.info("Three detection methods active - strong correlation bonus")
        elif active_methods >= 2:  # Two methods agree
            correlation_bonus += self.correlation_weights['two_methods']
            logger.info("Two detection methods active - moderate correlation bonus")
        
        # High confidence agreement bonus
        if high_confidence_methods >= 2:
            correlation_bonus += self.correlation_weights['high_confidence_agreement']
            logger.info("Multiple high-confidence detections - additional bonus")
        
        # Advanced correlation factors from correlation analysis
        correlation_strength = correlation_analysis.get('correlation_strength', 0.0)
        multi_host_activity = correlation_analysis.get('multi_host_activity', False)
        temporal_correlation = correlation_analysis.get('temporal_correlation', 0.0)
        
        # Enhance bonus based on correlation quality
        if correlation_strength > 0.7:
            correlation_bonus += 0.05  # Strong correlation between detections
        
        if multi_host_activity:
            correlation_bonus += 0.03  # Multiple hosts involved increases confidence
        
        if temporal_correlation > 0.6:
            correlation_bonus += 0.02  # Temporal patterns align across methods
        
        # Pattern consistency bonus
        pattern_consistency = correlation_analysis.get('pattern_consistency', 0.0)
        if pattern_consistency > 0.8:
            correlation_bonus += 0.03
        
        # Cap the correlation bonus to prevent over-inflation
        correlation_bonus = min(0.25, correlation_bonus)
        
        logger.info(f"Correlation bonus calculated: {correlation_bonus:.3f} "
                   f"(active_methods: {active_methods}, high_conf: {high_confidence_methods})")
        
        return correlation_bonus
    
    def calculate_sophisticated_threat_score(self, component_scores: Dict[str, float],
                                           correlation_analysis: Dict[str, Any],
                                           statistical_analysis: Dict[str, Any],
                                           behavioral_analysis: Dict[str, Any]) -> float:
        """Calculate sophisticated threat score with enhanced correlation weighting"""
        
        # Base weighted score
        base_score = sum(component_scores[comp] * self.component_weights[comp] 
                        for comp in self.component_weights.keys())
        
        # ESSENTIAL: Correlation bonus calculation
        # This is the key differentiator between noise and real threats
        correlation_bonus = self.calculate_correlation_bonus(component_scores, correlation_analysis)
        
        # Statistical significance bonus
        statistical_bonus = 0.0
        if statistical_analysis.get('high_statistical_significance', False):
            statistical_bonus = 0.06
            logger.info("High statistical significance detected")
        
        # Pattern entropy bonus (low entropy = more structured = more suspicious)
        pattern_entropy = statistical_analysis.get('pattern_entropy_avg', 5.0)
        if pattern_entropy < 2.0:
            entropy_bonus = 0.05 * (2.0 - pattern_entropy) / 2.0
            statistical_bonus += entropy_bonus
        
        # Behavioral sophistication bonus
        behavioral_bonus = 0.0
        if behavioral_analysis.get('sophisticated_evasion', False):
            behavioral_bonus = 0.04
            logger.info("Sophisticated evasion techniques detected")
        
        evasion_count = behavioral_analysis.get('evasion_indicator_count', 0)
        if evasion_count > 0:
            behavioral_bonus += min(0.03, evasion_count * 0.01)
        
        # Pattern complexity consideration
        pattern_complexity = statistical_analysis.get('pattern_complexity_score', 0.0)
        complexity_bonus = min(0.05, pattern_complexity * 0.1)
        
        # Calculate final score with all enhancements
        final_score = (base_score + correlation_bonus + statistical_bonus + 
                      behavioral_bonus + complexity_bonus)
        
        # Apply sophisticated bounds and normalization
        # Ensure minimum score for any detection, maximum cap for safety
        final_score = max(0.05, min(0.95, final_score))
        
        logger.info(f"Threat score breakdown - Base: {base_score:.3f}, "
                   f"Correlation: {correlation_bonus:.3f}, Statistical: {statistical_bonus:.3f}, "
                   f"Behavioral: {behavioral_bonus:.3f}, Final: {final_score:.3f}")
        
        return final_score

