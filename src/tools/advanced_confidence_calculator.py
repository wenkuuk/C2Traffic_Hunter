
#!/usr/bin/env python3
"""
Advanced confidence calculation system with enhanced C2 detection techniques
"""

import math
import statistics
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class EnhancedConfidenceMetrics:
    """Enhanced confidence calculation metrics"""
    base_score: float
    detection_consistency: float
    feature_completeness: float
    temporal_confidence: float
    behavioral_confidence: float
    correlation_confidence: float
    statistical_confidence: float
    final_score: float
    confidence_level: str
    confidence_factors: Dict[str, float]
    warnings: List[str]

class AdvancedConfidenceCalculator:
    """Advanced confidence calculator with sophisticated C2 detection metrics"""
    
    def __init__(self):
        self.confidence_thresholds = {
            'VERY_HIGH': 0.85,
            'HIGH': 0.70,
            'MEDIUM_HIGH': 0.55,
            'MEDIUM': 0.40,
            'LOW_MEDIUM': 0.25,
            'LOW': 0.0
        }
        
        # Feature importance weights
        self.feature_weights = {
            'detection_consistency': 0.25,
            'feature_completeness': 0.15,
            'temporal_confidence': 0.20,
            'behavioral_confidence': 0.20,
            'correlation_confidence': 0.15,
            'statistical_confidence': 0.05
        }
    
    def calculate_detection_consistency(self, detection_scores: Dict[str, float]) -> float:
        """Calculate consistency across different detection methods"""
        if len(detection_scores) < 2:
            return 0.7  # Moderate confidence with single detection
        
        scores = list(detection_scores.values())
        
        # Calculate variance in detection scores
        score_variance = statistics.variance(scores)
        
        # Low variance = high consistency
        if score_variance < 0.05:
            consistency = 0.95
        elif score_variance < 0.15:
            consistency = 0.85
        elif score_variance < 0.3:
            consistency = 0.70
        else:
            consistency = 0.50
        
        # Boost if multiple methods agree on high threat
        high_score_count = sum(1 for score in scores if score > 0.7)
        if high_score_count >= 2:
            consistency += 0.1
        
        # Boost if all methods detect something
        if all(score > 0.3 for score in scores):
            consistency += 0.05
        
        return min(1.0, consistency)
    
    def calculate_feature_completeness(self, features: Dict[str, Any]) -> float:
        """Calculate confidence based on available features"""
        # Core feature categories and their importance
        feature_categories = {
            'timing': ['intervals', 'periodicity', 'jitter', 'avg_interval'],
            'size': ['packet_sizes', 'avg_packet_size', 'packet_variance'],
            'behavioral': ['user_agents', 'paths', 'request_count'],
            'statistical': ['entropy', 'variance', 'coefficient_of_variation'],
            'network': ['ports', 'protocols', 'headers'],
            'certificate': ['cert_size', 'self_signed', 'validity_days']
        }
        
        category_scores = {}
        for category, feature_list in feature_categories.items():
            available_features = sum(1 for feature in feature_list if feature in features)
            category_scores[category] = available_features / len(feature_list)
        
        # Weight categories by importance for C2 detection
        category_weights = {
            'timing': 0.25,      # Most important for C2 beaconing
            'behavioral': 0.20,  # Important for automated behavior
            'statistical': 0.20, # Important for pattern detection
            'size': 0.15,        # Useful for uniformity detection
            'network': 0.12,     # Supporting evidence
            'certificate': 0.08  # Additional context
        }
        
        weighted_completeness = sum(
            category_scores.get(cat, 0) * weight 
            for cat, weight in category_weights.items()
        )
        
        return min(1.0, weighted_completeness + 0.2)  # Base boost
    
    def calculate_temporal_confidence(self, timestamps: List[float], 
                                    detection_age_hours: float = 0) -> float:
        """Calculate confidence based on temporal patterns"""
        if not timestamps or len(timestamps) < 3:
            return 0.5
        
        # Analyze pattern duration
        duration = timestamps[-1] - timestamps[0]
        pattern_count = len(timestamps)
        
        # Longer patterns with more data points = higher confidence
        duration_confidence = min(1.0, duration / 3600)  # Normalize by hour
        count_confidence = min(1.0, pattern_count / 20)   # Normalize by count
        
        # Recent detections have higher confidence
        age_factor = math.exp(-detection_age_hours / 24)  # Decay over days
        
        temporal_confidence = (duration_confidence * 0.4 + 
                             count_confidence * 0.4 + 
                             age_factor * 0.2)
        
        return min(1.0, temporal_confidence)
    
    def calculate_behavioral_confidence(self, behavioral_features: Dict[str, Any]) -> float:
        """Calculate confidence based on behavioral indicators"""
        confidence_factors = []
        
        # Regularity in timing patterns
        if 'coefficient_of_variation' in behavioral_features:
            cov = behavioral_features['coefficient_of_variation']
            if cov < 0.3:  # Very regular = high confidence
                confidence_factors.append(0.9)
            elif cov < 0.5:  # Somewhat regular
                confidence_factors.append(0.7)
            else:
                confidence_factors.append(0.5)
        
        # Periodicity strength
        if 'periodicity' in behavioral_features:
            periodicity = behavioral_features['periodicity']
            confidence_factors.append(min(1.0, periodicity + 0.3))
        
        # Pattern consistency
        if 'uniform_packets' in behavioral_features:
            confidence_factors.append(0.8)
        
        # User agent consistency
        if 'user_agent_count' in behavioral_features:
            ua_count = behavioral_features['user_agent_count']
            if ua_count == 1:  # Single UA = automated behavior
                confidence_factors.append(0.9)
            elif ua_count <= 3:
                confidence_factors.append(0.7)
            else:
                confidence_factors.append(0.5)
        
        # Request frequency patterns
        if 'request_count' in behavioral_features:
            req_count = behavioral_features['request_count']
            if req_count > 50:  # High volume = higher confidence
                confidence_factors.append(0.8)
        
        return statistics.mean(confidence_factors) if confidence_factors else 0.5
    
    def calculate_correlation_confidence(self, correlation_data: Dict[str, Any]) -> float:
        """Calculate confidence based on detection correlations"""
        if not correlation_data:
            return 0.5
        
        # Number of correlated detection types
        correlation_types = correlation_data.get('correlation_types', [])
        type_diversity = len(set(correlation_types))
        
        # Base confidence from correlation diversity
        if type_diversity >= 3:
            base_confidence = 0.9
        elif type_diversity == 2:
            base_confidence = 0.8
        elif type_diversity == 1:
            base_confidence = 0.6
        else:
            base_confidence = 0.4
        
        # Correlation strength
        correlation_strength = correlation_data.get('correlation_strength', 0.0)
        strength_confidence = min(1.0, correlation_strength + 0.3)
        
        # Host correlation factor
        multi_host = correlation_data.get('multi_host_activity', False)
        host_factor = 1.1 if multi_host else 1.0
        
        return min(1.0, (base_confidence + strength_confidence) / 2 * host_factor)
    
    def calculate_statistical_confidence(self, statistical_metrics: Dict[str, float]) -> float:
        """Calculate confidence based on statistical significance"""
        confidence_factors = []
        
        # Entropy analysis confidence
        if 'entropy' in statistical_metrics:
            entropy = statistical_metrics['entropy']
            if entropy < 2.0 or entropy > 7.0:  # Extreme values are significant
                confidence_factors.append(0.8)
            else:
                confidence_factors.append(0.6)
        
        # Variance analysis confidence
        if 'variance' in statistical_metrics:
            variance = statistical_metrics['variance']
            if variance < 0.1:  # Very low variance = regular pattern
                confidence_factors.append(0.9)
            elif variance > 10:  # High variance might indicate randomization
                confidence_factors.append(0.7)
            else:
                confidence_factors.append(0.6)
        
        # Sample size confidence
        if 'sample_size' in statistical_metrics:
            sample_size = statistical_metrics['sample_size']
            size_confidence = min(1.0, sample_size / 50)  # Confidence increases with sample size
            confidence_factors.append(size_confidence)
        
        return statistics.mean(confidence_factors) if confidence_factors else 0.5
    
    def calculate_comprehensive_confidence(self, analysis_data: Dict[str, Any]) -> EnhancedConfidenceMetrics:
        """Calculate comprehensive confidence metrics"""
        warnings = []
        
        try:
            # Extract relevant data
            detection_scores = analysis_data.get('detection_scores', {})
            features = analysis_data.get('features', {})
            timestamps = analysis_data.get('timestamps', [])
            behavioral_features = analysis_data.get('behavioral_features', {})
            correlation_data = analysis_data.get('correlation_data', {})
            statistical_metrics = analysis_data.get('statistical_metrics', {})
            detection_age_hours = analysis_data.get('detection_age_hours', 0)
            
            # Calculate individual confidence components
            base_score = 0.6  # Base confidence level
            
            detection_consistency = self.calculate_detection_consistency(detection_scores)
            feature_completeness = self.calculate_feature_completeness(features)
            temporal_confidence = self.calculate_temporal_confidence(timestamps, detection_age_hours)
            behavioral_confidence = self.calculate_behavioral_confidence(behavioral_features)
            correlation_confidence = self.calculate_correlation_confidence(correlation_data)
            statistical_confidence = self.calculate_statistical_confidence(statistical_metrics)
            
            # Calculate weighted final score
            confidence_components = {
                'detection_consistency': detection_consistency,
                'feature_completeness': feature_completeness,
                'temporal_confidence': temporal_confidence,
                'behavioral_confidence': behavioral_confidence,
                'correlation_confidence': correlation_confidence,
                'statistical_confidence': statistical_confidence
            }
            
            final_score = base_score
            for component, score in confidence_components.items():
                weight = self.feature_weights.get(component, 0.1)
                final_score += (score - 0.5) * weight
            
            # Apply bounds and adjustments
            final_score = max(0.1, min(0.95, final_score))
            
            # Determine confidence level
            confidence_level = self._map_confidence_level(final_score)
            
            # Generate warnings for low confidence areas
            if detection_consistency < 0.5:
                warnings.append("Low detection consistency across methods")
            if feature_completeness < 0.4:
                warnings.append("Limited feature completeness")
            if temporal_confidence < 0.3:
                warnings.append("Insufficient temporal data")
            
            return EnhancedConfidenceMetrics(
                base_score=base_score,
                detection_consistency=detection_consistency,
                feature_completeness=feature_completeness,
                temporal_confidence=temporal_confidence,
                behavioral_confidence=behavioral_confidence,
                correlation_confidence=correlation_confidence,
                statistical_confidence=statistical_confidence,
                final_score=final_score,
                confidence_level=confidence_level,
                confidence_factors=confidence_components,
                warnings=warnings
            )
            
        except Exception as e:
            logger.error(f"Advanced confidence calculation failed: {e}")
            return self._create_default_confidence_metrics(warnings + [f"Calculation error: {e}"])
    
    def _map_confidence_level(self, score: float) -> str:
        """Map confidence score to descriptive level"""
        for level, threshold in self.confidence_thresholds.items():
            if score >= threshold:
                return level
        return 'LOW'
    
    def _create_default_confidence_metrics(self, warnings: List[str]) -> EnhancedConfidenceMetrics:
        """Create default confidence metrics for error cases"""
        return EnhancedConfidenceMetrics(
            base_score=0.3,
            detection_consistency=0.3,
            feature_completeness=0.3,
            temporal_confidence=0.3,
            behavioral_confidence=0.3,
            correlation_confidence=0.3,
            statistical_confidence=0.3,
            final_score=0.3,
            confidence_level='LOW',
            confidence_factors={},
            warnings=warnings
        )

