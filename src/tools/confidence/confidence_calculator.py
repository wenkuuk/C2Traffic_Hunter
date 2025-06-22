
#!/usr/bin/env python3
"""
Advanced confidence calculation system with enhanced C2 detection techniques
"""

import statistics
import logging
from typing import Dict, Any, List
from dataclasses import dataclass

from .detection_analyzer import DetectionConsistencyAnalyzer
from .feature_analyzer import FeatureCompletenessAnalyzer
from .temporal_analyzer import TemporalConfidenceAnalyzer
from .behavioral_analyzer import BehavioralConfidenceAnalyzer
from .correlation_analyzer import CorrelationConfidenceAnalyzer
from .statistical_analyzer import StatisticalConfidenceAnalyzer

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
        
        # Initialize analyzers
        self.detection_analyzer = DetectionConsistencyAnalyzer()
        self.feature_analyzer = FeatureCompletenessAnalyzer()
        self.temporal_analyzer = TemporalConfidenceAnalyzer()
        self.behavioral_analyzer = BehavioralConfidenceAnalyzer()
        self.correlation_analyzer = CorrelationConfidenceAnalyzer()
        self.statistical_analyzer = StatisticalConfidenceAnalyzer()
    
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
            
            detection_consistency = self.detection_analyzer.calculate_detection_consistency(detection_scores)
            feature_completeness = self.feature_analyzer.calculate_feature_completeness(features)
            temporal_confidence = self.temporal_analyzer.calculate_temporal_confidence(timestamps, detection_age_hours)
            behavioral_confidence = self.behavioral_analyzer.calculate_behavioral_confidence(behavioral_features)
            correlation_confidence = self.correlation_analyzer.calculate_correlation_confidence(correlation_data)
            statistical_confidence = self.statistical_analyzer.calculate_statistical_confidence(statistical_metrics)
            
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
