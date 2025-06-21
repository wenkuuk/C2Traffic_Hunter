
#!/usr/bin/env python3
"""
Advanced Confidence Calculation System v2.0
Enhanced with machine learning insights and temporal analysis
"""

import math
import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from contextlib import contextmanager

logger = logging.getLogger(__name__)

@dataclass
class AdvancedConfidenceMetrics:
    """Enhanced confidence calculation metrics"""
    base_score: float
    type_confidence: float
    recency_factor: float
    frequency_factor: float
    correlation_factor: float
    severity_factor: float
    reliability_factor: float
    context_factor: float
    temporal_consistency: float
    cross_validation_score: float
    final_score: float
    confidence_level: str
    warnings: List[str]
    quality_indicators: Dict[str, float]

class AdvancedTypeConfidenceCalculator:
    """Enhanced type-specific confidence calculations"""
    
    def __init__(self):
        self.type_config = {
            'signature': {
                'base': 0.4,
                'reliability_weight': 0.9,
                'false_positive_rate': 0.05
            },
            'ml': {
                'base': 0.0,  # Calculated from ML confidence
                'reliability_weight': 0.8,
                'model_uncertainty': 0.15
            },
            'behavioral': {
                'base': 0.25,
                'reliability_weight': 0.7,
                'baseline_quality_impact': 0.3
            },
            'beaconing': {
                'base': 0.3,
                'reliability_weight': 0.85,
                'pattern_strength_impact': 0.4
            }
        }
    
    def calculate(self, detection_type: str, metadata: Dict[str, Any]) -> float:
        """Enhanced type-specific confidence calculation"""
        config = self.type_config.get(detection_type, {
            'base': 0.2, 
            'reliability_weight': 0.6,
            'uncertainty': 0.2
        })
        
        base_confidence = config['base']
        
        if detection_type == 'ml':
            base_confidence = self._calculate_ml_confidence(metadata, config)
        elif detection_type == 'behavioral':
            base_confidence = self._calculate_behavioral_confidence(metadata, config)
        elif detection_type == 'beaconing':
            base_confidence = self._calculate_beaconing_confidence(metadata, config)
        elif detection_type == 'signature':
            base_confidence = self._calculate_signature_confidence(metadata, config)
        
        # Apply reliability adjustment
        reliability = metadata.get('source_reliability', 0.8)
        reliability_adjustment = config['reliability_weight'] + reliability * (1 - config['reliability_weight'])
        
        return base_confidence * reliability_adjustment
    
    def _calculate_ml_confidence(self, metadata: Dict[str, Any], config: Dict) -> float:
        """Advanced ML confidence calculation"""
        ml_confidence = metadata.get('ml_confidence', 0.5)
        model_accuracy = metadata.get('model_accuracy', 0.8)
        feature_quality = metadata.get('feature_quality', 0.7)
        
        # Model calibration
        calibrated_confidence = self._calibrate_ml_confidence(ml_confidence, model_accuracy)
        
        # Feature quality impact
        feature_impact = feature_quality * 0.3
        
        # Uncertainty adjustment
        uncertainty = config.get('model_uncertainty', 0.15)
        uncertainty_penalty = uncertainty * (1 - calibrated_confidence)
        
        final_confidence = (calibrated_confidence + feature_impact - uncertainty_penalty) * 0.45
        return max(0.1, min(0.9, final_confidence))
    
    def _calculate_behavioral_confidence(self, metadata: Dict[str, Any], config: Dict) -> float:
        """Enhanced behavioral confidence calculation"""
        base_conf = config['base']
        
        # Baseline quality impact
        baseline_quality = metadata.get('baseline_quality', 0.7)
        baseline_impact = config.get('baseline_quality_impact', 0.3)
        
        # Statistical significance
        statistical_significance = metadata.get('statistical_significance', 0.5)
        
        # Sample size adequacy
        sample_size = metadata.get('sample_size', 10)
        sample_adequacy = min(1.0, sample_size / 30)  # Adequate at 30+ samples
        
        confidence = (
            base_conf * (1 + baseline_quality * baseline_impact) *
            (0.8 + statistical_significance * 0.4) *
            (0.7 + sample_adequacy * 0.3)
        )
        
        return max(0.15, min(0.85, confidence))
    
    def _calculate_beaconing_confidence(self, metadata: Dict[str, Any], config: Dict) -> float:
        """Enhanced beaconing confidence calculation"""
        base_conf = config['base']
        
        # Pattern strength impact
        pattern_strength = metadata.get('pattern_strength', 0.5)
        strength_impact = config.get('pattern_strength_impact', 0.4)
        
        # Temporal consistency
        temporal_consistency = metadata.get('temporal_consistency', 0.6)
        
        # Duration factor
        duration_hours = metadata.get('duration_hours', 1)
        duration_factor = min(1.3, 1 + math.log(duration_hours + 1) * 0.1)
        
        confidence = (
            base_conf * (1 + pattern_strength * strength_impact) *
            (0.6 + temporal_consistency * 0.4) * duration_factor
        )
        
        return max(0.2, min(0.9, confidence))
    
    def _calculate_signature_confidence(self, metadata: Dict[str, Any], config: Dict) -> float:
        """Enhanced signature confidence calculation"""
        base_conf = config['base']
        
        # Signature quality
        signature_quality = metadata.get('signature_quality', 0.8)
        
        # False positive rate adjustment
        fp_rate = config.get('false_positive_rate', 0.05)
        fp_adjustment = 1 - fp_rate
        
        # Context relevance
        context_relevance = metadata.get('context_relevance', 0.8)
        
        confidence = base_conf * signature_quality * fp_adjustment * context_relevance
        
        return max(0.25, min(0.9, confidence))
    
    def _calibrate_ml_confidence(self, ml_confidence: float, model_accuracy: float) -> float:
        """Advanced ML confidence calibration"""
        # Platt scaling approximation
        calibration_factor = 0.3 + model_accuracy * 0.7
        
        # Apply sigmoid calibration
        calibrated = 1 / (1 + math.exp(-5 * (ml_confidence - 0.5)))
        
        return calibrated * calibration_factor

class AdvancedConfidenceCalculator:
    """Main advanced confidence calculation engine"""
    
    def __init__(self):
        self.type_calculator = AdvancedTypeConfidenceCalculator()
        
        # Enhanced configuration
        self.base_confidence = 0.4
        self.max_correlation_multiplier = 2.2
        self.temporal_decay_rate = math.log(2) / 24  # 50% decay in 24 hours
    
    def calculate_confidence(self, detection_data: Dict[str, Any]) -> AdvancedConfidenceMetrics:
        """Calculate comprehensive confidence metrics with advanced analysis"""
        warnings = []
        quality_indicators = {}
        
        try:
            # Extract and validate detection properties
            detection_type = detection_data.get('detection_type', 'unknown')
            severity = detection_data.get('severity', 5)
            timestamp = self._validate_timestamp(detection_data.get('timestamp'), warnings)
            metadata = detection_data.get('metadata', {})
            
            # Calculate individual factors with enhanced methods
            base_score = self._calculate_enhanced_base_score(metadata)
            type_confidence = self.type_calculator.calculate(detection_type, metadata)
            recency_factor = self._calculate_enhanced_recency_factor(timestamp)
            frequency_factor = self._calculate_enhanced_frequency_factor(metadata)
            correlation_factor = self._calculate_enhanced_correlation_factor(metadata)
            severity_factor = self._calculate_enhanced_severity_factor(severity, metadata)
            reliability_factor = metadata.get('source_reliability', 0.8)
            context_factor = self._calculate_enhanced_context_factor(metadata, timestamp)
            
            # New advanced factors
            temporal_consistency = self._calculate_temporal_consistency(metadata)
            cross_validation_score = self._calculate_cross_validation_score(metadata)
            
            # Quality indicators for transparency
            quality_indicators = {
                'data_completeness': self._assess_data_completeness(detection_data),
                'signal_strength': self._assess_signal_strength(metadata),
                'context_richness': self._assess_context_richness(metadata),
                'validation_coverage': self._assess_validation_coverage(metadata)
            }
            
            # Calculate final score with advanced weighting
            final_score = self._calculate_advanced_final_score(
                base_score, type_confidence, recency_factor, frequency_factor,
                correlation_factor, severity_factor, reliability_factor, context_factor,
                temporal_consistency, cross_validation_score, quality_indicators
            )
            
            # Determine confidence level with enhanced thresholds
            confidence_level = self._get_enhanced_confidence_level(final_score, quality_indicators)
            
            return AdvancedConfidenceMetrics(
                base_score=base_score,
                type_confidence=type_confidence,
                recency_factor=recency_factor,
                frequency_factor=frequency_factor,
                correlation_factor=correlation_factor,
                severity_factor=severity_factor,
                reliability_factor=reliability_factor,
                context_factor=context_factor,
                temporal_consistency=temporal_consistency,
                cross_validation_score=cross_validation_score,
                final_score=final_score,
                confidence_level=confidence_level,
                warnings=warnings,
                quality_indicators=quality_indicators
            )
            
        except Exception as e:
            logger.error(f"Advanced confidence calculation failed: {e}")
            return self._create_fallback_metrics(warnings + [f"Calculation error: {e}"])
    
    def _calculate_enhanced_correlation_factor(self, metadata: Dict[str, Any]) -> float:
        """Enhanced correlation factor with multiple correlation types"""
        correlation_count = metadata.get('correlated_detections', 0)
        correlation_types = metadata.get('correlation_types', [])
        
        if correlation_count == 0:
            return 1.0
        
        # Base correlation multiplier with logarithmic scaling
        base_multiplier = 1 + math.log(correlation_count + 1) * 0.15
        
        # Quality bonus for diverse correlation types
        type_diversity = len(set(correlation_types)) if correlation_types else 1
        diversity_bonus = min(0.25, type_diversity * 0.08)
        
        # Temporal correlation bonus
        temporal_correlation = metadata.get('temporal_correlation_strength', 0)
        temporal_bonus = temporal_correlation * 0.1
        
        # Cross-host correlation bonus
        cross_host_correlation = metadata.get('cross_host_correlation', 0)
        cross_host_bonus = min(0.15, cross_host_correlation * 0.05)
        
        total_factor = base_multiplier + diversity_bonus + temporal_bonus + cross_host_bonus
        
        return min(self.max_correlation_multiplier, total_factor)
    
    def _calculate_enhanced_frequency_factor(self, metadata: Dict[str, Any]) -> float:
        """Enhanced frequency factor with pattern analysis"""
        frequency = metadata.get('frequency', 1)
        time_window_hours = metadata.get('time_window_hours', 24.0)
        
        if frequency <= 1:
            return 1.0
        
        # Normalize by time window
        normalized_frequency = frequency / max(1, time_window_hours)
        
        # Optimal frequency range analysis
        if 0.1 <= normalized_frequency <= 10:  # 6 minutes to 10 hours
            frequency_quality = 1.2
        elif 0.01 <= normalized_frequency <= 50:  # 1.2 minutes to 4.2 days
            frequency_quality = 1.0
        else:
            frequency_quality = 0.8
        
        # Pattern regularity bonus
        frequency_regularity = metadata.get('frequency_regularity', 0.5)
        regularity_bonus = frequency_regularity * 0.2
        
        # Burst vs sustained pattern analysis
        burst_factor = metadata.get('burst_factor', 1.0)
        if burst_factor > 2:  # Bursty pattern
            burst_penalty = 0.1
        else:
            burst_penalty = 0
        
        frequency_boost = frequency_quality + regularity_bonus - burst_penalty
        return min(1.8, frequency_boost)
    
    def _calculate_temporal_consistency(self, metadata: Dict[str, Any]) -> float:
        """Calculate temporal consistency of detections"""
        timestamps = metadata.get('detection_timestamps', [])
        if len(timestamps) < 2:
            return 0.5
        
        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            if isinstance(timestamps[i], (int, float)) and isinstance(timestamps[i-1], (int, float)):
                intervals.append(timestamps[i] - timestamps[i-1])
        
        if not intervals:
            return 0.4
        
        # Consistency analysis
        if len(intervals) == 1:
            return 0.6
        
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return 0.3
        
        std_dev = statistics.stdev(intervals)
        cv = std_dev / mean_interval
        
        # Higher consistency for lower coefficient of variation
        consistency = max(0.2, 1 - min(cv, 2.0))
        
        # Bonus for long-term consistency
        if len(intervals) > 10:
            consistency *= 1.1
        
        return min(0.9, consistency)
    
    def _calculate_cross_validation_score(self, metadata: Dict[str, Any]) -> float:
        """Calculate cross-validation score from multiple detection methods"""
        validation_methods = metadata.get('validation_methods', [])
        validation_scores = metadata.get('validation_scores', {})
        
        if not validation_methods:
            return 0.3
        
        # Base score from method diversity
        method_diversity = len(set(validation_methods)) / 4.0  # Assume max 4 methods
        base_score = 0.4 + method_diversity * 0.3
        
        # Weighted average of validation scores
        if validation_scores:
            weighted_scores = []
            weights = {'signature': 0.3, 'ml': 0.3, 'behavioral': 0.2, 'statistical': 0.2}
            
            for method, score in validation_scores.items():
                weight = weights.get(method, 0.2)
                weighted_scores.append(score * weight)
            
            avg_validation = sum(weighted_scores) / max(len(weighted_scores), 1)
            validation_bonus = avg_validation * 0.4
        else:
            validation_bonus = 0.1
        
        return min(0.9, base_score + validation_bonus)
    
    def _calculate_advanced_final_score(self, base_score: float, type_confidence: float,
                                      recency_factor: float, frequency_factor: float,
                                      correlation_factor: float, severity_factor: float,
                                      reliability_factor: float, context_factor: float,
                                      temporal_consistency: float, cross_validation_score: float,
                                      quality_indicators: Dict[str, float]) -> float:
        """Advanced final score calculation with quality weighting"""
        
        # Core factors with updated weights
        core_factors = [type_confidence, recency_factor, frequency_factor, 
                       correlation_factor, severity_factor, reliability_factor, context_factor]
        core_weights = [0.22, 0.12, 0.10, 0.16, 0.10, 0.08, 0.08]
        
        # Advanced factors
        advanced_factors = [temporal_consistency, cross_validation_score]
        advanced_weights = [0.08, 0.06]
        
        # Calculate weighted geometric mean for stability
        total_weighted_product = 1.0
        
        for factor, weight in zip(core_factors + advanced_factors, core_weights + advanced_weights):
            total_weighted_product *= factor ** weight
        
        # Apply base score and quality adjustment
        quality_average = statistics.mean(quality_indicators.values()) if quality_indicators else 0.7
        quality_adjustment = 0.9 + quality_average * 0.2
        
        final_score = base_score * total_weighted_product * quality_adjustment
        
        # Apply bounds with soft limits
        if final_score < 0.1:
            return 0.1
        elif final_score > 0.95:
            return 0.95
        else:
            return final_score
    
    def _get_enhanced_confidence_level(self, score: float, quality_indicators: Dict[str, float]) -> str:
        """Enhanced confidence level determination with quality consideration"""
        # Quality-adjusted thresholds
        quality_avg = statistics.mean(quality_indicators.values()) if quality_indicators else 0.7
        
        # Adjust thresholds based on quality
        high_threshold = 0.75 - (1 - quality_avg) * 0.1
        medium_high_threshold = 0.6 - (1 - quality_avg) * 0.08
        medium_threshold = 0.4 - (1 - quality_avg) * 0.05
        low_threshold = 0.25
        
        if score >= high_threshold:
            return "VERY_HIGH"
        elif score >= medium_high_threshold:
            return "HIGH"
        elif score >= medium_threshold:
            return "MEDIUM"
        elif score >= low_threshold:
            return "LOW"
        else:
            return "VERY_LOW"
    
    # ... keep existing code (helper methods, assessment functions, etc.)
    
    def _validate_timestamp(self, timestamp, warnings: List[str]) -> datetime:
        """Validate and convert timestamp"""
        if not isinstance(timestamp, datetime):
            warnings.append("Invalid timestamp, using current time")
            return datetime.now()
        return timestamp
    
    def _calculate_enhanced_base_score(self, metadata: Dict[str, Any]) -> float:
        """Calculate enhanced base confidence score"""
        completeness = 0.6
        
        # Critical metadata fields
        critical_fields = ['source_reliability', 'detection_method', 'confidence_indicators', 'timestamp']
        for field in critical_fields:
            if field in metadata and metadata[field] is not None:
                completeness += 0.08
        
        # Optional enhancement fields
        optional_fields = ['context_data', 'validation_results', 'correlation_data']
        for field in optional_fields:
            if field in metadata and metadata[field]:
                completeness += 0.04
        
        return min(1.0, completeness)
    
    def _calculate_enhanced_recency_factor(self, timestamp: datetime) -> float:
        """Enhanced recency factor with configurable decay"""
        age_hours = (datetime.now() - timestamp).total_seconds() / 3600
        
        # Exponential decay with configurable rate
        recency_factor = math.exp(-self.temporal_decay_rate * age_hours)
        
        # Apply minimum threshold
        return max(0.15, recency_factor)
    
    def _calculate_enhanced_severity_factor(self, severity: int, metadata: Dict[str, Any]) -> float:
        """Enhanced severity factor calculation"""
        normalized_severity = max(1, min(10, severity)) / 10.0
        
        # Non-linear scaling for severity
        if normalized_severity >= 0.8:
            severity_factor = 0.85 + (normalized_severity - 0.8) * 0.75
        else:
            severity_factor = 0.4 + normalized_severity * 0.5625
        
        # Context-based adjustments
        threat_intelligence = metadata.get('threat_intel_match', False)
        if threat_intelligence:
            severity_factor *= 1.2
        
        impact_assessment = metadata.get('impact_score', 0.5)
        severity_factor *= (0.8 + impact_assessment * 0.4)
        
        return min(1.0, severity_factor)
    
    def _calculate_enhanced_context_factor(self, metadata: Dict[str, Any], timestamp: datetime) -> float:
        """Enhanced context factor calculation"""
        factors = []
        
        # Asset criticality with non-linear scaling
        asset_criticality = metadata.get('asset_criticality', 5) / 10.0
        asset_factor = 0.6 + asset_criticality * 0.8
        factors.append(asset_factor)
        
        # Enhanced business hours analysis
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        if 9 <= hour <= 17 and weekday < 5:  # Business hours
            time_factor = 1.0
        elif 6 <= hour <= 22 and weekday < 6:  # Extended hours
            time_factor = 0.9
        else:  # Off hours (more suspicious)
            time_factor = 1.2
        factors.append(time_factor)
        
        # Network context
        network_criticality = metadata.get('network_criticality', 1.0)
        network_factor = min(1.5, network_criticality)
        factors.append(network_factor)
        
        # User context
        user_risk = metadata.get('user_risk_score', 1.0)
        user_factor = min(1.4, user_risk)
        factors.append(user_factor)
        
        # Environmental context
        environment_risk = metadata.get('environment_risk', 0.5)
        env_factor = 0.8 + environment_risk * 0.6
        factors.append(env_factor)
        
        return statistics.mean(factors)
    
    def _assess_data_completeness(self, detection_data: Dict[str, Any]) -> float:
        """Assess completeness of detection data"""
        required_fields = ['detection_type', 'timestamp', 'severity']
        optional_fields = ['metadata', 'correlation_data', 'validation_results']
        
        required_score = sum(1 for field in required_fields if field in detection_data) / len(required_fields)
        optional_score = sum(1 for field in optional_fields if field in detection_data) / len(optional_fields)
        
        return (required_score * 0.7 + optional_score * 0.3)
    
    def _assess_signal_strength(self, metadata: Dict[str, Any]) -> float:
        """Assess signal strength from metadata"""
        indicators = []
        
        # Detection confidence
        detection_confidence = metadata.get('detection_confidence', 0.5)
        indicators.append(detection_confidence)
        
        # Signal-to-noise ratio
        snr = metadata.get('signal_noise_ratio', 1.0)
        snr_score = min(1.0, snr / 5.0)  # Normalize assuming good SNR is around 5
        indicators.append(snr_score)
        
        # Feature strength for ML detections
        feature_strength = metadata.get('feature_strength', 0.6)
        indicators.append(feature_strength)
        
        return statistics.mean(indicators)
    
    def _assess_context_richness(self, metadata: Dict[str, Any]) -> float:
        """Assess richness of contextual information"""
        context_elements = [
            'asset_context', 'network_context', 'user_context', 
            'temporal_context', 'threat_context'
        ]
        
        available_contexts = sum(1 for element in context_elements if element in metadata)
        richness_score = available_contexts / len(context_elements)
        
        # Bonus for high-quality context
        context_quality = metadata.get('context_quality_score', 0.7)
        return (richness_score * 0.7 + context_quality * 0.3)
    
    def _assess_validation_coverage(self, metadata: Dict[str, Any]) -> float:
        """Assess validation coverage across different methods"""
        validation_methods = metadata.get('validation_methods', [])
        validation_quality = metadata.get('validation_quality', {})
        
        coverage_score = len(validation_methods) / 4.0  # Assume 4 max validation methods
        
        if validation_quality:
            quality_avg = statistics.mean(validation_quality.values())
            return (coverage_score * 0.6 + quality_avg * 0.4)
        
        return coverage_score * 0.8  # Penalty for missing quality scores
    
    def _create_fallback_metrics(self, warnings: List[str]) -> AdvancedConfidenceMetrics:
        """Create fallback metrics when calculation fails"""
        return AdvancedConfidenceMetrics(
            base_score=0.3,
            type_confidence=0.3,
            recency_factor=0.5,
            frequency_factor=1.0,
            correlation_factor=1.0,
            severity_factor=0.5,
            reliability_factor=0.5,
            context_factor=0.5,
            temporal_consistency=0.3,
            cross_validation_score=0.3,
            final_score=0.25,
            confidence_level="LOW",
            warnings=warnings,
            quality_indicators={'overall': 0.3}
        )
