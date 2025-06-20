
#!/usr/bin/env python3
"""
Enhanced confidence calculation system
"""

import math
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from contextlib import contextmanager
import statistics

logger = logging.getLogger(__name__)

@dataclass
class ConfidenceMetrics:
    """Detailed confidence calculation metrics"""
    base_score: float
    type_confidence: float
    recency_factor: float
    frequency_factor: float
    correlation_factor: float
    severity_factor: float
    reliability_factor: float
    context_factor: float
    final_score: float
    confidence_level: str
    warnings: List[str]

class ConfidenceCalculationError(Exception):
    """Confidence calculation error"""
    pass

class TypeConfidenceCalculator:
    """Type-specific confidence calculations"""
    
    def __init__(self):
        self.type_config = {
            'signature': {
                'base': 0.35,
                'reliability_weight': 0.9
            },
            'ml': {
                'base': 0.0,  # Calculated from ML confidence
                'reliability_weight': 0.8
            },
            'behavioral': {
                'base': 0.28,
                'reliability_weight': 0.7
            },
            'beaconing': {
                'base': 0.25,
                'reliability_weight': 0.8
            }
        }
    
    def calculate(self, detection_type: str, metadata: Dict[str, Any]) -> float:
        """Calculate type-specific confidence"""
        config = self.type_config.get(detection_type, {'base': 0.2, 'reliability_weight': 0.6})
        base_confidence = config['base']
        
        if detection_type == 'ml':
            ml_confidence = metadata.get('ml_confidence', 0.5)
            model_accuracy = metadata.get('model_accuracy', 0.8)
            
            # Calibrate ML confidence
            calibrated_confidence = self._calibrate_ml_confidence(ml_confidence, model_accuracy)
            base_confidence = calibrated_confidence * 0.4
        
        # Apply reliability weight
        reliability = metadata.get('source_reliability', 0.8)
        return base_confidence * (config['reliability_weight'] + reliability * 0.2)
    
    def _calibrate_ml_confidence(self, ml_confidence: float, model_accuracy: float) -> float:
        """Calibrate ML confidence based on model performance"""
        calibration_factor = 0.5 + (model_accuracy - 0.5)
        return ml_confidence * calibration_factor

class RecencyCalculator:
    """Calculate recency-based confidence factors"""
    
    def __init__(self, half_life_hours: float = 12.0):
        self.half_life_hours = half_life_hours
        self.decay_rate = math.log(2) / half_life_hours
    
    def calculate(self, timestamp: datetime) -> float:
        """Calculate recency factor with exponential decay"""
        age_hours = (datetime.now() - timestamp).total_seconds() / 3600
        
        # Exponential decay
        recency_factor = math.exp(-self.decay_rate * age_hours)
        
        # Apply minimum threshold
        return max(0.1, recency_factor)

class FrequencyCalculator:
    """Calculate frequency-based confidence factors"""
    
    def calculate(self, frequency: int, time_window_hours: float = 24.0) -> float:
        """Calculate frequency factor with logarithmic scaling"""
        if frequency <= 1:
            return 1.0
        
        # Normalize by time window
        normalized_frequency = frequency / max(1, time_window_hours)
        
        # Logarithmic scaling with diminishing returns
        frequency_boost = 1 + math.log(normalized_frequency + 1) * 0.15
        
        return min(1.8, frequency_boost)

class EnhancedConfidenceCalculator:
    """Main confidence calculation engine"""
    
    def __init__(self):
        self.type_calculator = TypeConfidenceCalculator()
        self.recency_calculator = RecencyCalculator()
        self.frequency_calculator = FrequencyCalculator()
        
        # Configuration
        self.base_confidence = 0.5
        self.max_correlation_multiplier = 2.5
    
    def calculate_confidence(self, detection_data: Dict[str, Any]) -> ConfidenceMetrics:
        """Calculate comprehensive confidence metrics"""
        warnings = []
        
        try:
            # Extract detection properties
            detection_type = detection_data.get('detection_type', 'unknown')
            severity = detection_data.get('severity', 5)
            timestamp = detection_data.get('timestamp', datetime.now())
            metadata = detection_data.get('metadata', {})
            
            # Validate inputs
            if not isinstance(timestamp, datetime):
                timestamp = datetime.now()
                warnings.append("Invalid timestamp, using current time")
            
            # Calculate individual factors
            base_score = self._calculate_base_score(metadata)
            type_confidence = self.type_calculator.calculate(detection_type, metadata)
            recency_factor = self.recency_calculator.calculate(timestamp)
            frequency_factor = self.frequency_calculator.calculate(
                metadata.get('frequency', 1)
            )
            correlation_factor = self._calculate_correlation_factor(
                metadata.get('correlated_detections', 0),
                metadata.get('correlation_types', [])
            )
            severity_factor = self._calculate_severity_factor(severity, metadata)
            reliability_factor = metadata.get('source_reliability', 0.8)
            context_factor = self._calculate_context_factor(metadata, timestamp)
            
            # Calculate final score
            final_score = self._calculate_final_score(
                base_score, type_confidence, recency_factor, frequency_factor,
                correlation_factor, severity_factor, reliability_factor, context_factor
            )
            
            # Determine confidence level
            confidence_level = self._get_confidence_level(final_score)
            
            return ConfidenceMetrics(
                base_score=base_score,
                type_confidence=type_confidence,
                recency_factor=recency_factor,
                frequency_factor=frequency_factor,
                correlation_factor=correlation_factor,
                severity_factor=severity_factor,
                reliability_factor=reliability_factor,
                context_factor=context_factor,
                final_score=final_score,
                confidence_level=confidence_level,
                warnings=warnings
            )
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {e}")
            raise ConfidenceCalculationError(f"Failed to calculate confidence: {e}")
    
    def _calculate_base_score(self, metadata: Dict[str, Any]) -> float:
        """Calculate base confidence score"""
        completeness = 0.7  # Base score
        
        # Boost for complete metadata
        important_fields = ['source_reliability', 'detection_method', 'confidence_indicators']
        for field in important_fields:
            if field in metadata:
                completeness += 0.1
        
        return min(1.0, completeness)
    
    def _calculate_correlation_factor(self, correlation_count: int, correlation_types: List[str]) -> float:
        """Calculate correlation confidence factor"""
        if correlation_count == 0:
            return 1.0
        
        # Base multiplier
        base_multiplier = 1 + (correlation_count * 0.12)
        
        # Quality bonus for diverse correlation types
        type_diversity = len(set(correlation_types)) if correlation_types else 1
        diversity_bonus = min(0.3, type_diversity * 0.08)
        
        return min(self.max_correlation_multiplier, base_multiplier + diversity_bonus)
    
    def _calculate_severity_factor(self, severity: int, metadata: Dict[str, Any]) -> float:
        """Calculate severity-based confidence factor"""
        # Normalize severity (1-10 scale)
        normalized_severity = max(1, min(10, severity)) / 10.0
        
        # Non-linear scaling for high severity
        if normalized_severity >= 0.8:
            severity_factor = 0.9 + (normalized_severity - 0.8) * 0.5
        else:
            severity_factor = 0.5 + normalized_severity * 0.5
        
        # Threat intelligence boost
        if metadata.get('threat_intel_match', False):
            severity_factor *= 1.15
        
        return min(1.0, severity_factor)
    
    def _calculate_context_factor(self, metadata: Dict[str, Any], timestamp: datetime) -> float:
        """Calculate context-based confidence factor"""
        factors = []
        
        # Asset criticality
        asset_criticality = metadata.get('asset_criticality', 5) / 10.0
        factors.append(asset_criticality)
        
        # Business hours factor
        is_business_hours = 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5
        business_factor = 1.2 if is_business_hours else 0.9
        factors.append(business_factor)
        
        # Network segment criticality
        network_criticality = metadata.get('network_criticality', 1.0)
        factors.append(min(2.0, network_criticality))
        
        # User risk score
        user_risk = metadata.get('user_risk_score', 1.0)
        factors.append(min(2.0, user_risk))
        
        # Calculate weighted average
        return statistics.mean(factors)
    
    def _calculate_final_score(self, base_score: float, type_confidence: float, 
                             recency_factor: float, frequency_factor: float,
                             correlation_factor: float, severity_factor: float,
                             reliability_factor: float, context_factor: float) -> float:
        """Calculate final confidence score"""
        # Weighted combination
        factors = [type_confidence, recency_factor, frequency_factor, 
                  correlation_factor, severity_factor, reliability_factor, context_factor]
        weights = [0.25, 0.15, 0.12, 0.18, 0.12, 0.08, 0.10]
        
        # Calculate weighted geometric mean for stability
        weighted_product = 1.0
        for factor, weight in zip(factors, weights):
            weighted_product *= factor ** weight
        
        # Apply base score
        final_score = base_score * weighted_product
        
        # Apply bounds
        return max(0.1, min(0.95, final_score))
    
    def _get_confidence_level(self, score: float) -> str:
        """Map confidence score to level"""
        if score >= 0.8:
            return "VERY_HIGH"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "VERY_LOW"
