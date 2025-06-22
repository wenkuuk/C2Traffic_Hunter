
#!/usr/bin/env python3
"""
Statistical confidence analysis
"""

import statistics
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class StatisticalConfidenceAnalyzer:
    """Analyzer for statistical significance confidence"""
    
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
