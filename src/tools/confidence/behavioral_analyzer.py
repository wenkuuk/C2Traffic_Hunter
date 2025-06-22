
#!/usr/bin/env python3
"""
Behavioral confidence analysis
"""

import statistics
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class BehavioralConfidenceAnalyzer:
    """Analyzer for behavioral indicators confidence"""
    
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
