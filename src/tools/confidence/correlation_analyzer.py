
#!/usr/bin/env python3
"""
Correlation confidence analysis
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class CorrelationConfidenceAnalyzer:
    """Analyzer for detection correlations confidence"""
    
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
