
#!/usr/bin/env python3
"""
Detection consistency analysis for confidence calculation
"""

import statistics
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class DetectionConsistencyAnalyzer:
    """Analyzer for detection method consistency"""
    
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
