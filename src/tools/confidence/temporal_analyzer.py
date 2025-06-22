
#!/usr/bin/env python3
"""
Temporal confidence analysis
"""

import math
import logging
from typing import List

logger = logging.getLogger(__name__)

class TemporalConfidenceAnalyzer:
    """Analyzer for temporal patterns confidence"""
    
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
