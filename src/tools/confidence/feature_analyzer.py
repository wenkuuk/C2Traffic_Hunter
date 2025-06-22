
#!/usr/bin/env python3
"""
Feature completeness analysis for confidence calculation
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class FeatureCompletenessAnalyzer:
    """Analyzer for feature completeness"""
    
    def __init__(self):
        # Core feature categories and their importance
        self.feature_categories = {
            'timing': ['intervals', 'periodicity', 'jitter', 'avg_interval'],
            'size': ['packet_sizes', 'avg_packet_size', 'packet_variance'],
            'behavioral': ['user_agents', 'paths', 'request_count'],
            'statistical': ['entropy', 'variance', 'coefficient_of_variation'],
            'network': ['ports', 'protocols', 'headers'],
            'certificate': ['cert_size', 'self_signed', 'validity_days']
        }
        
        # Weight categories by importance for C2 detection
        self.category_weights = {
            'timing': 0.25,      # Most important for C2 beaconing
            'behavioral': 0.20,  # Important for automated behavior
            'statistical': 0.20, # Important for pattern detection
            'size': 0.15,        # Useful for uniformity detection
            'network': 0.12,     # Supporting evidence
            'certificate': 0.08  # Additional context
        }
    
    def calculate_feature_completeness(self, features: Dict[str, Any]) -> float:
        """Calculate confidence based on available features"""
        category_scores = {}
        for category, feature_list in self.feature_categories.items():
            available_features = sum(1 for feature in feature_list if feature in features)
            category_scores[category] = available_features / len(feature_list)
        
        weighted_completeness = sum(
            category_scores.get(cat, 0) * weight 
            for cat, weight in self.category_weights.items()
        )
        
        return min(1.0, weighted_completeness + 0.2)  # Base boost
