
#!/usr/bin/env python3
"""
Threat classification and level determination
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """Advanced threat classification system"""
    
    def __init__(self):
        # Advanced threat level thresholds with dynamic adjustment
        self.base_thresholds = {
            'CRITICAL': 0.80,
            'HIGH': 0.65,
            'MEDIUM-HIGH': 0.50,
            'MEDIUM': 0.35,
            'LOW-MEDIUM': 0.20,
            'LOW': 0.0
        }
    
    def determine_dynamic_threat_level(self, threat_score: float, 
                                     correlation_analysis: Dict[str, Any]) -> str:
        """Determine threat level with dynamic adjustment based on correlation"""
        correlation_confidence = correlation_analysis.get('correlation_confidence', 0.5)
        
        # Adjust thresholds based on correlation strength
        if correlation_confidence > 0.8:
            adjustment = -0.08  # Lower thresholds with strong correlation
        elif correlation_confidence > 0.6:
            adjustment = -0.04
        else:
            adjustment = 0.02   # Raise thresholds with weak correlation
        
        adjusted_thresholds = {
            level: threshold + adjustment 
            for level, threshold in self.base_thresholds.items()
        }
        
        for level, threshold in adjusted_thresholds.items():
            if threat_score >= threshold:
                return level
        
        return 'LOW'
    
    def assess_detection_sophistication(self, detections: Dict[str, int]) -> Dict[str, Any]:
        """Assess the sophistication of detected threats"""
        active_types = sum(1 for count in detections.values() if count > 0)
        total_detections = sum(detections.values())
        
        return {
            'detection_diversity': active_types,
            'detection_volume': total_detections,
            'sophistication_level': 'HIGH' if active_types >= 3 else 'MEDIUM' if active_types >= 2 else 'LOW'
        }
    
    def assess_pattern_complexity(self, statistical_analysis: Dict[str, Any]) -> float:
        """Assess the complexity of detected patterns"""
        complexity_score = 0.0
        
        if statistical_analysis.get('high_statistical_significance', False):
            complexity_score += 0.4
        
        pattern_entropy = statistical_analysis.get('pattern_entropy_avg', 0.0)
        if pattern_entropy > 0:
            complexity_score += min(0.3, pattern_entropy / 10)
        
        return min(1.0, complexity_score)
    
    def detect_evasion_techniques(self, behavioral_analysis: Dict[str, Any]) -> list[str]:
        """Detect specific evasion techniques"""
        evasion_techniques = []
        
        if behavioral_analysis.get('sophisticated_evasion', False):
            evasion_count = behavioral_analysis.get('evasion_indicator_count', 0)
            
            if evasion_count >= 3:
                evasion_techniques.append('Advanced multi-vector evasion')
            elif evasion_count >= 2:
                evasion_techniques.append('Moderate evasion techniques')
            else:
                evasion_techniques.append('Basic evasion detected')
        
        return evasion_techniques
