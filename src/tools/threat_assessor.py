
#!/usr/bin/env python3
"""
Enhanced threat assessment module for C2 traffic analysis
"""

import math
from datetime import datetime


class ThreatAssessor:
    """Enhanced threat scoring with improved accuracy"""
    
    # Configurable weights and severity multipliers
    THREAT_WEIGHTS = {
        'signature_detections': {'base': 0.4, 'severity_multiplier': 1.5},
        'ml_classifications': {'base': 0.3, 'confidence_multiplier': 1.2},
        'beaconing_patterns': {'base': 0.2, 'regularity_multiplier': 1.3},
        'behavioral_anomalies': {'base': 0.1, 'anomaly_multiplier': 1.1}
    }
    
    # More granular threat levels
    THREAT_THRESHOLDS = {
        'CRITICAL': 0.85,
        'HIGH': 0.65,
        'MEDIUM-HIGH': 0.45,
        'MEDIUM': 0.25,
        'LOW-MEDIUM': 0.15,
        'LOW': 0.0
    }
    
    @staticmethod
    def calculate_weighted_score(detections, detection_type):
        """Calculate weighted score based on quantity and severity"""
        if not detections:
            return 0.0
        
        config = ThreatAssessor.THREAT_WEIGHTS[detection_type]
        base_weight = config['base']
        
        # Quantity factor: logarithmic scaling to prevent score explosion
        quantity_factor = min(1.0 + math.log(len(detections)) * 0.2, 2.0)
        
        # Severity/confidence factor based on detection type
        severity_factor = 1.0
        if detection_type == 'signature_detections':
            severity_factor = ThreatAssessor._calculate_signature_severity(detections)
        elif detection_type == 'ml_classifications':
            severity_factor = ThreatAssessor._calculate_ml_confidence(detections)
        elif detection_type == 'beaconing_patterns':
            severity_factor = ThreatAssessor._calculate_beaconing_severity(detections)
        elif detection_type == 'behavioral_anomalies':
            severity_factor = ThreatAssessor._calculate_anomaly_severity(detections)
        
        return base_weight * quantity_factor * severity_factor
    
    @staticmethod
    def _calculate_signature_severity(detections):
        """Calculate severity based on signature criticality"""
        if not detections:
            return 1.0
        
        severity_sum = 0
        for detection in detections:
            # Use signature_score as severity indicator (fallback to 5)
            severity = detection.get('signature_score', 5) if isinstance(detection, dict) else 5
            severity_sum += severity
        
        avg_severity = severity_sum / len(detections)
        return 0.5 + (avg_severity / 10.0)  # Scale to 0.5-1.5
    
    @staticmethod
    def _calculate_ml_confidence(detections):
        """Calculate factor based on ML confidence scores"""
        if not detections:
            return 1.0
        
        confidence_sum = 0
        for detection in detections:
            # Use ml_score as confidence indicator (fallback to 0.5)
            confidence = detection.get('ml_score', 0.5) if isinstance(detection, dict) else 0.5
            confidence_sum += confidence
        
        avg_confidence = confidence_sum / len(detections)
        return 0.7 + (avg_confidence * 0.8)  # Scale to 0.7-1.5
    
    @staticmethod
    def _calculate_beaconing_severity(patterns):
        """Calculate severity based on beaconing characteristics"""
        if not patterns:
            return 1.0
        
        severity_factors = []
        for pattern in patterns:
            # Extract pattern characteristics with fallbacks
            if isinstance(pattern, dict):
                regularity = 1 - pattern.get('coefficient_variation', 0.5)  # Convert CV to regularity
                duration = pattern.get('duration', 3600) / 3600  # Convert to hours
                frequency = pattern.get('session_count', 1) / max(duration, 1)  # Sessions per hour
            else:
                regularity = 0.5
                duration = 1
                frequency = 1
            
            # More regular, longer duration, higher frequency = higher threat
            factor = regularity * min(duration / 24, 2.0) * min(frequency / 60, 2.0)
            severity_factors.append(factor)
        
        avg_factor = sum(severity_factors) / len(severity_factors)
        return 0.6 + min(avg_factor, 0.9)  # Scale to 0.6-1.5
    
    @staticmethod
    def _calculate_anomaly_severity(anomalies):
        """Calculate severity based on anomaly strength"""
        if not anomalies:
            return 1.0
        
        severity_sum = 0
        for anomaly in anomalies:
            # Use confidence as deviation indicator (fallback to 1.0)
            deviation = anomaly.get('confidence', 1.0) if isinstance(anomaly, dict) else 1.0
            severity_sum += min(deviation * 5, 5.0)  # Scale and cap at 5
        
        avg_deviation = severity_sum / len(anomalies)
        return 0.5 + (avg_deviation / 10.0)  # Scale to 0.5-1.0
    
    @staticmethod
    def generate_threat_summary(results):
        """Generate enhanced threat assessment with improved scoring"""
        # Calculate weighted scores for each category
        signature_score = ThreatAssessor.calculate_weighted_score(
            results.get('signature_detections', []), 'signature_detections'
        )
        
        ml_score = ThreatAssessor.calculate_weighted_score(
            results.get('ml_classifications', []), 'ml_classifications'
        )
        
        beaconing_score = ThreatAssessor.calculate_weighted_score(
            results.get('beaconing_patterns', []), 'beaconing_patterns'
        )
        
        behavioral_score = ThreatAssessor.calculate_weighted_score(
            results.get('behavioral_anomalies', []), 'behavioral_anomalies'
        )
        
        # Calculate composite threat score
        raw_threat_score = signature_score + ml_score + beaconing_score + behavioral_score
        
        # Apply normalization and correlation factors
        correlation_bonus = ThreatAssessor._calculate_correlation_bonus(results)
        normalized_score = min(raw_threat_score + correlation_bonus, 1.0)
        
        # Determine threat level with more granular categories
        threat_level = "LOW"
        for level, threshold in sorted(ThreatAssessor.THREAT_THRESHOLDS.items(), 
                                     key=lambda x: x[1], reverse=True):
            if normalized_score >= threshold:
                threat_level = level
                break
        
        # Calculate confidence in assessment
        confidence = ThreatAssessor._calculate_assessment_confidence(results)
        
        return {
            'total_detections': sum(len(results.get(key, [])) for key in 
                                  ['signature_detections', 'ml_classifications', 
                                   'beaconing_patterns', 'behavioral_anomalies']),
            'signature_detections': len(results.get('signature_detections', [])),
            'ml_classifications': len(results.get('ml_classifications', [])),
            'beaconing_patterns': len(results.get('beaconing_patterns', [])),
            'behavioral_anomalies': len(results.get('behavioral_anomalies', [])),
            'component_scores': {
                'signature_score': signature_score,
                'ml_score': ml_score,
                'beaconing_score': beaconing_score,
                'behavioral_score': behavioral_score
            },
            'raw_threat_score': raw_threat_score,
            'threat_score': normalized_score,
            'threat_level': threat_level,
            'assessment_confidence': confidence,
            'correlation_bonus': correlation_bonus
        }
    
    @staticmethod
    def _calculate_correlation_bonus(results):
        """Calculate bonus score for correlated indicators"""
        categories_with_detections = sum(1 for key in 
            ['signature_detections', 'ml_classifications', 'beaconing_patterns', 'behavioral_anomalies']
            if results.get(key, []))
        
        # Bonus for multiple detection types (suggests coordinated attack)
        if categories_with_detections >= 3:
            return 0.15
        elif categories_with_detections >= 2:
            return 0.08
        else:
            return 0.0
    
    @staticmethod
    def _calculate_assessment_confidence(results):
        """Calculate confidence in the threat assessment"""
        total_indicators = sum(len(results.get(key, [])) for key in 
                             ['signature_detections', 'ml_classifications', 
                              'beaconing_patterns', 'behavioral_anomalies'])
        
        # Higher confidence with more indicators and diverse detection types
        base_confidence = min(total_indicators * 0.1, 0.7)
        
        diversity_bonus = len([key for key in 
                             ['signature_detections', 'ml_classifications', 
                              'beaconing_patterns', 'behavioral_anomalies']
                             if results.get(key, [])]) * 0.075
        
        return min(base_confidence + diversity_bonus, 1.0)

    @staticmethod
    def finalize_analysis(results, host_stats, statistical_analyzer, behavioral_analyzer):
        """Enhanced final analysis with behavioral patterns"""
        # Original beaconing analysis
        for host_key, stats in host_stats.items():
            if len(stats['timestamps']) >= 3:
                beacon_analysis = statistical_analyzer.analyze_beaconing(host_key, stats['timestamps'])
                if beacon_analysis and beacon_analysis.get('is_regular'):
                    results['beacon_candidates'].append(beacon_analysis)
        
        # Enhanced behavioral analysis
        beaconing_patterns = behavioral_analyzer.analyze_beaconing()
        results['beaconing_patterns'] = beaconing_patterns
        
        communication_anomalies = behavioral_analyzer.analyze_communication_patterns()
        results['behavioral_anomalies'] = communication_anomalies
        
        # Original suspicious hosts analysis
        for host_key, stats in host_stats.items():
            suspicion_indicators = statistical_analyzer.analyze_host_behavior(host_key, stats)
            if suspicion_indicators:
                results['suspicious_hosts'][host_key] = suspicion_indicators

    @staticmethod
    def compare_scoring_methods(sample_results):
        """Compare enhanced scoring with detailed breakdown"""
        enhanced = ThreatAssessor.generate_threat_summary(sample_results)
        
        print("Enhanced Threat Assessment:")
        print(f"  Threat Score: {enhanced['threat_score']:.3f}")
        print(f"  Threat Level: {enhanced['threat_level']}")
        print(f"  Assessment Confidence: {enhanced['assessment_confidence']:.3f}")
        print(f"  Correlation Bonus: {enhanced['correlation_bonus']:.3f}")
        print(f"  Component Scores:")
        for component, score in enhanced['component_scores'].items():
            print(f"    {component}: {score:.3f}")
        
        return enhanced
