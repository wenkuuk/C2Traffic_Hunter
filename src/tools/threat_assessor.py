
#!/usr/bin/env python3
"""
Advanced threat assessment module for C2 traffic analysis
"""

import math
from datetime import datetime
from typing import Dict, List, Any, Optional


class ThreatAssessor:
    """Advanced threat scoring with multi-factor confidence analysis and temporal correlation"""

    # Enhanced configuration with temporal and correlation factors
    THREAT_WEIGHTS = {
        'signature_detections': {'base': 0.45, 'max_weight': 0.6},
        'ml_classifications': {'base': 0.35, 'max_weight': 0.5},
        'beaconing_patterns': {'base': 0.15, 'max_weight': 0.3},
        'behavioral_anomalies': {'base': 0.05, 'max_weight': 0.2}
    }
    
    # More sophisticated threat level classification
    THREAT_THRESHOLDS = {
        'CRITICAL': {'score': 0.8, 'confidence': 0.7},
        'HIGH': {'score': 0.6, 'confidence': 0.6},
        'MEDIUM-HIGH': {'score': 0.4, 'confidence': 0.5},
        'MEDIUM': {'score': 0.25, 'confidence': 0.4},
        'LOW-MEDIUM': {'score': 0.15, 'confidence': 0.3},
        'LOW': {'score': 0.0, 'confidence': 0.0}
    }
    
    @staticmethod
    def calculate_enhanced_confidence_score(detection: Dict[str, Any]) -> float:
        """Enhanced confidence calculation with multiple factors"""
        base_confidence = 0.5
        
        # Detection type confidence
        detection_type = detection.get('type', '')
        if detection_type == 'signature':
            base_confidence += 0.3
        elif detection_type == 'ml':
            ml_conf = detection.get('ml_confidence', 0.2)
            base_confidence += ml_conf * 0.4  # Scale ML confidence
        elif detection_type == 'behavioral':
            base_confidence += 0.25
        elif detection_type == 'beaconing':
            base_confidence += 0.2
        
        # Temporal recency factor (more recent = higher confidence)
        age_hours = detection.get('age_hours', 0)
        if age_hours <= 1:
            recency_factor = 1.0
        elif age_hours <= 24:
            recency_factor = 1 - (age_hours - 1) / 23 * 0.3  # 30% decay over 24h
        else:
            recency_factor = max(0.2, 1 - age_hours / 168 * 0.5)  # 50% decay over week
        
        base_confidence *= recency_factor
        
        # Frequency amplification (repeated detections increase confidence)
        frequency = detection.get('frequency', 1)
        if frequency > 1:
            freq_multiplier = min(1.8, 1 + math.log(frequency) * 0.2)
            base_confidence *= freq_multiplier
        
        # Correlation with other detection types
        correlated_detections = detection.get('correlated_detections', 0)
        correlation_types = detection.get('correlation_types', [])
        
        if correlated_detections > 0:
            # Higher correlation bonus for diverse detection types
            correlation_diversity = len(set(correlation_types)) / 4.0  # Max 4 types
            correlation_multiplier = 1 + (correlated_detections * 0.15 + correlation_diversity * 0.2)
            base_confidence *= min(2.0, correlation_multiplier)
        
        # Severity/criticality factor
        severity = detection.get('severity', 5)  # 1-10 scale
        severity_factor = 0.8 + (severity / 10) * 0.4  # Scale from 0.8 to 1.2
        base_confidence *= severity_factor
        
        # Source reliability factor
        source_reliability = detection.get('source_reliability', 0.8)  # 0-1 scale
        base_confidence *= source_reliability
        
        return min(1.0, max(0.1, base_confidence))
    
    @staticmethod
    def calculate_pattern_strength(pattern: Dict[str, Any]) -> float:
        """Calculate beaconing pattern strength based on timing consistency"""
        timestamps = pattern.get('timestamps', [])
        if len(timestamps) < 3:
            return 0.5
        
        # Calculate time intervals
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return 0.5
        
        # Statistical analysis of intervals
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance) if variance > 0 else 0
        
        # Coefficient of variation (lower = more regular)
        if mean_interval > 0:
            cv = std_dev / mean_interval
            regularity_score = max(0.3, 1 - cv)  # More regular = higher score
        else:
            regularity_score = 0.3
        
        # Duration factor (longer beaconing = higher threat)
        duration_hours = pattern.get('duration_hours', 1)
        duration_factor = min(1.5, 1 + math.log(duration_hours) * 0.1)
        
        # Frequency factor
        frequency_per_hour = pattern.get('frequency_per_hour', 1)
        frequency_factor = min(1.3, 1 + math.log(frequency_per_hour) * 0.05)
        
        strength = regularity_score * duration_factor * frequency_factor
        return min(1.0, max(0.3, strength))
    
    @staticmethod
    def calculate_anomaly_strength(anomaly: Dict[str, Any]) -> float:
        """Calculate behavioral anomaly strength"""
        baseline = anomaly.get('baseline', 0)
        current = anomaly.get('current', 0)
        
        if baseline == 0:
            return 0.7 if current > 0 else 0.3
        
        # Calculate relative deviation
        relative_deviation = abs(current - baseline) / baseline
        
        # Statistical significance (if available)
        z_score = anomaly.get('z_score', relative_deviation)
        
        # Convert to strength score (0-1)
        if z_score >= 3:
            strength = 0.9
        elif z_score >= 2:
            strength = 0.7
        elif z_score >= 1:
            strength = 0.5
        else:
            strength = max(0.2, z_score / 2)
        
        # Factor in persistence
        persistence_hours = anomaly.get('persistence_hours', 1)
        persistence_factor = min(1.4, 1 + math.log(persistence_hours) * 0.1)
        
        return min(1.0, strength * persistence_factor)

    @staticmethod
    def generate_threat_summary(results: Dict[str, List]) -> Dict[str, Any]:
        """Generate comprehensive threat assessment with advanced scoring"""
        
        # Initialize tracking variables
        component_scores = {}
        confidence_scores = {}
        detection_details = {}
        
        # Process signature detections
        sig_detections = results.get('signature_detections', [])
        if sig_detections:
            confidences = []
            for d in sig_detections:
                # Convert existing detection format to enhanced format
                enhanced_detection = {
                    'type': 'signature',
                    'severity': d.get('signature_score', 5),
                    'frequency': 1,
                    'age_hours': 0,  # Assume recent
                    'source_reliability': 0.9  # High reliability for signature matches
                }
                conf = ThreatAssessor.calculate_enhanced_confidence_score(enhanced_detection)
                confidences.append(conf)
            
            component_scores['signature'] = max(confidences) * ThreatAssessor.THREAT_WEIGHTS['signature_detections']['base']
            confidence_scores['signature'] = sum(confidences) / len(confidences)
            detection_details['signature'] = {
                'count': len(sig_detections),
                'max_confidence': max(confidences),
                'avg_confidence': sum(confidences) / len(confidences),
                'high_confidence_count': sum(1 for c in confidences if c > 0.7)
            }
        else:
            component_scores['signature'] = 0
            confidence_scores['signature'] = 0
            detection_details['signature'] = {'count': 0}
        
        # Process ML classifications
        ml_detections = results.get('ml_classifications', [])
        if ml_detections:
            ml_confidences = []
            for detection in ml_detections:
                enhanced_detection = {
                    'type': 'ml',
                    'ml_confidence': detection.get('ml_score', 0.5),
                    'severity': int(detection.get('ml_score', 0.5) * 10),
                    'frequency': 1,
                    'age_hours': 0,
                    'source_reliability': 0.8
                }
                enhanced_conf = ThreatAssessor.calculate_enhanced_confidence_score(enhanced_detection)
                original_conf = detection.get('ml_score', 0.5)
                # Combine enhanced confidence with original ML confidence
                combined_conf = (enhanced_conf + original_conf) / 2
                ml_confidences.append(combined_conf)
            
            component_scores['ml'] = max(ml_confidences) * ThreatAssessor.THREAT_WEIGHTS['ml_classifications']['base']
            confidence_scores['ml'] = sum(ml_confidences) / len(ml_confidences)
            detection_details['ml'] = {
                'count': len(ml_detections),
                'max_confidence': max(ml_confidences),
                'avg_confidence': sum(ml_confidences) / len(ml_confidences)
            }
        else:
            component_scores['ml'] = 0
            confidence_scores['ml'] = 0
            detection_details['ml'] = {'count': 0}
        
        # Process beaconing patterns
        beacon_patterns = results.get('beaconing_patterns', [])
        if beacon_patterns:
            beacon_strengths = []
            for pattern in beacon_patterns:
                if 'strength' not in pattern:
                    pattern['strength'] = ThreatAssessor.calculate_pattern_strength(pattern)
                beacon_strengths.append(pattern['strength'])
            
            component_scores['beaconing'] = max(beacon_strengths) * ThreatAssessor.THREAT_WEIGHTS['beaconing_patterns']['base']
            confidence_scores['beaconing'] = sum(beacon_strengths) / len(beacon_strengths)
            detection_details['beaconing'] = {
                'count': len(beacon_patterns),
                'max_strength': max(beacon_strengths),
                'avg_strength': sum(beacon_strengths) / len(beacon_strengths)
            }
        else:
            component_scores['beaconing'] = 0
            confidence_scores['beaconing'] = 0
            detection_details['beaconing'] = {'count': 0}
        
        # Process behavioral anomalies
        behavioral_anomalies = results.get('behavioral_anomalies', [])
        if behavioral_anomalies:
            anomaly_strengths = []
            for anomaly in behavioral_anomalies:
                if 'anomaly_score' not in anomaly:
                    anomaly['anomaly_score'] = ThreatAssessor.calculate_anomaly_strength(anomaly)
                anomaly_strengths.append(anomaly['anomaly_score'])
            
            component_scores['behavioral'] = max(anomaly_strengths) * ThreatAssessor.THREAT_WEIGHTS['behavioral_anomalies']['base']
            confidence_scores['behavioral'] = sum(anomaly_strengths) / len(anomaly_strengths)
            detection_details['behavioral'] = {
                'count': len(behavioral_anomalies),
                'max_strength': max(anomaly_strengths),
                'avg_strength': sum(anomaly_strengths) / len(anomaly_strengths)
            }
        else:
            component_scores['behavioral'] = 0
            confidence_scores['behavioral'] = 0
            detection_details['behavioral'] = {'count': 0}
        
        # Calculate composite scores
        raw_threat_score = sum(component_scores.values())
        overall_confidence = sum(confidence_scores.values()) / len([c for c in confidence_scores.values() if c > 0]) if any(confidence_scores.values()) else 0
        
        # Calculate correlation bonus
        active_detection_types = sum(1 for score in component_scores.values() if score > 0)
        correlation_bonus = ThreatAssessor._calculate_correlation_bonus(active_detection_types, results)
        
        # Apply correlation bonus and normalization
        final_threat_score = min(1.0, raw_threat_score + correlation_bonus)
        
        # Determine threat level with confidence consideration
        threat_level, confidence_level = ThreatAssessor._determine_threat_level(final_threat_score, overall_confidence)
        
        # Calculate risk assessment
        risk_factors = ThreatAssessor._assess_risk_factors(results, detection_details)
        
        return {
            'total_detections': sum(len(results.get(key, [])) for key in 
                                  ['signature_detections', 'ml_classifications', 
                                   'beaconing_patterns', 'behavioral_anomalies']),
            'detection_breakdown': {
                'signature_detections': len(results.get('signature_detections', [])),
                'ml_classifications': len(results.get('ml_classifications', [])),
                'beaconing_patterns': len(results.get('beaconing_patterns', [])),
                'behavioral_anomalies': len(results.get('behavioral_anomalies', []))
            },
            'component_scores': component_scores,
            'confidence_scores': confidence_scores,
            'detection_details': detection_details,
            'raw_threat_score': raw_threat_score,
            'correlation_bonus': correlation_bonus,
            'threat_score': final_threat_score,
            'threat_level': threat_level,
            'overall_confidence': overall_confidence,
            'confidence_level': confidence_level,
            'risk_factors': risk_factors,
            'assessment_metadata': {
                'active_detection_types': active_detection_types,
                'timestamp': datetime.now().isoformat(),
                'analysis_version': '2.0'
            }
        }
    
    @staticmethod
    def _calculate_correlation_bonus(active_types: int, results: Dict) -> float:
        """Calculate correlation bonus with enhanced logic"""
        if active_types <= 1:
            return 0.0
        
        base_bonus = {2: 0.05, 3: 0.12, 4: 0.20}.get(active_types, 0.20)
        
        # Additional bonus for high-confidence detections across types
        high_conf_bonus = 0.0
        total_detections = sum(len(results.get(key, [])) for key in 
                             ['signature_detections', 'ml_classifications', 
                              'beaconing_patterns', 'behavioral_anomalies'])
        
        if total_detections >= 5:
            high_conf_bonus = min(0.08, total_detections * 0.01)
        
        return base_bonus + high_conf_bonus
    
    @staticmethod
    def _determine_threat_level(threat_score: float, confidence: float) -> tuple:
        """Determine threat level considering both score and confidence"""
        # Primary classification based on threat score
        primary_level = "LOW"
        for level, thresholds in sorted(ThreatAssessor.THREAT_THRESHOLDS.items(), 
                                       key=lambda x: x[1]['score'], reverse=True):
            if threat_score >= thresholds['score']:
                primary_level = level
                break
        
        # Confidence level classification
        if confidence >= 0.8:
            confidence_level = "HIGH"
        elif confidence >= 0.6:
            confidence_level = "MEDIUM"
        elif confidence >= 0.4:
            confidence_level = "LOW-MEDIUM"
        else:
            confidence_level = "LOW"
        
        # Adjust threat level based on confidence
        if confidence < 0.4 and primary_level in ["CRITICAL", "HIGH"]:
            primary_level = "MEDIUM-HIGH"  # Downgrade high threats with low confidence
        elif confidence >= 0.8 and primary_level == "MEDIUM":
            primary_level = "MEDIUM-HIGH"  # Upgrade medium threats with high confidence
        
        return primary_level, confidence_level
    
    @staticmethod
    def _assess_risk_factors(results: Dict, detection_details: Dict) -> Dict:
        """Assess additional risk factors"""
        risk_factors = {
            'persistence': False,
            'lateral_movement': False,
            'data_exfiltration': False,
            'command_control': False,
            'privilege_escalation': False
        }
        
        # Check for persistence indicators
        beacon_count = detection_details.get('beaconing', {}).get('count', 0)
        behavioral_count = detection_details.get('behavioral', {}).get('count', 0)
        if beacon_count > 0 or behavioral_count >= 2:
            risk_factors['persistence'] = True
        
        # Check for command and control
        if beacon_count > 0:
            risk_factors['command_control'] = True
        
        # Check for potential data exfiltration
        sig_count = detection_details.get('signature', {}).get('count', 0)
        ml_count = detection_details.get('ml', {}).get('count', 0)
        if sig_count >= 3 or ml_count >= 2:
            risk_factors['data_exfiltration'] = True
        
        return risk_factors
    
    @staticmethod
    def finalize_analysis(results, host_stats, statistical_analyzer, behavioral_analyzer):
        """Enhanced final analysis with improved correlation and temporal analysis"""
        
        # Cross-reference detections by host for correlation analysis
        host_detection_map = {}
        
        # Enhanced beaconing analysis with correlation
        for host_key, stats in host_stats.items():
            if len(stats['timestamps']) >= 3:
                beacon_analysis = statistical_analyzer.analyze_beaconing(host_key, stats['timestamps'])
                if beacon_analysis and beacon_analysis.get('is_regular'):
                    # Enhanced correlation tracking
                    correlated_sigs = [d for d in results.get('signature_detections', []) 
                                     if d.get('session_data', {}).get('host', '') == host_key]
                    correlated_ml = [d for d in results.get('ml_classifications', []) 
                                   if d.get('session_data', {}).get('host', '') == host_key]
                    
                    beacon_analysis['correlated_detections'] = len(correlated_sigs) + len(correlated_ml)
                    beacon_analysis['correlation_types'] = []
                    if correlated_sigs:
                        beacon_analysis['correlation_types'].append('signature')
                    if correlated_ml:
                        beacon_analysis['correlation_types'].append('ml')
                    
                    # Calculate pattern strength
                    beacon_analysis['strength'] = ThreatAssessor.calculate_pattern_strength(beacon_analysis)
                    
                    results['beacon_candidates'].append(beacon_analysis)
                    
                    # Track host detections
                    if host_key not in host_detection_map:
                        host_detection_map[host_key] = []
                    host_detection_map[host_key].append(('beaconing', beacon_analysis))
        
        # Enhanced behavioral analysis
        beaconing_patterns = behavioral_analyzer.analyze_beaconing()
        for pattern in beaconing_patterns:
            pattern['strength'] = ThreatAssessor.calculate_pattern_strength(pattern)
        results['beaconing_patterns'] = beaconing_patterns
        
        # Enhanced communication anomaly detection
        communication_anomalies = behavioral_analyzer.analyze_communication_patterns()
        for anomaly in communication_anomalies:
            anomaly['anomaly_score'] = ThreatAssessor.calculate_anomaly_strength(anomaly)
        results['behavioral_anomalies'] = communication_anomalies
        
        # Enhanced suspicious host detection with multi-factor correlation
        for host_key, stats in host_stats.items():
            suspicion_indicators = statistical_analyzer.analyze_host_behavior(host_key, stats)
            if suspicion_indicators:
                # Enhanced correlation scoring
                correlation_data = {
                    'signature_matches': 0,
                    'ml_matches': 0,
                    'beaconing_matches': 0,
                    'behavioral_matches': 0,
                    'total_correlation_score': 0
                }
                
                # Count correlations by type
                for detection in results.get('signature_detections', []):
                    if detection.get('session_data', {}).get('host', '') == host_key:
                        correlation_data['signature_matches'] += 1
                
                for detection in results.get('ml_classifications', []):
                    if detection.get('session_data', {}).get('host', '') == host_key:
                        correlation_data['ml_matches'] += 1
                
                for pattern in results.get('beaconing_patterns', []):
                    if pattern.get('host_key', '') == host_key:
                        correlation_data['beaconing_matches'] += 1
                
                for anomaly in results.get('behavioral_anomalies', []):
                    if anomaly.get('host_key', '') == host_key:
                        correlation_data['behavioral_matches'] += 1
                
                # Calculate weighted correlation score
                correlation_data['total_correlation_score'] = (
                    correlation_data['signature_matches'] * 0.4 +
                    correlation_data['ml_matches'] * 0.3 +
                    correlation_data['beaconing_matches'] * 0.2 +
                    correlation_data['behavioral_matches'] * 0.1
                )
                
                suspicion_indicators['correlation_data'] = correlation_data
                results['suspicious_hosts'][host_key] = suspicion_indicators
        
        return results

    @staticmethod
    def compare_scoring_methods(sample_results):
        """Compare enhanced scoring with detailed breakdown"""
        enhanced = ThreatAssessor.generate_threat_summary(sample_results)
        
        print("Enhanced Threat Assessment:")
        print(f"  Threat Score: {enhanced['threat_score']:.3f}")
        print(f"  Threat Level: {enhanced['threat_level']}")
        print(f"  Overall Confidence: {enhanced['overall_confidence']:.3f}")
        print(f"  Confidence Level: {enhanced['confidence_level']}")
        print(f"  Correlation Bonus: {enhanced['correlation_bonus']:.3f}")
        print(f"  Component Scores:")
        for component, score in enhanced['component_scores'].items():
            print(f"    {component}: {score:.3f}")
        print(f"  Risk Factors: {enhanced['risk_factors']}")
        
        return enhanced
