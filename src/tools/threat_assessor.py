
#!/usr/bin/env python3
"""
Threat assessment module for C2 traffic analysis
"""

from datetime import datetime


class ThreatAssessor:
    """Handles threat scoring and assessment"""
    
    @staticmethod
    def generate_threat_summary(results):
        """Generate overall threat assessment"""
        total_detections = (
            len(results['signature_detections']) +
            len(results['ml_classifications']) +
            len(results['beaconing_patterns']) +
            len(results['behavioral_anomalies'])
        )
        
        # Calculate threat level
        threat_score = 0
        if len(results['signature_detections']) > 0:
            threat_score += 0.4
        if len(results['ml_classifications']) > 0:
            threat_score += 0.3
        if len(results['beaconing_patterns']) > 0:
            threat_score += 0.2
        if len(results['behavioral_anomalies']) > 0:
            threat_score += 0.1
        
        threat_level = "LOW"
        if threat_score > 0.7:
            threat_level = "CRITICAL"
        elif threat_score > 0.5:
            threat_level = "HIGH"
        elif threat_score > 0.3:
            threat_level = "MEDIUM"
        
        return {
            'total_detections': total_detections,
            'signature_detections': len(results['signature_detections']),
            'ml_classifications': len(results['ml_classifications']),
            'beaconing_patterns': len(results['beaconing_patterns']),
            'behavioral_anomalies': len(results['behavioral_anomalies']),
            'threat_score': threat_score,
            'threat_level': threat_level
        }
    
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
