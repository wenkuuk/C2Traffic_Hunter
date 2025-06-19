
#!/usr/bin/env python3
"""
Enhanced reporting module for advanced C2 traffic analysis
"""

from datetime import datetime


class EnhancedReporter:
    """Enhanced reporting with detailed threat assessment"""
    
    @staticmethod
    def generate_report(results, host_stats, threat_summary):
        """Generate enhanced analysis report"""
        # Convert sets to lists for JSON serialization
        for host_key, stats in host_stats.items():
            if isinstance(stats.get('user_agents'), set):
                stats['user_agents'] = list(stats['user_agents'])
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'suspicious_hosts': len(results['suspicious_hosts']),
                'beacon_candidates': len(results['beacon_candidates']),
                'suspicious_requests': len(results['suspicious_requests']),
                'file_transfers': len(results['file_transfers']),
                'statistical_anomalies': len(results['statistical_anomalies']),
                'signature_detections': len(results['signature_detections']),
                'ml_classifications': len(results['ml_classifications']),
                'behavioral_anomalies': len(results['behavioral_anomalies']),
                'beaconing_patterns': len(results['beaconing_patterns']),
                'threat_level': threat_summary['threat_level'],
                'threat_score': threat_summary['threat_score'],
                'assessment_confidence': threat_summary.get('assessment_confidence', 0),
                'correlation_bonus': threat_summary.get('correlation_bonus', 0),
                'component_scores': threat_summary.get('component_scores', {})
            },
            'details': dict(results)
        }
        
        return report
    
    @staticmethod
    def print_detailed_report(report, verbose=False):
        """Enhanced console report with detailed threat assessment"""
        print("\n" + "="*70)
        print("ADVANCED C2 TRAFFIC ANALYSIS REPORT")
        print("="*70)
        
        summary = report['summary']
        
        print(f"\nTHREAT ASSESSMENT: {summary['threat_level']}")
        print(f"Threat Score: {summary['threat_score']:.3f}")
        print(f"Assessment Confidence: {summary.get('assessment_confidence', 0):.3f}")
        if summary.get('correlation_bonus', 0) > 0:
            print(f"Correlation Bonus: +{summary['correlation_bonus']:.3f}")
        
        # Display component scores breakdown
        component_scores = summary.get('component_scores', {})
        if component_scores:
            print(f"\nCOMPONENT SCORES:")
            for component, score in component_scores.items():
                component_name = component.replace('_', ' ').title()
                print(f"  {component_name}: {score:.3f}")
        
        print(f"\nDETECTION SUMMARY:")
        print(f"  Suspicious hosts: {summary['suspicious_hosts']}")
        print(f"  Beacon candidates: {summary['beacon_candidates']}")
        print(f"  Suspicious requests: {summary['suspicious_requests']}")
        print(f"  Signature detections: {summary['signature_detections']}")
        print(f"  ML classifications: {summary['ml_classifications']}")
        print(f"  Behavioral anomalies: {summary['behavioral_anomalies']}")
        print(f"  Beaconing patterns: {summary['beaconing_patterns']}")
        print(f"  Large file transfers: {summary['file_transfers']}")
        print(f"  Statistical anomalies: {summary['statistical_anomalies']}")
        
        if verbose and summary['threat_level'] not in ['LOW', 'LOW-MEDIUM']:
            # Show signature detections
            if report['details']['signature_detections']:
                print(f"\n[!] SIGNATURE DETECTIONS:")
                print("-" * 50)
                for detection in report['details']['signature_detections'][:5]:
                    session = detection['session_data']
                    print(f"  {session['src_ip']} -> {session['dst_ip']}")
                    print(f"    Host: {session['host']}")
                    print(f"    Path: {session['path']}")
                    print(f"    Score: {detection['signature_score']}")
                    print(f"    Matches: {', '.join(detection['signature_matches'])}")
                    print()
            
            # Show ML classifications
            if report['details']['ml_classifications']:
                print(f"\n[!] ML CLASSIFICATIONS:")
                print("-" * 50)
                for classification in report['details']['ml_classifications'][:5]:
                    session = classification['session_data']
                    print(f"  {session['src_ip']} -> {session['dst_ip']}")
                    print(f"    Host: {session['host']}")
                    print(f"    ML Score: {classification['ml_score']:.2f}")
                    print(f"    Reason: {classification['ml_reason']}")
                    print()
            
            # Show beaconing patterns with enhanced details
            if report['details']['beaconing_patterns']:
                print(f"\n[!] BEACONING PATTERNS:")
                print("-" * 50)
                for beacon in report['details']['beaconing_patterns']:
                    print(f"  Host: {beacon['host_key']}")
                    print(f"    Pattern: {beacon['pattern_type']}")
                    print(f"    Sessions: {beacon['session_count']}")
                    print(f"    Interval: {beacon['mean_interval']:.1f}s")
                    print(f"    Regularity: {beacon['confidence']:.2f}")
                    if beacon.get('duration'):
                        print(f"    Duration: {beacon['duration']:.0f}s")
                    print()
            
            # Show behavioral anomalies with details
            if report['details']['behavioral_anomalies']:
                print(f"\n[!] BEHAVIORAL ANOMALIES:")
                print("-" * 50)
                for anomaly in report['details']['behavioral_anomalies']:
                    print(f"  Host: {anomaly['host_key']}")
                    print(f"    Type: {anomaly['anomaly_type']}")
                    print(f"    Confidence: {anomaly['confidence']:.2f}")
                    if 'count' in anomaly:
                        print(f"    Count: {anomaly['count']}")
                    if 'unique_ratio' in anomaly:
                        print(f"    Unique Ratio: {anomaly['unique_ratio']:.2f}")
                    print()
        
        if report['details']['beacon_candidates']:
            print(f"\n[!] Potential Beaconing Activity:")
            print("-" * 40)
            for beacon in report['details']['beacon_candidates']:
                print(f"  Host: {beacon['host']}")
                print(f"    Requests: {beacon['request_count']}")
                print(f"    Avg interval: {beacon['avg_interval']:.2f}s")
                print(f"    Regularity score: {1-beacon['coefficient_of_variation']:.2f}")
        
        print("\n" + "="*70)
