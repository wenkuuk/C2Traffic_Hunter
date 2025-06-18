
#!/usr/bin/env python3
"""
Enhanced reporting module for advanced C2 traffic analysis
"""

from datetime import datetime


class EnhancedReporter:
    """Enhanced reporting with threat assessment"""
    
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
                'threat_score': threat_summary['threat_score']
            },
            'details': dict(results)
        }
        
        return report
    
    @staticmethod
    def print_detailed_report(report, verbose=False):
        """Enhanced console report with threat assessment"""
        print("\n" + "="*70)
        print("ADVANCED C2 TRAFFIC ANALYSIS REPORT")
        print("="*70)
        
        print(f"\nTHREAT ASSESSMENT: {report['summary']['threat_level']}")
        print(f"Threat Score: {report['summary']['threat_score']:.2f}")
        
        print(f"\nDETECTION SUMMARY:")
        print(f"  Suspicious hosts: {report['summary']['suspicious_hosts']}")
        print(f"  Beacon candidates: {report['summary']['beacon_candidates']}")
        print(f"  Suspicious requests: {report['summary']['suspicious_requests']}")
        print(f"  Signature detections: {report['summary']['signature_detections']}")
        print(f"  ML classifications: {report['summary']['ml_classifications']}")
        print(f"  Behavioral anomalies: {report['summary']['behavioral_anomalies']}")
        print(f"  Large file transfers: {report['summary']['file_transfers']}")
        print(f"  Statistical anomalies: {report['summary']['statistical_anomalies']}")
        
        if verbose and report['summary']['threat_level'] != 'LOW':
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
            
            # Show beaconing patterns
            if report['details']['beaconing_patterns']:
                print(f"\n[!] BEACONING PATTERNS:")
                print("-" * 50)
                for beacon in report['details']['beaconing_patterns']:
                    print(f"  Host: {beacon['host_key']}")
                    print(f"    Pattern: {beacon['pattern_type']}")
                    print(f"    Sessions: {beacon['session_count']}")
                    print(f"    Interval: {beacon['mean_interval']:.1f}s")
                    print(f"    Confidence: {beacon['confidence']:.2f}")
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
