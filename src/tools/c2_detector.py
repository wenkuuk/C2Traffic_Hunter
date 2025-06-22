
#!/usr/bin/env python3
"""
Advanced C2 Traffic Detection System
Implements signature-based detection, ML feature extraction, and behavioral analysis
"""

import argparse
import json
from collections import defaultdict

try:
    from scapy.all import rdpcap
except ImportError:
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

from patterns import PatternDetector
from http_parser import HTTPParser
from statistical_analysis import StatisticalAnalyzer
from signatures import SignatureEngine
from ml_features import MLFeatureExtractor
from behavioral_analysis import BehavioralAnalyzer
from packet_analyzer import PacketAnalyzer
from enhanced_threat_assessor import EnhancedThreatAssessor
from enhanced_reporter import EnhancedReporter
from enhanced_statistical_analyzer import EnhancedStatisticalAnalyzer


class AdvancedC2Detector:
    def __init__(self):
        # Initialize all components
        self.pattern_detector = PatternDetector()
        self.http_parser = HTTPParser()
        self.statistical_analyzer = StatisticalAnalyzer()
        self.signature_engine = SignatureEngine()
        self.ml_extractor = MLFeatureExtractor()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.enhanced_threat_assessor = EnhancedThreatAssessor()
        self.enhanced_statistical_analyzer = EnhancedStatisticalAnalyzer()
        
        # Initialize packet analyzer with dependencies
        self.packet_analyzer = PacketAnalyzer(
            self.http_parser,
            self.statistical_analyzer, 
            self.pattern_detector,
            self.signature_engine,
            self.ml_extractor
        )
        
        # ... keep existing code (results and host_stats initialization)
        self.results = {
            'suspicious_hosts': defaultdict(list),
            'beacon_candidates': [],
            'suspicious_requests': [],
            'file_transfers': [],
            'statistical_anomalies': [],
            'signature_detections': [],
            'ml_classifications': [],
            'behavioral_anomalies': [],
            'beaconing_patterns': []
        }
        
        self.host_stats = defaultdict(lambda: {
            'request_count': 0,
            'intervals': [],
            'user_agents': set(),
            'paths': [],
            'response_sizes': [],
            'timestamps': [],
            'last_seen': None
        })

    def analyze_packet(self, packet):
        """Analyze individual packet for suspicious indicators"""
        self.packet_analyzer.analyze_packet(
            packet, self.results, self.behavioral_analyzer, self.host_stats
        )

    def finalize_analysis(self):
        """Enhanced final analysis with behavioral patterns and advanced statistics"""
        # Cross-reference detections by host for correlation analysis
        host_detection_map = {}
        
        # Enhanced beaconing analysis with advanced statistical methods
        for host_key, stats in self.host_stats.items():
            if len(stats['timestamps']) >= 3:
                # Use enhanced statistical analyzer for better beaconing detection
                intervals = []
                timestamps = sorted(stats['timestamps'])
                for i in range(1, len(timestamps)):
                    intervals.append(timestamps[i] - timestamps[i-1])
                
                if intervals:
                    # Advanced timing analysis
                    timing_analysis = self.enhanced_statistical_analyzer.analyze_timing_patterns(intervals)
                    
                    # Create enhanced beacon analysis
                    beacon_analysis = {
                        'host_key': host_key,
                        'timestamps': timestamps,
                        'intervals': intervals,
                        'duration': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
                        **timing_analysis
                    }
                    
                    # Determine if this is regular beaconing
                    is_regular = (
                        timing_analysis.get('high_periodicity', False) or
                        timing_analysis.get('very_regular', False) or
                        (timing_analysis.get('timing_cov', 1.0) < 0.3 and len(intervals) >= 5)
                    )
                    
                    beacon_analysis['is_regular'] = is_regular
                    
                    if is_regular:
                        # Enhanced correlation tracking
                        correlated_sigs = [d for d in self.results.get('signature_detections', []) 
                                         if d.get('session_data', {}).get('host', '') == host_key]
                        correlated_ml = [d for d in self.results.get('ml_classifications', []) 
                                       if d.get('session_data', {}).get('host', '') == host_key]
                        
                        beacon_analysis['correlated_detections'] = len(correlated_sigs) + len(correlated_ml)
                        beacon_analysis['correlation_types'] = []
                        if correlated_sigs:
                            beacon_analysis['correlation_types'].append('signature')
                        if correlated_ml:
                            beacon_analysis['correlation_types'].append('ml')
                        
                        # Calculate enhanced pattern strength
                        beacon_analysis['strength'] = self.enhanced_threat_assessor.pattern_analyzer.calculate_beaconing_strength(beacon_analysis)
                        
                        self.results['beacon_candidates'].append(beacon_analysis)
                        
                        # Track host detections
                        if host_key not in host_detection_map:
                            host_detection_map[host_key] = []
                        host_detection_map[host_key].append(('beaconing', beacon_analysis))
        
        # ... keep existing code (enhanced behavioral analysis)
        beaconing_patterns = self.behavioral_analyzer.analyze_beaconing()
        for pattern in beaconing_patterns:
            pattern['strength'] = self.enhanced_threat_assessor.pattern_analyzer.calculate_beaconing_strength(pattern)
        self.results['beaconing_patterns'] = beaconing_patterns
        
        communication_anomalies = self.behavioral_analyzer.analyze_communication_patterns()
        for anomaly in communication_anomalies:
            anomaly['anomaly_score'] = self.enhanced_threat_assessor.anomaly_analyzer.calculate_anomaly_strength(anomaly)
        self.results['behavioral_anomalies'] = communication_anomalies
        
        # Enhanced suspicious host detection with advanced statistical analysis
        for host_key, stats in self.host_stats.items():
            # Extract packet sizes and timing data for enhanced analysis
            packet_sizes = stats.get('response_sizes', [])
            timestamps = sorted(stats.get('timestamps', []))
            
            # Calculate intervals if we have timestamps
            intervals = []
            if len(timestamps) > 1:
                intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            # Perform enhanced statistical analysis
            packet_analysis = self.enhanced_statistical_analyzer.analyze_packet_uniformity(packet_sizes) if packet_sizes else {}
            timing_analysis = self.enhanced_statistical_analyzer.analyze_timing_patterns(intervals) if intervals else {}
            cert_analysis = {}  # Certificate analysis would go here if available
            
            # Calculate behavioral suspicion using enhanced methods
            behavioral_score = self.enhanced_statistical_analyzer.calculate_behavioral_score(
                packet_analysis, timing_analysis, cert_analysis
            )
            
            # Use existing suspicion indicators as base
            suspicion_indicators = self.statistical_analyzer.analyze_host_behavior(host_key, stats)
            
            if suspicion_indicators or behavioral_score > 0.3:
                # Enhanced correlation scoring
                correlation_data = {
                    'signature_matches': 0,
                    'ml_matches': 0,
                    'beaconing_matches': 0,
                    'behavioral_matches': 0,
                    'total_correlation_score': 0,
                    'behavioral_score': behavioral_score,
                    'packet_analysis': packet_analysis,
                    'timing_analysis': timing_analysis
                }
                
                # ... keep existing code (correlation counting logic)
                for detection in self.results.get('signature_detections', []):
                    if detection.get('session_data', {}).get('host', '') == host_key:
                        correlation_data['signature_matches'] += 1
                
                for detection in self.results.get('ml_classifications', []):
                    if detection.get('session_data', {}).get('host', '') == host_key:
                        correlation_data['ml_matches'] += 1
                
                for pattern in self.results.get('beaconing_patterns', []):
                    if pattern.get('host_key', '') == host_key:
                        correlation_data['beaconing_matches'] += 1
                
                for anomaly in self.results.get('behavioral_anomalies', []):
                    if anomaly.get('host_key', '') == host_key:
                        correlation_data['behavioral_matches'] += 1
                
                # Calculate weighted correlation score including behavioral score
                correlation_data['total_correlation_score'] = (
                    correlation_data['signature_matches'] * 0.3 +
                    correlation_data['ml_matches'] * 0.25 +
                    correlation_data['beaconing_matches'] * 0.2 +
                    correlation_data['behavioral_matches'] * 0.15 +
                    behavioral_score * 0.1
                )
                
                # Combine with existing suspicion indicators
                if not suspicion_indicators:
                    suspicion_indicators = {
                        'host_key': host_key,
                        'suspicion_score': behavioral_score,
                        'indicators': []
                    }
                else:
                    # Enhance existing suspicion score with behavioral analysis
                    existing_score = suspicion_indicators.get('suspicion_score', 0)
                    suspicion_indicators['suspicion_score'] = max(existing_score, behavioral_score)
                
                suspicion_indicators['correlation_data'] = correlation_data
                self.results['suspicious_hosts'][host_key] = suspicion_indicators
        
        return self.results

    def generate_threat_summary(self):
        """Generate overall threat assessment using enhanced assessor"""
        return self.enhanced_threat_assessor.generate_threat_assessment(self.results)

    def analyze_pcap(self, pcap_file: str):
        """Main analysis function"""
        print(f"[+] Loading PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            print(f"[+] Loaded {len(packets)} packets")
            
            for i, packet in enumerate(packets):
                if i % 1000 == 0:
                    print(f"[+] Processed {i} packets...")
                self.analyze_packet(packet)
            
            print("[+] Finalizing analysis...")
            self.finalize_analysis()
            
        except Exception as e:
            print(f"[-] Error reading PCAP file: {e}")
            return False
        
        return True

    def generate_report(self):
        """Generate enhanced analysis report with threat remediation"""
        # Convert sets to lists for JSON serialization
        for host_key, stats in self.host_stats.items():
            if isinstance(stats.get('user_agents'), set):
                stats['user_agents'] = list(stats['user_agents'])
        
        # Generate enhanced threat summary with remediation
        threat_summary = self.generate_threat_summary()
        
        # Generate comprehensive report including remediation
        report = EnhancedReporter.generate_report(
            self.results, self.host_stats, threat_summary
        )
        
        # Add remediation report if threats were detected
        if threat_summary and threat_summary.remediation_report:
            report['threat_remediation'] = threat_summary.remediation_report
            print("[+] Threat remediation plan generated")
        
        return report

    def print_detailed_report(self, report, verbose=False):
        """Enhanced console report with threat assessment and remediation"""
        EnhancedReporter.print_detailed_report(report, verbose)
        
        # Print remediation summary if available
        if 'threat_remediation' in report:
            remediation = report['threat_remediation']
            print("\n" + "="*60)
            print("THREAT REMEDIATION PLAN")
            print("="*60)
            print(f"Threat ID: {remediation['threat_id']}")
            print(f"Threat Type: {remediation['threat_type']}")
            print(f"Threat Level: {remediation['threat_level']}")
            print(f"Estimated Timeline: {remediation['estimated_total_time']}")
            
            if remediation['immediate_actions']:
                print(f"\nImmediate Actions Required: {len(remediation['immediate_actions'])}")
                for i, action in enumerate(remediation['immediate_actions'][:3], 1):
                    print(f"  {i}. {action['title']} (Priority: {action['priority']})")
            
            if remediation['short_term_actions']:
                print(f"\nShort-term Actions: {len(remediation['short_term_actions'])}")
            
            if remediation['long_term_actions']:
                print(f"Long-term Actions: {len(remediation['long_term_actions'])}")
            
            print(f"\nBusiness Impact: {remediation['business_impact_assessment']}")


def main():
    parser = argparse.ArgumentParser(description="Advanced C2 Traffic Detection System")
    parser.add_argument("pcap_file", help="Path to PCAP file to analyze")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--threshold", type=float, default=0.5, help="ML classification threshold")
    
    args = parser.parse_args()
    
    detector = AdvancedC2Detector()
    
    if detector.analyze_pcap(args.pcap_file):
        report = detector.generate_report()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {args.output}")
        
        if not args.output or args.verbose:
            detector.print_detailed_report(report, args.verbose)
        
        return 0
    else:
        print("[-] Analysis failed!")
        return 1


if __name__ == "__main__":
    exit(main())

