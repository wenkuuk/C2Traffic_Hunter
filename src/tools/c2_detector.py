
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
        
        # Initialize packet analyzer with dependencies
        self.packet_analyzer = PacketAnalyzer(
            self.http_parser,
            self.statistical_analyzer, 
            self.pattern_detector,
            self.signature_engine,
            self.ml_extractor
        )
        
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
        """Enhanced final analysis with behavioral patterns"""
        # Cross-reference detections by host for correlation analysis
        host_detection_map = {}
        
        # Enhanced beaconing analysis with correlation
        for host_key, stats in self.host_stats.items():
            if len(stats['timestamps']) >= 3:
                beacon_analysis = self.statistical_analyzer.analyze_beaconing(host_key, stats['timestamps'])
                if beacon_analysis and beacon_analysis.get('is_regular'):
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
                    
                    # Calculate pattern strength using enhanced assessor
                    beacon_analysis['strength'] = self.enhanced_threat_assessor.pattern_analyzer.calculate_beaconing_strength(beacon_analysis)
                    
                    self.results['beacon_candidates'].append(beacon_analysis)
                    
                    # Track host detections
                    if host_key not in host_detection_map:
                        host_detection_map[host_key] = []
                    host_detection_map[host_key].append(('beaconing', beacon_analysis))
        
        # Enhanced behavioral analysis
        beaconing_patterns = self.behavioral_analyzer.analyze_beaconing()
        for pattern in beaconing_patterns:
            pattern['strength'] = self.enhanced_threat_assessor.pattern_analyzer.calculate_beaconing_strength(pattern)
        self.results['beaconing_patterns'] = beaconing_patterns
        
        # Enhanced communication anomaly detection
        communication_anomalies = self.behavioral_analyzer.analyze_communication_patterns()
        for anomaly in communication_anomalies:
            anomaly['anomaly_score'] = self.enhanced_threat_assessor.anomaly_analyzer.calculate_anomaly_strength(anomaly)
        self.results['behavioral_anomalies'] = communication_anomalies
        
        # Enhanced suspicious host detection with multi-factor correlation
        for host_key, stats in self.host_stats.items():
            suspicion_indicators = self.statistical_analyzer.analyze_host_behavior(host_key, stats)
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
                
                # Calculate weighted correlation score
                correlation_data['total_correlation_score'] = (
                    correlation_data['signature_matches'] * 0.4 +
                    correlation_data['ml_matches'] * 0.3 +
                    correlation_data['beaconing_matches'] * 0.2 +
                    correlation_data['behavioral_matches'] * 0.1
                )
                
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
        """Generate enhanced analysis report"""
        # Convert sets to lists for JSON serialization
        for host_key, stats in self.host_stats.items():
            if isinstance(stats.get('user_agents'), set):
                stats['user_agents'] = list(stats['user_agents'])
        
        # Generate enhanced threat summary
        threat_summary = self.generate_threat_summary()
        
        return EnhancedReporter.generate_report(
            self.results, self.host_stats, threat_summary
        )

    def print_detailed_report(self, report, verbose=False):
        """Enhanced console report with threat assessment"""
        EnhancedReporter.print_detailed_report(report, verbose)


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
