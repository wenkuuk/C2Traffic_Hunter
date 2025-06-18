
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
from threat_assessor import ThreatAssessor
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
        ThreatAssessor.finalize_analysis(
            self.results, self.host_stats, 
            self.statistical_analyzer, self.behavioral_analyzer
        )

    def generate_threat_summary(self):
        """Generate overall threat assessment"""
        return ThreatAssessor.generate_threat_summary(self.results)

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
        
        # Generate threat summary
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
