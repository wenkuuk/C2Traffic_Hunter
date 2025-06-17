
#!/usr/bin/env python3
"""
Advanced C2 Traffic Detection System
Implements signature-based detection, ML feature extraction, and behavioral analysis
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

from patterns import PatternDetector
from http_parser import HTTPParser
from statistical_analysis import StatisticalAnalyzer
from reporting import ReportGenerator
from signatures import SignatureEngine
from ml_features import MLFeatureExtractor
from behavioral_analysis import BehavioralAnalyzer


class AdvancedC2Detector:
    def __init__(self):
        # Original components
        self.pattern_detector = PatternDetector()
        self.http_parser = HTTPParser()
        self.statistical_analyzer = StatisticalAnalyzer()
        self.report_generator = ReportGenerator()
        
        # New advanced components
        self.signature_engine = SignatureEngine()
        self.ml_extractor = MLFeatureExtractor()
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        self.results = {
            'suspicious_hosts': defaultdict(list),
            'beacon_candidates': [],
            'suspicious_requests': [],
            'file_transfers': [],
            'statistical_anomalies': [],
            # New advanced results
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
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                return
                
            tcp_layer = packet[TCP]
            
            # Check if this is HTTP traffic
            is_http_port = tcp_layer.dport in [80, 8080] or tcp_layer.sport in [80, 8080]
            
            if not packet.haslayer(Raw):
                return
                
            payload = packet[Raw].load
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Check if it's HTTP traffic by content or port
            if not is_http_port and not self.http_parser.is_http_traffic(payload_str):
                return
            
            # Try to determine if this is HTTP request or response
            if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                self.analyze_http_request_packet(packet, payload)
            elif payload_str.startswith('HTTP/'):
                self.analyze_http_response_packet(packet, payload)
                
        except Exception as e:
            pass

    def analyze_http_request_packet(self, packet, payload: bytes):
        """Enhanced HTTP request packet analysis"""
        try:
            http_data = self.http_parser.parse_http_request(payload)
            if not http_data:
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            timestamp = float(packet.time)
            
            # Create session data for advanced analysis
            session_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'timestamp': timestamp,
                'method': http_data.get('method', ''),
                'host': http_data.get('host', ''),
                'path': http_data.get('path', ''),
                'user_agent': http_data.get('user_agent', ''),
                'headers': http_data.get('headers', {}),
                'request_size': len(payload),
                'response_size': 0,  # Will be updated if response is found
                'response_code': '',
                'session_duration': 0,
                'request_interval': 0
            }
            
            # Update host statistics
            host_key = f"{src_ip}->{dst_ip}:{http_data.get('host', '')}"
            stats = self.host_stats[host_key]
            stats['request_count'] += 1
            stats['user_agents'].add(http_data.get('user_agent', ''))
            stats['paths'].append(http_data.get('path', ''))
            stats['timestamps'].append(timestamp)
            
            if stats['last_seen']:
                interval = timestamp - stats['last_seen']
                stats['intervals'].append(interval)
                session_data['request_interval'] = interval
            stats['last_seen'] = timestamp
            
            # Add session to behavioral analyzer
            self.behavioral_analyzer.add_session(session_data)
            
            # Original suspicion scoring
            suspicion_score, reasons = self.statistical_analyzer.calculate_suspicion_score(
                http_data, dst_port, self.pattern_detector
            )
            
            # Advanced signature-based detection
            sig_score, sig_matches = self.signature_engine.detect_signatures(session_data, payload)
            if sig_score > 0:
                self.results['signature_detections'].append({
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'session_data': session_data,
                    'signature_score': sig_score,
                    'signature_matches': sig_matches
                })
                suspicion_score += sig_score
                reasons.extend(sig_matches)
            
            # ML feature extraction and classification
            features = self.ml_extractor.extract_features(session_data, payload)
            ml_score, ml_reason = self.ml_extractor.classify_session(features)
            
            if ml_score > 0.5:  # Threshold for suspicious classification
                self.results['ml_classifications'].append({
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'session_data': session_data,
                    'ml_score': ml_score,
                    'ml_reason': ml_reason,
                    'features': features
                })
                suspicion_score += int(ml_score * 5)  # Convert to integer scale
                reasons.append(f"ML classification: {ml_reason}")
            
            # Record suspicious requests (enhanced criteria)
            if suspicion_score >= 2 or sig_score > 0 or ml_score > 0.5:
                self.results['suspicious_requests'].append({
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'host': http_data.get('host', ''),
                    'method': http_data.get('method', ''),
                    'path': http_data.get('path', ''),
                    'user_agent': http_data.get('user_agent', ''),
                    'suspicion_score': suspicion_score,
                    'signature_score': sig_score,
                    'ml_score': ml_score,
                    'reasons': reasons
                })
                
        except Exception as e:
            pass

    def analyze_http_response_packet(self, packet, payload: bytes):
        """Analyze HTTP response packet"""
        # ... keep existing code (HTTP response analysis)
        try:
            http_data = self.http_parser.parse_http_response(payload)
            if not http_data:
                return
                
            # Check response size for potential file transfers
            content_length = http_data.get('content_length', 0)
            body_entropy = self.pattern_detector.calculate_entropy(http_data.get('body', ''))
            
            if content_length > 10000:  # Large responses
                self.results['file_transfers'].append({
                    'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'size': content_length,
                    'entropy': body_entropy,
                    'status_code': http_data.get('status_code', '')
                })
            
            # Check for suspicious response patterns
            if body_entropy > 7.0 and content_length > 1000:  # High entropy content
                self.results['statistical_anomalies'].append({
                    'type': 'high_entropy_response',
                    'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'entropy': body_entropy,
                    'size': content_length
                })
                    
        except Exception as e:
            pass

    def finalize_analysis(self):
        """Enhanced final analysis with behavioral patterns"""
        # Original beaconing analysis
        for host_key, stats in self.host_stats.items():
            if len(stats['timestamps']) >= 3:
                beacon_analysis = self.statistical_analyzer.analyze_beaconing(host_key, stats['timestamps'])
                if beacon_analysis and beacon_analysis.get('is_regular'):
                    self.results['beacon_candidates'].append(beacon_analysis)
        
        # Enhanced behavioral analysis
        beaconing_patterns = self.behavioral_analyzer.analyze_beaconing()
        self.results['beaconing_patterns'] = beaconing_patterns
        
        communication_anomalies = self.behavioral_analyzer.analyze_communication_patterns()
        self.results['behavioral_anomalies'] = communication_anomalies
        
        # Original suspicious hosts analysis
        for host_key, stats in self.host_stats.items():
            suspicion_indicators = self.statistical_analyzer.analyze_host_behavior(host_key, stats)
            if suspicion_indicators:
                self.results['suspicious_hosts'][host_key] = suspicion_indicators

    def generate_threat_summary(self):
        """Generate overall threat assessment"""
        total_detections = (
            len(self.results['signature_detections']) +
            len(self.results['ml_classifications']) +
            len(self.results['beaconing_patterns']) +
            len(self.results['behavioral_anomalies'])
        )
        
        # Calculate threat level
        threat_score = 0
        if len(self.results['signature_detections']) > 0:
            threat_score += 0.4
        if len(self.results['ml_classifications']) > 0:
            threat_score += 0.3
        if len(self.results['beaconing_patterns']) > 0:
            threat_score += 0.2
        if len(self.results['behavioral_anomalies']) > 0:
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
            'signature_detections': len(self.results['signature_detections']),
            'ml_classifications': len(self.results['ml_classifications']),
            'beaconing_patterns': len(self.results['beaconing_patterns']),
            'behavioral_anomalies': len(self.results['behavioral_anomalies']),
            'threat_score': threat_score,
            'threat_level': threat_level
        }

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
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'suspicious_hosts': len(self.results['suspicious_hosts']),
                'beacon_candidates': len(self.results['beacon_candidates']),
                'suspicious_requests': len(self.results['suspicious_requests']),
                'file_transfers': len(self.results['file_transfers']),
                'statistical_anomalies': len(self.results['statistical_anomalies']),
                # Enhanced summary
                'signature_detections': len(self.results['signature_detections']),
                'ml_classifications': len(self.results['ml_classifications']),
                'behavioral_anomalies': len(self.results['behavioral_anomalies']),
                'beaconing_patterns': len(self.results['beaconing_patterns']),
                'threat_level': threat_summary['threat_level'],
                'threat_score': threat_summary['threat_score']
            },
            'details': dict(self.results)  # Convert defaultdict to regular dict
        }
        
        return report

    def print_detailed_report(self, report, verbose=False):
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
        
        # ... keep existing code (rest of the report display)
        if report['details']['beacon_candidates']:
            print(f"\n[!] Potential Beaconing Activity:")
            print("-" * 40)
            for beacon in report['details']['beacon_candidates']:
                print(f"  Host: {beacon['host']}")
                print(f"    Requests: {beacon['request_count']}")
                print(f"    Avg interval: {beacon['avg_interval']:.2f}s")
                print(f"    Regularity score: {1-beacon['coefficient_of_variation']:.2f}")
        
        print("\n" + "="*70)


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
