
#!/usr/bin/env python3
"""
C2 Traffic Detection Script for PCAP Analysis
Analyzes HTTP traffic for potential Command and Control communications
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


class C2Detector:
    def __init__(self):
        self.pattern_detector = PatternDetector()
        self.http_parser = HTTPParser()
        self.statistical_analyzer = StatisticalAnalyzer()
        self.report_generator = ReportGenerator()
        
        self.results = {
            'suspicious_hosts': defaultdict(list),
            'beacon_candidates': [],
            'suspicious_requests': [],
            'file_transfers': [],
            'statistical_anomalies': []
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
            
            # Check if this is HTTP traffic (port 80, 8080, or non-standard ports with HTTP content)
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
            # Silently continue on packet parsing errors
            pass

    def analyze_http_request_packet(self, packet, payload: bytes):
        """Analyze HTTP request packet"""
        try:
            http_data = self.http_parser.parse_http_request(payload)
            if not http_data:
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            timestamp = float(packet.time)
            
            method = http_data.get('method', '')
            host = http_data.get('host', '')
            path = http_data.get('path', '')
            user_agent = http_data.get('user_agent', '')
            
            # Update host statistics
            host_key = f"{src_ip}->{dst_ip}:{host}"
            stats = self.host_stats[host_key]
            stats['request_count'] += 1
            stats['user_agents'].add(user_agent)
            stats['paths'].append(path)
            stats['timestamps'].append(timestamp)
            
            if stats['last_seen']:
                interval = timestamp - stats['last_seen']
                stats['intervals'].append(interval)
            stats['last_seen'] = timestamp
            
            # Calculate suspicion score
            suspicion_score, reasons = self.statistical_analyzer.calculate_suspicion_score(
                http_data, dst_port, self.pattern_detector
            )
            
            # Record suspicious requests
            if suspicion_score >= 2:
                self.results['suspicious_requests'].append({
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'host': host,
                    'method': method,
                    'path': path,
                    'user_agent': user_agent,
                    'suspicion_score': suspicion_score,
                    'reasons': reasons
                })
                
        except Exception as e:
            pass

    def analyze_http_response_packet(self, packet, payload: bytes):
        """Analyze HTTP response packet"""
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
        """Perform final analysis after processing all packets"""
        # Analyze beaconing patterns
        for host_key, stats in self.host_stats.items():
            if len(stats['timestamps']) >= 3:
                beacon_analysis = self.statistical_analyzer.analyze_beaconing(host_key, stats['timestamps'])
                if beacon_analysis and beacon_analysis.get('is_regular'):
                    self.results['beacon_candidates'].append(beacon_analysis)
        
        # Identify suspicious hosts
        for host_key, stats in self.host_stats.items():
            suspicion_indicators = self.statistical_analyzer.analyze_host_behavior(host_key, stats)
            if suspicion_indicators:
                self.results['suspicious_hosts'][host_key] = suspicion_indicators

    def analyze_pcap(self, pcap_file: str):
        """Main analysis function"""
        print(f"Loading PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            print(f"Loaded {len(packets)} packets")
            
            for i, packet in enumerate(packets):
                if i % 1000 == 0:
                    print(f"Processed {i} packets...")
                self.analyze_packet(packet)
            
            print("Finalizing analysis...")
            self.finalize_analysis()
            
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return False
        
        return True

    def generate_report(self):
        """Generate analysis report"""
        return self.report_generator.generate_report(self.results, self.host_stats)

    def print_detailed_report(self, report, verbose=False):
        """Print detailed console report"""
        self.report_generator.print_detailed_report(report, verbose)


def main():
    parser = argparse.ArgumentParser(description="C2 Traffic Detection in PCAP files")
    parser.add_argument("pcap_file", help="Path to PCAP file to analyze")
    parser.add_argument("-o", "--output", help="Output JSON file for results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    detector = C2Detector()
    
    if detector.analyze_pcap(args.pcap_file):
        report = detector.generate_report()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"Report saved to {args.output}")
        
        if not args.output or args.verbose:
            detector.print_detailed_report(report, args.verbose)
        
        return 0
    else:
        print("Analysis failed!")
        return 1


if __name__ == "__main__":
    exit(main())
