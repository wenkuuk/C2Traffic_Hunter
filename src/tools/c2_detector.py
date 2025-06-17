
#!/usr/bin/env python3
"""
C2 Traffic Detection Script for PCAP Analysis
Analyzes HTTP traffic for potential Command and Control communications
"""

import argparse
import json
import re
import base64
import hashlib
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Set, Tuple
import math

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

class C2Detector:
    def __init__(self):
        self.suspicious_patterns = {
            'user_agents': [
                r'Mozilla/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)',
                r'curl/',
                r'wget/',
                r'python-requests/',
                r'Go-http-client/',
                r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64-like patterns
            ],
            'url_patterns': [
                r'/[a-f0-9]{32}',  # MD5-like hashes
                r'/[a-f0-9]{40}',  # SHA1-like hashes
                r'/[A-Za-z0-9+/]{20,}={0,2}',  # Base64 encoded paths
                r'/\d{10,13}',  # Timestamps
                r'/(data|config|update|check|beacon|ping)$',
                r'/[a-z]{2,3}/[a-z]{2,3}$',  # Short path segments
            ],
            'headers': [
                'X-Forwarded-For',
                'X-Real-IP',
                'X-Custom-',
                'Authorization: Basic',
            ],
            'file_extensions': [
                '.php', '.asp', '.aspx', '.jsp', '.cgi'
            ]
        }
        
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
            'last_seen': None
        })

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0
        
        # Count frequency of each character
        freq = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy

    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent matches suspicious patterns"""
        if not user_agent:
            return False
            
        for pattern in self.suspicious_patterns['user_agents']:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        return False

    def is_suspicious_url(self, url: str) -> bool:
        """Check if URL matches suspicious patterns"""
        if not url:
            return False
            
        for pattern in self.suspicious_patterns['url_patterns']:
            if re.search(pattern, url):
                return True
        return False

    def analyze_beaconing(self, host: str, timestamps: List[float]) -> Dict:
        """Analyze timing patterns for potential beaconing"""
        if len(timestamps) < 3:
            return {}
            
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        if not intervals:
            return {}
            
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # Check for regular beaconing (low variance in intervals)
        coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 0
        
        return {
            'host': host,
            'request_count': len(timestamps),
            'avg_interval': avg_interval,
            'std_deviation': std_dev,
            'coefficient_of_variation': coefficient_of_variation,
            'is_regular': coefficient_of_variation < 0.3 and len(timestamps) > 5
        }

    def analyze_packet(self, packet):
        """Analyze individual packet for suspicious indicators"""
        if not packet.haslayer(TCP):
            return
            
        if packet.haslayer(HTTPRequest):
            self.analyze_http_request(packet)
        elif packet.haslayer(HTTPResponse):
            self.analyze_http_response(packet)

    def analyze_http_request(self, packet):
        """Analyze HTTP request for C2 indicators"""
        try:
            http_layer = packet[HTTPRequest]
            
            # Extract basic info
            method = http_layer.Method.decode() if http_layer.Method else ''
            host = http_layer.Host.decode() if http_layer.Host else ''
            path = http_layer.Path.decode() if http_layer.Path else ''
            user_agent = http_layer.User_Agent.decode() if http_layer.User_Agent else ''
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = float(packet.time)
            
            # Update host statistics
            host_key = f"{src_ip}->{dst_ip}:{host}"
            self.host_stats[host_key]['request_count'] += 1
            self.host_stats[host_key]['user_agents'].add(user_agent)
            self.host_stats[host_key]['paths'].append(path)
            
            if self.host_stats[host_key]['last_seen']:
                interval = timestamp - self.host_stats[host_key]['last_seen']
                self.host_stats[host_key]['intervals'].append(interval)
            self.host_stats[host_key]['last_seen'] = timestamp
            
            # Check for suspicious indicators
            suspicion_score = 0
            reasons = []
            
            # Check user agent
            if self.is_suspicious_user_agent(user_agent):
                suspicion_score += 3
                reasons.append(f"Suspicious user agent: {user_agent}")
            
            # Check URL patterns
            if self.is_suspicious_url(path):
                suspicion_score += 2
                reasons.append(f"Suspicious URL pattern: {path}")
            
            # Check for high entropy in path (potential encryption)
            path_entropy = self.calculate_entropy(path)
            if path_entropy > 4.5:
                suspicion_score += 2
                reasons.append(f"High entropy in path: {path_entropy:.2f}")
            
            # Check for base64 patterns in headers or body
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', payload):
                    suspicion_score += 1
                    reasons.append("Base64-like content detected")
            
            # Record suspicious requests
            if suspicion_score >= 2:
                self.results['suspicious_requests'].append({
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'host': host,
                    'method': method,
                    'path': path,
                    'user_agent': user_agent,
                    'suspicion_score': suspicion_score,
                    'reasons': reasons
                })
                
        except Exception as e:
            print(f"Error analyzing HTTP request: {e}")

    def analyze_http_response(self, packet):
        """Analyze HTTP response for C2 indicators"""
        try:
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                
                # Check response size for potential file transfers
                if len(payload) > 10000:  # Large responses
                    self.results['file_transfers'].append({
                        'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'size': len(payload),
                        'entropy': self.calculate_entropy(payload.decode('utf-8', errors='ignore'))
                    })
                    
        except Exception as e:
            print(f"Error analyzing HTTP response: {e}")

    def finalize_analysis(self):
        """Perform final analysis after processing all packets"""
        # Analyze beaconing patterns
        for host_key, stats in self.host_stats.items():
            if len(stats['intervals']) >= 3:
                beacon_analysis = self.analyze_beaconing(host_key, stats['intervals'])
                if beacon_analysis and beacon_analysis.get('is_regular'):
                    self.results['beacon_candidates'].append(beacon_analysis)
        
        # Identify suspicious hosts
        for host_key, stats in self.host_stats.items():
            suspicion_indicators = []
            
            # Multiple different user agents (potential evasion)
            if len(stats['user_agents']) > 3:
                suspicion_indicators.append(f"Multiple user agents: {len(stats['user_agents'])}")
            
            # High request frequency
            if stats['request_count'] > 100:
                suspicion_indicators.append(f"High request count: {stats['request_count']}")
            
            # Consistent path patterns
            unique_paths = set(stats['paths'])
            if len(unique_paths) < len(stats['paths']) * 0.1:  # Less than 10% unique paths
                suspicion_indicators.append("Repetitive path patterns")
            
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

    def generate_report(self) -> Dict:
        """Generate analysis report"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'suspicious_hosts': len(self.results['suspicious_hosts']),
                'beacon_candidates': len(self.results['beacon_candidates']),
                'suspicious_requests': len(self.results['suspicious_requests']),
                'file_transfers': len(self.results['file_transfers'])
            },
            'details': self.results
        }
        
        # Convert sets to lists for JSON serialization
        for host_key, stats in self.host_stats.items():
            if isinstance(stats.get('user_agents'), set):
                stats['user_agents'] = list(stats['user_agents'])
        
        return report

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
        else:
            print("\n" + "="*50)
            print("C2 TRAFFIC ANALYSIS REPORT")
            print("="*50)
            
            print(f"\nSummary:")
            print(f"  Suspicious hosts: {report['summary']['suspicious_hosts']}")
            print(f"  Beacon candidates: {report['summary']['beacon_candidates']}")
            print(f"  Suspicious requests: {report['summary']['suspicious_requests']}")
            print(f"  Large file transfers: {report['summary']['file_transfers']}")
            
            if report['details']['beacon_candidates']:
                print(f"\nPotential Beaconing Activity:")
                for beacon in report['details']['beacon_candidates']:
                    print(f"  Host: {beacon['host']}")
                    print(f"    Requests: {beacon['request_count']}")
                    print(f"    Avg interval: {beacon['avg_interval']:.2f}s")
                    print(f"    Regularity: {1-beacon['coefficient_of_variation']:.2f}")
            
            if report['details']['suspicious_requests'] and args.verbose:
                print(f"\nTop Suspicious Requests:")
                for req in sorted(report['details']['suspicious_requests'], 
                                key=lambda x: x['suspicion_score'], reverse=True)[:5]:
                    print(f"  {req['src_ip']} -> {req['dst_ip']} ({req['host']})")
                    print(f"    Path: {req['path']}")
                    print(f"    Score: {req['suspicion_score']}")
                    print(f"    Reasons: {', '.join(req['reasons'])}")
    else:
        print("Analysis failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
