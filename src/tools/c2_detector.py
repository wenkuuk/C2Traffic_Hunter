
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
    from scapy.layers.inet import TCP, IP
    from scapy.packet import Packet
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
                r'.*bot.*',
                r'.*crawler.*',
            ],
            'url_patterns': [
                r'/[a-f0-9]{32}',  # MD5-like hashes
                r'/[a-f0-9]{40}',  # SHA1-like hashes
                r'/[A-Za-z0-9+/]{20,}={0,2}',  # Base64 encoded paths
                r'/\d{10,13}',  # Timestamps
                r'/(data|config|update|check|beacon|ping)$',
                r'/[a-z]{2,3}/[a-z]{2,3}$',  # Short path segments
                r'/admin/.*',
                r'/panel/.*',
                r'/gate\.php',
                r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',  # UUID paths
            ],
            'suspicious_headers': [
                'X-Forwarded-For',
                'X-Real-IP',
                'X-Custom-',
                'Authorization: Basic',
                'x-session-token',
                'x-auth-key', 
                'x-bot-id',
                'x-campaign-id',
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
            'timestamps': [],
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

    def is_http_traffic(self, payload: str) -> bool:
        """Check if packet contains HTTP traffic"""
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        http_responses = ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']
        
        for method in http_methods:
            if payload.startswith(method + ' '):
                return True
        
        for response in http_responses:
            if payload.startswith(response):
                return True
                
        return False

    def parse_http_request(self, payload: bytes) -> Dict:
        """Parse HTTP request from raw payload"""
        try:
            # Decode payload
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')
            
            if not lines:
                return {}
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return {}
            
            method = parts[0]
            path = parts[1]
            
            # Parse headers
            headers = {}
            body = ""
            body_start = 0
            
            for i, line in enumerate(lines[1:], 1):
                if line == '':  # Empty line indicates start of body
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return {
                'method': method,
                'path': path,
                'headers': headers,
                'host': headers.get('host', ''),
                'user_agent': headers.get('user-agent', ''),
                'body': body,
                'full_payload': payload_str
            }
            
        except Exception as e:
            return {}

    def parse_http_response(self, payload: bytes) -> Dict:
        """Parse HTTP response from raw payload"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')
            
            if not lines:
                return {}
            
            # Parse status line
            status_line = lines[0]
            parts = status_line.split(' ')
            if len(parts) < 3:
                return {}
            
            status_code = parts[1] if len(parts) > 1 else ''
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':  # Empty line indicates start of body
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return {
                'status_code': status_code,
                'headers': headers,
                'body': body,
                'content_length': len(body)
            }
            
        except Exception as e:
            return {}

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
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                return
                
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            
            # Check if this is HTTP traffic (port 80, 8080, or non-standard ports with HTTP content)
            is_http_port = tcp_layer.dport in [80, 8080] or tcp_layer.sport in [80, 8080]
            
            if not packet.haslayer(Raw):
                return
                
            payload = packet[Raw].load
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Check if it's HTTP traffic by content or port
            if not is_http_port and not self.is_http_traffic(payload_str):
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
            http_data = self.parse_http_request(payload)
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
            
            # Check for suspicious headers
            for header, value in http_data.get('headers', {}).items():
                if any(suspicious_header.lower() in header.lower() 
                       for suspicious_header in self.suspicious_patterns['suspicious_headers']):
                    suspicion_score += 1
                    reasons.append(f"Suspicious header: {header}")
            
            # Check for base64 patterns in payload
            if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', http_data.get('full_payload', '')):
                suspicion_score += 1
                reasons.append("Base64-like content detected")
            
            # Check for non-standard ports
            if dst_port not in [80, 443, 8080, 8443]:
                suspicion_score += 1
                reasons.append(f"Non-standard HTTP port: {dst_port}")
            
            # Check for suspicious file extensions
            for ext in self.suspicious_patterns['file_extensions']:
                if path.endswith(ext):
                    suspicion_score += 1
                    reasons.append(f"Suspicious file extension: {ext}")
                    break
            
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
            http_data = self.parse_http_response(payload)
            if not http_data:
                return
                
            # Check response size for potential file transfers
            content_length = http_data.get('content_length', 0)
            body_entropy = self.calculate_entropy(http_data.get('body', ''))
            
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
                beacon_analysis = self.analyze_beaconing(host_key, stats['timestamps'])
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
            
            # Consistent path patterns (could indicate automated behavior)
            unique_paths = set(stats['paths'])
            if len(unique_paths) < len(stats['paths']) * 0.1 and len(stats['paths']) > 10:  # Less than 10% unique paths
                suspicion_indicators.append("Repetitive path patterns")
            
            # Check for regular intervals (simple beaconing detection)
            if len(stats['intervals']) > 5:
                avg_interval = sum(stats['intervals']) / len(stats['intervals'])
                variance = sum((x - avg_interval) ** 2 for x in stats['intervals']) / len(stats['intervals'])
                if variance < (avg_interval * 0.1) ** 2:  # Low variance
                    suspicion_indicators.append(f"Regular intervals detected (avg: {avg_interval:.2f}s)")
            
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
        # Convert sets to lists for JSON serialization
        for host_key, stats in self.host_stats.items():
            if isinstance(stats.get('user_agents'), set):
                stats['user_agents'] = list(stats['user_agents'])
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'suspicious_hosts': len(self.results['suspicious_hosts']),
                'beacon_candidates': len(self.results['beacon_candidates']),
                'suspicious_requests': len(self.results['suspicious_requests']),
                'file_transfers': len(self.results['file_transfers']),
                'statistical_anomalies': len(self.results['statistical_anomalies'])
            },
            'details': dict(self.results)  # Convert defaultdict to regular dict
        }
        
        return report

    def print_detailed_report(self, report: Dict, verbose: bool = False):
        """Print detailed console report"""
        print("\n" + "="*60)
        print("C2 TRAFFIC ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nSummary:")
        print(f"  Suspicious hosts: {report['summary']['suspicious_hosts']}")
        print(f"  Beacon candidates: {report['summary']['beacon_candidates']}")
        print(f"  Suspicious requests: {report['summary']['suspicious_requests']}")
        print(f"  Large file transfers: {report['summary']['file_transfers']}")
        print(f"  Statistical anomalies: {report['summary']['statistical_anomalies']}")
        
        if report['details']['beacon_candidates']:
            print(f"\n[!] Potential Beaconing Activity:")
            print("-" * 40)
            for beacon in report['details']['beacon_candidates']:
                print(f"  Host: {beacon['host']}")
                print(f"    Requests: {beacon['request_count']}")
                print(f"    Avg interval: {beacon['avg_interval']:.2f}s")
                print(f"    Regularity score: {1-beacon['coefficient_of_variation']:.2f}")
        
        if report['details']['suspicious_hosts']:
            print(f"\n[!] Suspicious Hosts:")
            print("-" * 40)
            for host, indicators in list(report['details']['suspicious_hosts'].items())[:5]:
                print(f"  {host}")
                for indicator in indicators:
                    print(f"    - {indicator}")
        
        if report['details']['suspicious_requests'] and verbose:
            print(f"\n[!] Top Suspicious Requests:")
            print("-" * 40)
            for req in sorted(report['details']['suspicious_requests'], 
                            key=lambda x: x['suspicion_score'], reverse=True)[:10]:
                print(f"  {req['src_ip']}:{req['src_port']} -> {req['dst_ip']}:{req['dst_port']}")
                print(f"    Host: {req['host']}")
                print(f"    Path: {req['path']}")
                print(f"    Method: {req['method']}")
                print(f"    Score: {req['suspicion_score']}")
                print(f"    Reasons: {', '.join(req['reasons'])}")
                print()
        
        if report['details']['file_transfers']:
            print(f"\n[!] Large File Transfers:")
            print("-" * 40)
            for transfer in report['details']['file_transfers'][:5]:
                print(f"  {transfer['src_ip']} -> {transfer['dst_ip']}")
                print(f"    Size: {transfer['size']:,} bytes")
                print(f"    Entropy: {transfer['entropy']:.2f}")
                print(f"    Status: {transfer.get('status_code', 'unknown')}")
        
        print("\n" + "="*60)

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
