
#!/usr/bin/env python3
"""
Packet analysis module for C2 traffic detection
"""

from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import TCP, IP, Raw
except ImportError:
    print("Error: scapy not installed. Install with: pip install scapy")
    exit(1)

from http_parser import HTTPParser
from statistical_analysis import StatisticalAnalyzer
from signatures import SignatureEngine
from ml_features import MLFeatureExtractor


class PacketAnalyzer:
    """Handles individual packet analysis"""
    
    def __init__(self, http_parser, statistical_analyzer, pattern_detector, 
                 signature_engine, ml_extractor):
        self.http_parser = http_parser
        self.statistical_analyzer = statistical_analyzer
        self.pattern_detector = pattern_detector
        self.signature_engine = signature_engine
        self.ml_extractor = ml_extractor
        
    def analyze_packet(self, packet, results, behavioral_analyzer, host_stats):
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
                self.analyze_http_request_packet(packet, payload, results, behavioral_analyzer, host_stats)
            elif payload_str.startswith('HTTP/'):
                self.analyze_http_response_packet(packet, payload, results)
                
        except Exception as e:
            pass

    def analyze_http_request_packet(self, packet, payload, results, behavioral_analyzer, host_stats):
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
                'response_size': 0,
                'response_code': '',
                'session_duration': 0,
                'request_interval': 0
            }
            
            # Update host statistics
            host_key = f"{src_ip}->{dst_ip}:{http_data.get('host', '')}"
            stats = host_stats[host_key]
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
            behavioral_analyzer.add_session(session_data)
            
            # Original suspicion scoring
            suspicion_score, reasons = self.statistical_analyzer.calculate_suspicion_score(
                http_data, dst_port, self.pattern_detector
            )
            
            # Advanced signature-based detection
            sig_score, sig_matches = self.signature_engine.detect_signatures(session_data, payload)
            if sig_score > 0:
                results['signature_detections'].append({
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
            
            if ml_score > 0.5:
                results['ml_classifications'].append({
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'session_data': session_data,
                    'ml_score': ml_score,
                    'ml_reason': ml_reason,
                    'features': features
                })
                suspicion_score += int(ml_score * 5)
                reasons.append(f"ML classification: {ml_reason}")
            
            # Record suspicious requests
            if suspicion_score >= 2 or sig_score > 0 or ml_score > 0.5:
                results['suspicious_requests'].append({
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

    def analyze_http_response_packet(self, packet, payload, results):
        """Analyze HTTP response packet"""
        try:
            http_data = self.http_parser.parse_http_response(payload)
            if not http_data:
                return
                
            # Check response size for potential file transfers
            content_length = http_data.get('content_length', 0)
            body_entropy = self.pattern_detector.calculate_entropy(http_data.get('body', ''))
            
            if content_length > 10000:
                results['file_transfers'].append({
                    'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'size': content_length,
                    'entropy': body_entropy,
                    'status_code': http_data.get('status_code', '')
                })
            
            # Check for suspicious response patterns
            if body_entropy > 7.0 and content_length > 1000:
                results['statistical_anomalies'].append({
                    'type': 'high_entropy_response',
                    'timestamp': datetime.fromtimestamp(float(packet.time)).isoformat(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'entropy': body_entropy,
                    'size': content_length
                })
                    
        except Exception as e:
            pass
