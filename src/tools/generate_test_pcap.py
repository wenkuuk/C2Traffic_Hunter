
#!/usr/bin/env python3
"""
Generate test PCAP files for C2 detection validation
"""

import os
import time
import random
import hashlib
from scapy.all import *

def generate_normal_traffic():
    """Generate normal HTTP traffic"""
    packets = []
    base_time = time.time()
    
    # Normal web browsing traffic
    for i in range(20):
        # HTTP GET request
        ip = IP(src="192.168.1.100", dst="93.184.216.34")  # example.com
        tcp = TCP(sport=random.randint(40000, 50000), dport=80, flags="PA")
        
        http_request = f"GET /page{i} HTTP/1.1\r\n"
        http_request += "Host: example.com\r\n"
        http_request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        http_request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        http_request += "Connection: keep-alive\r\n\r\n"
        
        packet = ip/tcp/Raw(load=http_request.encode())
        packet.time = base_time + i * random.uniform(1, 10)
        packets.append(packet)
        
        # HTTP response
        ip_resp = IP(src="93.184.216.34", dst="192.168.1.100")
        tcp_resp = TCP(sport=80, dport=tcp.sport, flags="PA")
        
        http_response = "HTTP/1.1 200 OK\r\n"
        http_response += "Content-Type: text/html\r\n"
        http_response += "Content-Length: 1000\r\n\r\n"
        http_response += "<html><body>Normal content</body></html>" * 20
        
        packet_resp = ip_resp/tcp_resp/Raw(load=http_response.encode())
        packet_resp.time = packet.time + random.uniform(0.1, 0.5)
        packets.append(packet_resp)
    
    return packets

def generate_c2_traffic():
    """Generate malicious C2 traffic"""
    packets = []
    base_time = time.time()
    
    # Suspicious characteristics
    c2_domains = ["evil.onion", "malicious.dyndns.org", "192.168.100.50"]
    suspicious_paths = ["/gate.php", "/admin/panel", "/check", "/beacon"]
    suspicious_uas = ["", "curl/7.68.0", "python-requests/2.25.1"]
    
    # Generate beaconing traffic
    for i in range(50):
        domain = random.choice(c2_domains)
        path = random.choice(suspicious_paths)
        ua = random.choice(suspicious_uas)
        
        # Regular intervals (beaconing pattern)
        timestamp = base_time + i * 60.0  # Every 60 seconds
        
        ip = IP(src="192.168.1.100", dst="10.0.0.1")
        tcp = TCP(sport=random.randint(40000, 50000), dport=80, flags="PA")
        
        # Suspicious HTTP request
        if path == "/gate.php":
            # POST with encoded data
            http_request = "POST /gate.php HTTP/1.1\r\n"
            http_request += f"Host: {domain}\r\n"
            http_request += f"User-Agent: {ua}\r\n"
            http_request += "Content-Type: application/x-www-form-urlencoded\r\n"
            http_request += "X-Session-Token: QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
            
            # Encoded payload
            encoded_data = base64.b64encode(f"cmd=status&id={i}".encode()).decode()
            http_request += f"Content-Length: {len(encoded_data)}\r\n\r\n"
            http_request += encoded_data
        else:
            # GET with suspicious path
            http_request = f"GET {path} HTTP/1.1\r\n"
            http_request += f"Host: {domain}\r\n"
            http_request += f"User-Agent: {ua}\r\n"
            if random.random() < 0.3:  # Sometimes add suspicious headers
                http_request += "X-Bot-ID: bot123\r\n"
            http_request += "\r\n"
        
        packet = ip/tcp/Raw(load=http_request.encode())
        packet.time = timestamp
        packets.append(packet)
        
        # Response with high entropy data
        ip_resp = IP(src="10.0.0.1", dst="192.168.1.100")
        tcp_resp = TCP(sport=80, dport=tcp.sport, flags="PA")
        
        http_response = "HTTP/1.1 200 OK\r\n"
        http_response += "Content-Type: text/plain\r\n"
        
        # High entropy response (encrypted C2 data)
        entropy_data = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=500))
        http_response += f"Content-Length: {len(entropy_data)}\r\n\r\n"
        http_response += entropy_data
        
        packet_resp = ip_resp/tcp_resp/Raw(load=http_response.encode())
        packet_resp.time = timestamp + random.uniform(0.1, 0.3)
        packets.append(packet_resp)
    
    return packets

def generate_mixed_traffic():
    """Generate mixed normal and malicious traffic"""
    normal = generate_normal_traffic()
    malicious = generate_c2_traffic()
    
    # Combine and sort by timestamp
    all_packets = normal + malicious
    all_packets.sort(key=lambda x: x.time)
    
    return all_packets

def main():
    """Generate test PCAP files"""
    print("[+] Generating test PCAP files...")
    
    # Create test directory
    os.makedirs("test_pcaps", exist_ok=True)
    
    # Generate normal traffic
    print("[+] Generating normal traffic...")
    normal_packets = generate_normal_traffic()
    wrpcap("test_pcaps/normal_traffic.pcap", normal_packets)
    print(f"    Saved {len(normal_packets)} packets to normal_traffic.pcap")
    
    # Generate C2 traffic
    print("[+] Generating C2 traffic...")
    c2_packets = generate_c2_traffic()
    wrpcap("test_pcaps/c2_traffic.pcap", c2_packets)
    print(f"    Saved {len(c2_packets)} packets to c2_traffic.pcap")
    
    # Generate mixed traffic
    print("[+] Generating mixed traffic...")
    mixed_packets = generate_mixed_traffic()
    wrpcap("test_pcaps/mixed_traffic.pcap", mixed_packets)
    print(f"    Saved {len(mixed_packets)} packets to mixed_traffic.pcap")
    
    print("\n[+] Test PCAP files generated successfully!")
    print("    You can now test the detection system with these files:")
    print("    python c2_detector.py test_pcaps/normal_traffic.pcap -v")
    print("    python c2_detector.py test_pcaps/c2_traffic.pcap -v")
    print("    python c2_detector.py test_pcaps/mixed_traffic.pcap -v")

if __name__ == "__main__":
    main()
