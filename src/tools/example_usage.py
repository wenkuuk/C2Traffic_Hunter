
#!/usr/bin/env python3
"""
Example usage and testing for the C2 detector
"""

import json
from c2_detector import C2Detector

def demo_analysis():
    """Demonstrate the C2 detector with sample analysis"""
    
    print("C2 Traffic Detection Demo")
    print("=" * 40)
    
    # This would normally analyze a real PCAP file
    # For demo purposes, we'll show the structure
    
    detector = C2Detector()
    
    # Example of what suspicious patterns look like
    print("\nSuspicious User Agent Patterns:")
    test_agents = [
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "curl/7.68.0",
        "python-requests/2.25.1",
        "Go-http-client/1.1",
        "dGVzdF9hZ2VudA==",  # Base64 encoded
    ]
    
    for agent in test_agents:
        is_suspicious = detector.is_suspicious_user_agent(agent)
        print(f"  {agent}: {'SUSPICIOUS' if is_suspicious else 'OK'}")
    
    print("\nSuspicious URL Patterns:")
    test_urls = [
        "/a1b2c3d4e5f6789012345678901234567890abcd",  # Hash-like
        "/dGVzdF9wYXRo",  # Base64-like
        "/1609459200",  # Timestamp
        "/config",  # C2 endpoint
        "/data/update",  # C2 path
    ]
    
    for url in test_urls:
        is_suspicious = detector.is_suspicious_url(url)
        print(f"  {url}: {'SUSPICIOUS' if is_suspicious else 'OK'}")
    
    print("\nEntropy Analysis Examples:")
    test_strings = [
        "normal text content",
        "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456",  # High entropy
        "aaaaaaaaaaaaaaaaaaaaaaaa",  # Low entropy
        "dGhpcyBpcyBhIHRlc3Q=",  # Base64
    ]
    
    for string in test_strings:
        entropy = detector.calculate_entropy(string)
        print(f"  '{string}': entropy = {entropy:.2f}")

if __name__ == "__main__":
    demo_analysis()
