
#!/usr/bin/env python3
"""
Test cases for C2 Traffic Detection System
"""

import unittest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock

from c2_detector import AdvancedC2Detector
from signatures import SignatureEngine
from ml_features import MLFeatureExtractor
from behavioral_analysis import BehavioralAnalyzer

class TestSignatureEngine(unittest.TestCase):
    """Test signature-based detection"""
    
    def setUp(self):
        self.engine = SignatureEngine()
    
    def test_malicious_domain_detection(self):
        """Test detection of malicious domains"""
        # Test onion domain
        session_data = {
            'host': 'test.onion',
            'path': '/test',
            'user_agent': 'Mozilla/5.0',
            'headers': {}
        }
        score, matches = self.engine.detect_signatures(session_data)
        self.assertGreater(score, 0)
        self.assertTrue(any('domain' in match.lower() for match in matches))
    
    def test_suspicious_path_detection(self):
        """Test detection of suspicious paths"""
        session_data = {
            'host': 'example.com',
            'path': '/gate.php',
            'user_agent': 'Mozilla/5.0',
            'headers': {}
        }
        score, matches = self.engine.detect_signatures(session_data)
        self.assertGreater(score, 0)
        self.assertTrue(any('path' in match.lower() for match in matches))
    
    def test_malicious_user_agent_detection(self):
        """Test detection of malicious user agents"""
        session_data = {
            'host': 'example.com',
            'path': '/test',
            'user_agent': 'curl/7.68.0',
            'headers': {}
        }
        score, matches = self.engine.detect_signatures(session_data)
        self.assertGreater(score, 0)
        self.assertTrue(any('user agent' in match.lower() for match in matches))
    
    def test_clean_traffic(self):
        """Test that clean traffic doesn't trigger signatures"""
        session_data = {
            'host': 'google.com',
            'path': '/search',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'headers': {}
        }
        score, matches = self.engine.detect_signatures(session_data)
        self.assertEqual(score, 0)
        self.assertEqual(len(matches), 0)

class TestMLFeatureExtractor(unittest.TestCase):
    """Test ML feature extraction"""
    
    def setUp(self):
        self.extractor = MLFeatureExtractor()
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # High entropy string
        high_entropy = "A9kL3mN8qR2tY7wE1rT6uI5oP4aS3dF"
        entropy = self.extractor._calculate_entropy(high_entropy)
        self.assertGreater(entropy, 4.0)
        
        # Low entropy string
        low_entropy = "aaaaaaaaaa"
        entropy = self.extractor._calculate_entropy(low_entropy)
        self.assertLess(entropy, 1.0)
    
    def test_feature_extraction(self):
        """Test feature extraction from session data"""
        from dataclasses import dataclass
        
        @dataclass
        class MockSession:
            path: str = "/test/path"
            host: str = "example.com"
            user_agent: str = "Mozilla/5.0"
            headers: dict = None
            request_size: int = 1000
            response_size: int = 2000
            dst_port: int = 80
            method: str = "GET"
            response_code: str = "200"
            request_interval: float = 30.0
            session_duration: float = 0.5
            is_encrypted: bool = False
        
        session = MockSession()
        session.headers = {}
        
        features = self.extractor.extract_features(session)
        
        # Check that features are extracted
        self.assertIn('path_length', features)
        self.assertIn('host_length', features)
        self.assertIn('path_entropy', features)
        self.assertIn('is_ip_address', features)
        self.assertEqual(features['path_length'], len(session.path))
        self.assertEqual(features['method_get'], 1)

class TestBehavioralAnalyzer(unittest.TestCase):
    """Test behavioral analysis"""
    
    def setUp(self):
        self.analyzer = BehavioralAnalyzer()
    
    def test_beaconing_detection(self):
        """Test beaconing pattern detection"""
        from dataclasses import dataclass
        
        @dataclass
        class MockSession:
            src_ip: str
            dst_ip: str
            host: str
            timestamp: float
            user_agent: str = "Mozilla/5.0"
            path: str = "/test"
            response_size: int = 1000
        
        # Create regular beaconing pattern
        base_time = 1000000000.0
        for i in range(15):  # 15 sessions with regular 60-second intervals
            session = MockSession(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                host="evil.com",
                timestamp=base_time + (i * 60.0)  # Every 60 seconds
            )
            self.analyzer.add_session(session)
        
        beacons = self.analyzer.analyze_beaconing()
        self.assertGreater(len(beacons), 0)
        
        # Check beacon characteristics
        beacon = beacons[0]
        self.assertEqual(beacon['session_count'], 15)
        self.assertAlmostEqual(beacon['mean_interval'], 60.0, delta=1.0)
        self.assertLess(beacon['coefficient_variation'], 0.3)  # Should be very regular

class TestAdvancedC2Detector(unittest.TestCase):
    """Test main C2 detector"""
    
    def setUp(self):
        self.detector = AdvancedC2Detector()
    
    @patch('c2_detector.rdpcap')
    def test_pcap_analysis_flow(self, mock_rdpcap):
        """Test the complete analysis flow"""
        # Mock packet data
        mock_packets = []
        mock_rdpcap.return_value = mock_packets
        
        # Test with empty PCAP
        result = self.detector.analyze_pcap("fake.pcap")
        self.assertTrue(result)
        
        # Check that results structure is created
        self.assertIn('signature_detections', self.detector.results)
        self.assertIn('ml_classifications', self.detector.results)
        self.assertIn('behavioral_anomalies', self.detector.results)
        self.assertIn('beaconing_patterns', self.detector.results)
    
    def test_threat_assessment(self):
        """Test threat level calculation"""
        # Add some mock detections
        self.detector.results['signature_detections'] = [{'test': 'data'}]
        self.detector.results['ml_classifications'] = [{'test': 'data'}]
        self.detector.results['beaconing_patterns'] = []
        self.detector.results['behavioral_anomalies'] = []
        
        summary = self.detector.generate_threat_summary()
        
        self.assertIn('threat_level', summary)
        self.assertIn('threat_score', summary)
        self.assertGreater(summary['threat_score'], 0)
        self.assertIn(summary['threat_level'], ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_report_generation(self):
        """Test report generation and serialization"""
        detector = AdvancedC2Detector()
        
        # Generate empty report
        report = detector.generate_report()
        
        # Check report structure
        self.assertIn('analysis_timestamp', report)
        self.assertIn('summary', report)
        self.assertIn('detections', report)
        
        # Test JSON serialization
        try:
            json.dumps(report, default=str)
        except Exception as e:
            self.fail(f"Report serialization failed: {e}")

def run_test_suite():
    """Run all tests and generate report"""
    print("="*60)
    print("C2 TRAFFIC DETECTION SYSTEM - TEST SUITE")
    print("="*60)
    
    # Create test suite
    test_classes = [
        TestSignatureEngine,
        TestMLFeatureExtractor,
        TestBehavioralAnalyzer,
        TestAdvancedC2Detector,
        TestIntegration
    ]
    
    suite = unittest.TestSuite()
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORs:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_test_suite()
    exit(0 if success else 1)
