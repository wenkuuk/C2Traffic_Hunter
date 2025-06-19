
#!/usr/bin/env python3
"""
Comprehensive validation tests for the Advanced Threat Assessor
"""

import sys
import os
import math
from datetime import datetime, timedelta

# Add the tools directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threat_assessor import ThreatAssessor


class ThreatAssessmentValidator:
    """Validation class for testing threat assessment functionality"""
    
    @staticmethod
    def create_test_detection(detection_type: str, **kwargs) -> dict:
        """Create a test detection with specified parameters"""
        base_detection = {
            'timestamp': datetime.now().isoformat(),
            'session_data': {
                'src_ip': '192.168.1.100',
                'dst_ip': '203.0.113.1',
                'host': 'suspicious-c2.example.com',
                'path': '/api/beacon',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        }
        
        if detection_type == 'signature':
            base_detection.update({
                'signature_score': kwargs.get('score', 7),
                'signature_matches': kwargs.get('matches', ['suspicious_path', 'c2_domain'])
            })
        elif detection_type == 'ml':
            base_detection.update({
                'ml_score': kwargs.get('score', 0.8),
                'ml_reason': kwargs.get('reason', 'High entropy content detected'),
                'features': kwargs.get('features', {})
            })
        elif detection_type == 'beaconing':
            base_detection.update({
                'host_key': kwargs.get('host_key', '192.168.1.100->203.0.113.1:suspicious-c2.example.com'),
                'pattern_type': kwargs.get('pattern', 'regular_interval'),
                'session_count': kwargs.get('count', 10),
                'mean_interval': kwargs.get('interval', 300.0),
                'confidence': kwargs.get('confidence', 0.9),
                'duration': kwargs.get('duration', 3600),
                'timestamps': kwargs.get('timestamps', [i * 300 for i in range(10)])
            })
        elif detection_type == 'behavioral':
            base_detection.update({
                'host_key': kwargs.get('host_key', '192.168.1.100->203.0.113.1:suspicious-c2.example.com'),
                'anomaly_type': kwargs.get('anomaly', 'unusual_request_pattern'),
                'confidence': kwargs.get('confidence', 0.7),
                'baseline': kwargs.get('baseline', 10),
                'current': kwargs.get('current', 50),
                'z_score': kwargs.get('z_score', 2.5)
            })
        
        return base_detection
    
    @staticmethod
    def test_enhanced_confidence_calculation():
        """Test enhanced confidence scoring"""
        print("\n=== Testing Enhanced Confidence Calculation ===")
        
        # Test signature detection confidence
        sig_detection = {
            'type': 'signature',
            'severity': 8,
            'frequency': 3,
            'age_hours': 2,
            'correlated_detections': 2,
            'correlation_types': ['ml', 'beaconing'],
            'source_reliability': 0.9
        }
        
        confidence = ThreatAssessor.calculate_enhanced_confidence_score(sig_detection)
        print(f"Signature Detection Confidence: {confidence:.3f}")
        assert 0.7 <= confidence <= 1.0, f"Expected high confidence for signature, got {confidence}"
        
        # Test ML detection confidence
        ml_detection = {
            'type': 'ml',
            'ml_confidence': 0.85,
            'severity': 7,
            'frequency': 1,
            'age_hours': 0.5,
            'source_reliability': 0.8
        }
        
        ml_confidence = ThreatAssessor.calculate_enhanced_confidence_score(ml_detection)
        print(f"ML Detection Confidence: {ml_confidence:.3f}")
        assert 0.6 <= ml_confidence <= 1.0, f"Expected good confidence for ML, got {ml_confidence}"
        
        # Test aged detection (should have lower confidence)
        aged_detection = {
            'type': 'signature',
            'severity': 8,
            'frequency': 1,
            'age_hours': 72,  # 3 days old
            'source_reliability': 0.9
        }
        
        aged_confidence = ThreatAssessor.calculate_enhanced_confidence_score(aged_detection)
        print(f"Aged Detection Confidence: {aged_confidence:.3f}")
        assert aged_confidence < confidence, f"Aged detection should have lower confidence"
        
        print("✓ Enhanced confidence calculation tests passed")
    
    @staticmethod
    def test_pattern_strength_calculation():
        """Test beaconing pattern strength calculation"""
        print("\n=== Testing Pattern Strength Calculation ===")
        
        # Test regular beaconing pattern
        regular_pattern = {
            'timestamps': [i * 300 for i in range(10)],  # Every 5 minutes
            'duration_hours': 2,
            'frequency_per_hour': 12
        }
        
        strength = ThreatAssessor.calculate_pattern_strength(regular_pattern)
        print(f"Regular Pattern Strength: {strength:.3f}")
        assert 0.7 <= strength <= 1.0, f"Expected high strength for regular pattern, got {strength}"
        
        # Test irregular pattern
        irregular_pattern = {
            'timestamps': [0, 100, 500, 600, 1200, 2000, 2100],  # Irregular intervals
            'duration_hours': 1,
            'frequency_per_hour': 7
        }
        
        irregular_strength = ThreatAssessor.calculate_pattern_strength(irregular_pattern)
        print(f"Irregular Pattern Strength: {irregular_strength:.3f}")
        assert irregular_strength < strength, f"Irregular pattern should have lower strength"
        
        # Test insufficient data
        insufficient_pattern = {
            'timestamps': [0, 300],  # Only 2 timestamps
            'duration_hours': 0.1,
            'frequency_per_hour': 20
        }
        
        insufficient_strength = ThreatAssessor.calculate_pattern_strength(insufficient_pattern)
        print(f"Insufficient Data Pattern Strength: {insufficient_strength:.3f}")
        assert insufficient_strength == 0.5, f"Expected default strength for insufficient data"
        
        print("✓ Pattern strength calculation tests passed")
    
    @staticmethod
    def test_anomaly_strength_calculation():
        """Test behavioral anomaly strength calculation"""
        print("\n=== Testing Anomaly Strength Calculation ===")
        
        # Test high deviation anomaly
        high_anomaly = {
            'baseline': 10,
            'current': 50,
            'z_score': 3.5,
            'persistence_hours': 4
        }
        
        high_strength = ThreatAssessor.calculate_anomaly_strength(high_anomaly)
        print(f"High Anomaly Strength: {high_strength:.3f}")
        assert 0.8 <= high_strength <= 1.0, f"Expected high strength for significant anomaly"
        
        # Test medium deviation anomaly
        medium_anomaly = {
            'baseline': 20,
            'current': 35,
            'z_score': 1.5,
            'persistence_hours': 1
        }
        
        medium_strength = ThreatAssessor.calculate_anomaly_strength(medium_anomaly)
        print(f"Medium Anomaly Strength: {medium_strength:.3f}")
        assert 0.4 <= medium_strength <= 0.7, f"Expected medium strength for moderate anomaly"
        
        # Test low deviation anomaly
        low_anomaly = {
            'baseline': 30,
            'current': 32,
            'z_score': 0.5,
            'persistence_hours': 0.5
        }
        
        low_strength = ThreatAssessor.calculate_anomaly_strength(low_anomaly)
        print(f"Low Anomaly Strength: {low_strength:.3f}")
        assert low_strength < medium_strength, f"Low anomaly should have lower strength"
        
        print("✓ Anomaly strength calculation tests passed")
    
    @staticmethod
    def test_comprehensive_threat_assessment():
        """Test comprehensive threat assessment with multiple detection types"""
        print("\n=== Testing Comprehensive Threat Assessment ===")
        
        # Create test results with multiple detection types
        test_results = {
            'signature_detections': [
                ThreatAssessmentValidator.create_test_detection('signature', score=8),
                ThreatAssessmentValidator.create_test_detection('signature', score=6),
                ThreatAssessmentValidator.create_test_detection('signature', score=9)
            ],
            'ml_classifications': [
                ThreatAssessmentValidator.create_test_detection('ml', score=0.85),
                ThreatAssessmentValidator.create_test_detection('ml', score=0.72)
            ],
            'beaconing_patterns': [
                ThreatAssessmentValidator.create_test_detection('beaconing', 
                    timestamps=[i * 300 for i in range(12)], confidence=0.9)
            ],
            'behavioral_anomalies': [
                ThreatAssessmentValidator.create_test_detection('behavioral', 
                    z_score=2.8, confidence=0.8)
            ]
        }
        
        # Generate threat summary
        summary = ThreatAssessor.generate_threat_summary(test_results)
        
        print(f"Total Detections: {summary['total_detections']}")
        print(f"Threat Score: {summary['threat_score']:.3f}")
        print(f"Threat Level: {summary['threat_level']}")
        print(f"Overall Confidence: {summary['overall_confidence']:.3f}")
        print(f"Confidence Level: {summary['confidence_level']}")
        print(f"Correlation Bonus: {summary['correlation_bonus']:.3f}")
        
        # Validate results
        assert summary['total_detections'] == 7, f"Expected 7 total detections, got {summary['total_detections']}"
        assert summary['threat_score'] > 0.4, f"Expected high threat score for multiple detections"
        assert summary['threat_level'] in ['MEDIUM-HIGH', 'HIGH', 'CRITICAL'], f"Expected elevated threat level"
        assert summary['correlation_bonus'] > 0, f"Expected correlation bonus for multiple detection types"
        assert len(summary['component_scores']) == 4, f"Expected 4 component scores"
        
        # Test risk factors
        risk_factors = summary['risk_factors']
        assert risk_factors['command_control'] == True, f"Expected command_control risk factor"
        assert risk_factors['persistence'] == True, f"Expected persistence risk factor"
        
        print("✓ Comprehensive threat assessment tests passed")
    
    @staticmethod
    def test_threat_level_determination():
        """Test threat level determination with various scenarios"""
        print("\n=== Testing Threat Level Determination ===")
        
        # Test critical threat with high confidence
        critical_results = {
            'signature_detections': [
                ThreatAssessmentValidator.create_test_detection('signature', score=10) for _ in range(5)
            ],
            'ml_classifications': [
                ThreatAssessmentValidator.create_test_detection('ml', score=0.95) for _ in range(3)
            ],
            'beaconing_patterns': [
                ThreatAssessmentValidator.create_test_detection('beaconing', confidence=0.95)
            ],
            'behavioral_anomalies': [
                ThreatAssessmentValidator.create_test_detection('behavioral', z_score=4.0)
            ]
        }
        
        critical_summary = ThreatAssessor.generate_threat_summary(critical_results)
        print(f"Critical Scenario - Threat Level: {critical_summary['threat_level']}, Score: {critical_summary['threat_score']:.3f}")
        assert critical_summary['threat_level'] in ['HIGH', 'CRITICAL'], f"Expected critical/high threat level"
        
        # Test low threat scenario
        low_results = {
            'signature_detections': [],
            'ml_classifications': [
                ThreatAssessmentValidator.create_test_detection('ml', score=0.3)
            ],
            'beaconing_patterns': [],
            'behavioral_anomalies': []
        }
        
        low_summary = ThreatAssessor.generate_threat_summary(low_results)
        print(f"Low Scenario - Threat Level: {low_summary['threat_level']}, Score: {low_summary['threat_score']:.3f}")
        assert low_summary['threat_level'] in ['LOW', 'LOW-MEDIUM'], f"Expected low threat level"
        
        # Test medium threat scenario
        medium_results = {
            'signature_detections': [
                ThreatAssessmentValidator.create_test_detection('signature', score=5)
            ],
            'ml_classifications': [
                ThreatAssessmentValidator.create_test_detection('ml', score=0.6)
            ],
            'beaconing_patterns': [],
            'behavioral_anomalies': [
                ThreatAssessmentValidator.create_test_detection('behavioral', z_score=1.5)
            ]
        }
        
        medium_summary = ThreatAssessor.generate_threat_summary(medium_results)
        print(f"Medium Scenario - Threat Level: {medium_summary['threat_level']}, Score: {medium_summary['threat_score']:.3f}")
        assert medium_summary['threat_level'] in ['MEDIUM', 'MEDIUM-HIGH'], f"Expected medium threat level"
        
        print("✓ Threat level determination tests passed")
    
    @staticmethod
    def test_correlation_bonus_calculation():
        """Test correlation bonus calculation"""
        print("\n=== Testing Correlation Bonus Calculation ===")
        
        # Test single detection type (no bonus)
        single_type_results = {
            'signature_detections': [ThreatAssessmentValidator.create_test_detection('signature')],
            'ml_classifications': [],
            'beaconing_patterns': [],
            'behavioral_anomalies': []
        }
        
        single_bonus = ThreatAssessor._calculate_correlation_bonus(1, single_type_results)
        print(f"Single Type Correlation Bonus: {single_bonus:.3f}")
        assert single_bonus == 0.0, f"Expected no bonus for single detection type"
        
        # Test multiple detection types
        multi_type_results = {
            'signature_detections': [ThreatAssessmentValidator.create_test_detection('signature')],
            'ml_classifications': [ThreatAssessmentValidator.create_test_detection('ml')],
            'beaconing_patterns': [ThreatAssessmentValidator.create_test_detection('beaconing')],
            'behavioral_anomalies': [ThreatAssessmentValidator.create_test_detection('behavioral')]
        }
        
        multi_bonus = ThreatAssessor._calculate_correlation_bonus(4, multi_type_results)
        print(f"Multi Type Correlation Bonus: {multi_bonus:.3f}")
        assert multi_bonus > 0.15, f"Expected significant bonus for multiple detection types"
        
        # Test high volume bonus
        high_volume_results = {
            'signature_detections': [ThreatAssessmentValidator.create_test_detection('signature') for _ in range(10)],
            'ml_classifications': [ThreatAssessmentValidator.create_test_detection('ml') for _ in range(5)],
            'beaconing_patterns': [],
            'behavioral_anomalies': []
        }
        
        volume_bonus = ThreatAssessor._calculate_correlation_bonus(2, high_volume_results)
        print(f"High Volume Correlation Bonus: {volume_bonus:.3f}")
        assert volume_bonus > 0.05, f"Expected bonus for high detection volume"
        
        print("✓ Correlation bonus calculation tests passed")
    
    @staticmethod
    def run_performance_benchmark():
        """Run performance benchmark for threat assessment"""
        print("\n=== Performance Benchmark ===")
        
        import time
        
        # Create large test dataset
        large_results = {
            'signature_detections': [
                ThreatAssessmentValidator.create_test_detection('signature', score=i%10+1) 
                for i in range(100)
            ],
            'ml_classifications': [
                ThreatAssessmentValidator.create_test_detection('ml', score=(i%10)/10.0) 
                for i in range(50)
            ],
            'beaconing_patterns': [
                ThreatAssessmentValidator.create_test_detection('beaconing', 
                    timestamps=[j * (300 + i*10) for j in range(20)]) 
                for i in range(10)
            ],
            'behavioral_anomalies': [
                ThreatAssessmentValidator.create_test_detection('behavioral', 
                    z_score=1 + i*0.5) 
                for i in range(25)
            ]
        }
        
        start_time = time.time()
        summary = ThreatAssessor.generate_threat_summary(large_results)
        end_time = time.time()
        
        processing_time = end_time - start_time
        total_detections = summary['total_detections']
        
        print(f"Processed {total_detections} detections in {processing_time:.4f} seconds")
        print(f"Processing rate: {total_detections/processing_time:.1f} detections/second")
        print(f"Final threat score: {summary['threat_score']:.3f}")
        print(f"Final threat level: {summary['threat_level']}")
        
        assert processing_time < 1.0, f"Processing took too long: {processing_time:.4f}s"
        assert total_detections == 185, f"Expected 185 total detections"
        
        print("✓ Performance benchmark passed")
    
    @staticmethod
    def run_all_tests():
        """Run all validation tests"""
        print("Starting Advanced Threat Assessor Validation Tests")
        print("=" * 60)
        
        try:
            ThreatAssessmentValidator.test_enhanced_confidence_calculation()
            ThreatAssessmentValidator.test_pattern_strength_calculation()
            ThreatAssessmentValidator.test_anomaly_strength_calculation()
            ThreatAssessmentValidator.test_comprehensive_threat_assessment()
            ThreatAssessmentValidator.test_threat_level_determination()
            ThreatAssessmentValidator.test_correlation_bonus_calculation()
            ThreatAssessmentValidator.run_performance_benchmark()
            
            print("\n" + "=" * 60)
            print("🎉 ALL TESTS PASSED! Advanced Threat Assessor is working correctly.")
            print("=" * 60)
            
            return True
            
        except AssertionError as e:
            print(f"\n❌ TEST FAILED: {e}")
            return False
        except Exception as e:
            print(f"\n💥 UNEXPECTED ERROR: {e}")
            return False


def main():
    """Main function to run validation tests"""
    validator = ThreatAssessmentValidator()
    success = validator.run_all_tests()
    
    if success:
        print("\nRunning comparison with sample data...")
        # Demonstrate the enhanced scoring
        sample_results = {
            'signature_detections': [
                ThreatAssessmentValidator.create_test_detection('signature', score=8),
                ThreatAssessmentValidator.create_test_detection('signature', score=6)
            ],
            'ml_classifications': [
                ThreatAssessmentValidator.create_test_detection('ml', score=0.8)
            ],
            'beaconing_patterns': [
                ThreatAssessmentValidator.create_test_detection('beaconing', confidence=0.9)
            ],
            'behavioral_anomalies': [
                ThreatAssessmentValidator.create_test_detection('behavioral', z_score=2.5)
            ]
        }
        
        ThreatAssessor.compare_scoring_methods(sample_results)
        
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
