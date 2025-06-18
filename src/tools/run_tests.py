
#!/usr/bin/env python3
"""
Comprehensive test runner for C2 Detection System
"""

import os
import sys
import subprocess
import time
from datetime import datetime

def run_unit_tests():
    """Run unit tests"""
    print("="*60)
    print("RUNNING UNIT TESTS")
    print("="*60)
    
    try:
        result = subprocess.run([sys.executable, "test_c2_detector.py"], 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running unit tests: {e}")
        return False

def run_integration_tests():
    """Run integration tests with generated PCAP files"""
    print("\n" + "="*60)
    print("RUNNING INTEGRATION TESTS")
    print("="*60)
    
    # Generate test PCAP files
    print("[+] Generating test PCAP files...")
    try:
        subprocess.run([sys.executable, "generate_test_pcap.py"], check=True)
    except Exception as e:
        print(f"Error generating test PCAPs: {e}")
        return False
    
    # Test cases
    test_cases = [
        ("test_pcaps/normal_traffic.pcap", "normal", 0, 5),  # file, type, min_detections, max_detections
        ("test_pcaps/c2_traffic.pcap", "malicious", 10, 100),
        ("test_pcaps/mixed_traffic.pcap", "mixed", 5, 50)
    ]
    
    results = []
    
    for pcap_file, traffic_type, min_det, max_det in test_cases:
        print(f"\n[+] Testing {traffic_type} traffic: {pcap_file}")
        
        if not os.path.exists(pcap_file):
            print(f"    SKIP: {pcap_file} not found")
            results.append(False)
            continue
        
        try:
            # Run detector
            start_time = time.time()
            result = subprocess.run([
                sys.executable, "c2_detector.py", pcap_file, 
                "-o", f"test_results_{traffic_type}.json"
            ], capture_output=True, text=True, timeout=60)
            
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                print(f"    FAIL: Detector returned error code {result.returncode}")
                print(f"    STDERR: {result.stderr}")
                results.append(False)
                continue
            
            # Parse output for threat assessment
            output_lines = result.stdout.split('\n')
            threat_level = "UNKNOWN"
            total_detections = 0
            
            for line in output_lines:
                if "THREAT ASSESSMENT:" in line:
                    threat_level = line.split(":")[-1].strip()
                elif "Signature-based detections:" in line:
                    total_detections += int(line.split(":")[-1].strip())
                elif "ML-based classifications:" in line:
                    total_detections += int(line.split(":")[-1].strip())
                elif "Beaconing patterns:" in line:
                    total_detections += int(line.split(":")[-1].strip())
                elif "Behavioral anomalies:" in line:
                    total_detections += int(line.split(":")[-1].strip())
            
            print(f"    RESULT: Threat Level = {threat_level}, Detections = {total_detections}")
            print(f"    PERFORMANCE: {execution_time:.2f} seconds")
            
            # Validate results
            if traffic_type == "normal":
                success = total_detections <= max_det and threat_level in ["LOW", "MEDIUM"]
            elif traffic_type == "malicious":
                success = total_detections >= min_det and threat_level in ["HIGH", "CRITICAL"]
            else:  # mixed
                success = min_det <= total_detections <= max_det
            
            if success:
                print(f"    PASS: Results within expected range")
            else:
                print(f"    FAIL: Results outside expected range ({min_det}-{max_det} detections)")
            
            results.append(success)
            
        except subprocess.TimeoutExpired:
            print(f"    FAIL: Test timed out after 60 seconds")
            results.append(False)
        except Exception as e:
            print(f"    FAIL: Error running test: {e}")
            results.append(False)
    
    return all(results)

def run_web_app_test():
    """Test web application startup"""
    print("\n" + "="*60)
    print("TESTING WEB APPLICATION")
    print("="*60)
    
    print("[+] Testing Flask app import...")
    try:
        import web_app
        print("    PASS: Web app imports successfully")
        return True
    except Exception as e:
        print(f"    FAIL: Web app import error: {e}")
        return False

def main():
    """Run comprehensive test suite"""
    print("C2 TRAFFIC DETECTION SYSTEM - COMPREHENSIVE TEST SUITE")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    start_time = time.time()
    results = []
    
    # Run all test categories
    test_functions = [
        ("Unit Tests", run_unit_tests),
        ("Integration Tests", run_integration_tests),
        ("Web Application Test", run_web_app_test)
    ]
    
    for test_name, test_func in test_functions:
        print(f"\n[+] Running {test_name}...")
        try:
            success = test_func()
            results.append((test_name, success))
            status = "PASS" if success else "FAIL"
            print(f"[+] {test_name}: {status}")
        except Exception as e:
            print(f"[-] {test_name}: ERROR - {e}")
            results.append((test_name, False))
    
    # Summary
    total_time = time.time() - start_time
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print("\n" + "="*60)
    print("TEST SUITE SUMMARY")
    print("="*60)
    print(f"Total test categories: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success rate: {(passed/total*100):.1f}%")
    print(f"Total execution time: {total_time:.2f} seconds")
    
    print("\nDetailed Results:")
    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} {test_name}")
    
    # Exit with appropriate code
    success_overall = passed == total
    if success_overall:
        print(f"\n🎉 All tests passed! System is ready for deployment.")
    else:
        print(f"\n❌ Some tests failed. Please review and fix issues before deployment.")
    
    return 0 if success_overall else 1

if __name__ == "__main__":
    exit(main())
