
# C2 Traffic Detection System - Python Application

This is a comprehensive Python-based application for detecting Command and Control (C2) traffic in network packet captures (PCAP files).

## Features

- **Multi-layered Detection**:
  - Signature-based detection for known malicious patterns
  - Machine learning feature extraction and classification
  - Behavioral analysis for beaconing and anomaly detection

- **Web Interface**: Flask-based web application for easy file upload and analysis
- **Comprehensive Testing**: Unit tests, integration tests, and test data generation
- **Enterprise-grade Reporting**: Detailed threat assessment with confidence scores

## Installation

1. Install required Python packages:
```bash
pip install -r requirements.txt
```

2. Install additional packages for the web application:
```bash
pip install flask werkzeug
```

## Usage

### Command Line Interface

Analyze a PCAP file directly:
```bash
python c2_detector.py traffic.pcap -v -o results.json
```

Options:
- `-v, --verbose`: Show detailed output
- `-o, --output`: Save results to JSON file
- `--threshold`: ML classification threshold (default: 0.5)

### Web Application

1. Start the Flask web server:
```bash
python web_app.py
```

2. Open your browser and navigate to: `http://localhost:5000`

3. Upload a PCAP file and view the analysis results

### Testing

Run the comprehensive test suite:
```bash
python run_tests.py
```

This will:
- Run unit tests for all components
- Generate test PCAP files with different traffic types
- Perform integration testing
- Test web application functionality

## Generate Test Data

Create test PCAP files for validation:
```bash
python generate_test_pcap.py
```

This generates:
- `normal_traffic.pcap`: Clean web browsing traffic
- `c2_traffic.pcap`: Malicious C2 communications
- `mixed_traffic.pcap`: Combination of normal and malicious traffic

## Architecture

### Core Components

1. **AdvancedC2Detector** (`c2_detector.py`): Main detection engine
2. **SignatureEngine** (`signatures.py`): Pattern-based detection
3. **MLFeatureExtractor** (`ml_features.py`): Machine learning features
4. **BehavioralAnalyzer** (`behavioral_analysis.py`): Behavioral pattern analysis

### Detection Methods

1. **Signature Detection**:
   - Malicious domains (onion, DynDNS, direct IPs)
   - Suspicious paths (admin panels, encoded paths)
   - Known malicious user agents
   - C2 header patterns
   - Payload signatures

2. **ML Classification**:
   - Entropy analysis
   - Character frequency patterns
   - Timing features
   - Protocol analysis
   - Response size patterns

3. **Behavioral Analysis**:
   - Beaconing pattern detection
   - User agent diversity analysis
   - Path repetition patterns
   - Response size consistency

### Threat Assessment

The system provides threat levels:
- **LOW**: Minimal suspicious activity
- **MEDIUM**: Some concerning patterns
- **HIGH**: Multiple suspicious indicators
- **CRITICAL**: Strong evidence of C2 activity

## Example Output

```
ADVANCED C2 TRAFFIC ANALYSIS REPORT
====================================

THREAT ASSESSMENT: HIGH
Threat Score: 0.75
Total Sessions Analyzed: 50

DETECTION SUMMARY:
  Signature-based detections: 15
  ML-based classifications: 8
  Beaconing patterns: 2
  Behavioral anomalies: 3

[SIGNATURE] 192.168.1.100 -> 10.0.0.1
  Host: evil.onion
  Path: /gate.php
  Score: 8
  Matches: Malicious domain pattern, Suspicious path

[BEACON] 192.168.1.100->10.0.0.1:evil.onion
  Pattern: regular_beaconing
  Sessions: 25
  Interval: 60.0s
  Confidence: 0.95
```

## Web Interface Features

- **Drag & Drop Upload**: Easy PCAP file upload
- **Real-time Progress**: Live analysis progress updates
- **Interactive Results**: Detailed threat assessment dashboard
- **Visual Indicators**: Color-coded threat levels and detection types
- **Export Results**: Download analysis reports as JSON

## Security Considerations

- File size limits (100MB maximum)
- Secure filename handling
- Input validation for PCAP files
- Temporary file cleanup
- Error handling and logging

## Testing Results

The test suite validates:
- ✓ Signature detection accuracy
- ✓ ML feature extraction
- ✓ Behavioral analysis algorithms
- ✓ Integration with real PCAP data
- ✓ Web application functionality
- ✓ Performance benchmarks

## Performance

- Processes ~1000 packets per second
- Memory usage scales with PCAP size
- Optimized for files up to 100MB
- Multi-threaded analysis support

## Contributing

1. Run tests before submitting changes
2. Follow PEP 8 style guidelines
3. Add test cases for new features
4. Update documentation as needed

## License

This project is for educational and research purposes.
