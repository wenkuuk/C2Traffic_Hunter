
# C2 Traffic Detection Tool

This tool analyzes PCAP files to detect potential Command and Control (C2) traffic over HTTP protocol.

## Features

- **Suspicious Pattern Detection**: Identifies unusual user agents, URL patterns, and HTTP headers
- **Beaconing Analysis**: Detects regular communication patterns typical of C2 beacons
- **Entropy Analysis**: Identifies high-entropy content that may indicate encrypted payloads
- **Statistical Anomalies**: Flags hosts with unusual traffic patterns
- **File Transfer Detection**: Identifies large data transfers that may be exfiltration

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Make sure you have appropriate permissions to read PCAP files

## Usage

Basic usage:
```bash
python c2_detector.py sample.pcap
```

Save results to JSON file:
```bash
python c2_detector.py sample.pcap -o results.json
```

Verbose output:
```bash
python c2_detector.py sample.pcap -v
```

## Detection Criteria

### Suspicious User Agents
- Outdated browser strings
- Command-line tools (curl, wget)
- Programming language HTTP clients
- Base64-encoded user agents

### URL Patterns
- Hash-like paths (MD5, SHA1)
- Base64-encoded paths
- Timestamp-based paths
- Common C2 endpoints (data, config, update, beacon)

### Beaconing Indicators
- Regular timing intervals (low variance)
- High request frequency to same host
- Repetitive URL patterns

### Content Analysis
- High entropy content (potential encryption)
- Large file transfers
- Base64-encoded payloads

## Output Format

The tool provides both console output and optional JSON export with detailed findings including:
- Suspicious host communications
- Potential beaconing activity
- Flagged HTTP requests with suspicion scores
- File transfer activities
- Statistical analysis results

## Notes

- This tool requires root/administrator privileges on some systems to read PCAP files
- Large PCAP files may take significant time to process
- Results should be manually reviewed as false positives are possible
- The tool focuses on HTTP traffic; HTTPS traffic will show limited analysis
