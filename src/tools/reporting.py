
#!/usr/bin/env python3
"""
Reporting module for C2 traffic analysis
"""

from datetime import datetime
from typing import Dict


class ReportGenerator:
    @staticmethod
    def generate_report(results: Dict, host_stats: Dict) -> Dict:
        """Generate analysis report"""
        # Convert sets to lists for JSON serialization
        for host_key, stats in host_stats.items():
            if isinstance(stats.get('user_agents'), set):
                stats['user_agents'] = list(stats['user_agents'])
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'suspicious_hosts': len(results['suspicious_hosts']),
                'beacon_candidates': len(results['beacon_candidates']),
                'suspicious_requests': len(results['suspicious_requests']),
                'file_transfers': len(results['file_transfers']),
                'statistical_anomalies': len(results['statistical_anomalies'])
            },
            'details': dict(results)  # Convert defaultdict to regular dict
        }
        
        return report

    @staticmethod
    def print_detailed_report(report: Dict, verbose: bool = False):
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
