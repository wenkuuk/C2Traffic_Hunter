
#!/usr/bin/env python3
"""
Behavioral analysis module for C2 traffic detection
"""

import statistics
from collections import defaultdict
from typing import Dict, List


class BehavioralAnalyzer:
    """Analyzes behavioral patterns across multiple sessions"""
    
    def __init__(self):
        self.host_sessions = defaultdict(list)
        self.timing_patterns = defaultdict(list)
        
    def add_session(self, session_data: Dict):
        """Add session for behavioral analysis"""
        host_key = f"{session_data.get('src_ip', '')}->{session_data.get('dst_ip', '')}:{session_data.get('host', '')}"
        self.host_sessions[host_key].append(session_data)
        self.timing_patterns[host_key].append(session_data.get('timestamp', 0))
    
    def analyze_beaconing(self) -> List[Dict]:
        """Detect beaconing patterns"""
        beacon_candidates = []
        
        for host_key, sessions in self.host_sessions.items():
            if len(sessions) < 5:  # Need minimum sessions for pattern detection
                continue
            
            timestamps = [s.get('timestamp', 0) for s in sessions]
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            if not intervals:
                continue
            
            # Statistical analysis of intervals
            mean_interval = statistics.mean(intervals)
            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            cv = std_interval / mean_interval if mean_interval > 0 else 0
            
            # Regular beaconing detection
            if cv < 0.3 and len(sessions) > 10 and mean_interval < 3600:  # Less than 1 hour
                beacon_candidates.append({
                    'host_key': host_key,
                    'session_count': len(sessions),
                    'mean_interval': mean_interval,
                    'std_interval': std_interval,
                    'coefficient_variation': cv,
                    'duration': timestamps[-1] - timestamps[0],
                    'confidence': 1 - cv,
                    'pattern_type': 'regular_beaconing'
                })
        
        return beacon_candidates
    
    def analyze_communication_patterns(self) -> List[Dict]:
        """Analyze communication patterns for anomalies"""
        anomalies = []
        
        for host_key, sessions in self.host_sessions.items():
            if len(sessions) < 3:
                continue
            
            # Analyze user agent diversity
            user_agents = set(s.get('user_agent', '') for s in sessions)
            if len(user_agents) > 5:  # Too many different user agents
                anomalies.append({
                    'host_key': host_key,
                    'anomaly_type': 'user_agent_diversity',
                    'count': len(user_agents),
                    'confidence': min(len(user_agents) / 10, 1.0)
                })
            
            # Analyze path patterns
            paths = [s.get('path', '') for s in sessions]
            unique_paths = set(paths)
            if len(unique_paths) < len(paths) * 0.1:  # Too repetitive
                anomalies.append({
                    'host_key': host_key,
                    'anomaly_type': 'repetitive_paths',
                    'unique_ratio': len(unique_paths) / len(paths),
                    'confidence': 1 - (len(unique_paths) / len(paths))
                })
            
            # Analyze response size patterns
            response_sizes = [s.get('response_size', 0) for s in sessions if s.get('response_size', 0) > 0]
            if len(response_sizes) > 5:
                size_std = statistics.stdev(response_sizes)
                size_mean = statistics.mean(response_sizes)
                if size_std / size_mean < 0.1:  # Very consistent sizes
                    anomalies.append({
                        'host_key': host_key,
                        'anomaly_type': 'consistent_response_sizes',
                        'size_cv': size_std / size_mean,
                        'confidence': 1 - (size_std / size_mean) * 10
                    })
        
        return anomalies
    
    def get_host_statistics(self) -> Dict:
        """Get comprehensive host statistics"""
        stats = {}
        
        for host_key, sessions in self.host_sessions.items():
            if len(sessions) == 0:
                continue
                
            user_agents = set(s.get('user_agent', '') for s in sessions)
            paths = [s.get('path', '') for s in sessions]
            timestamps = [s.get('timestamp', 0) for s in sessions]
            response_sizes = [s.get('response_size', 0) for s in sessions]
            
            # Calculate intervals
            intervals = []
            if len(timestamps) > 1:
                intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            stats[host_key] = {
                'request_count': len(sessions),
                'user_agents': list(user_agents),
                'unique_paths': len(set(paths)),
                'total_paths': len(paths),
                'avg_response_size': sum(response_sizes) / len(response_sizes) if response_sizes else 0,
                'avg_interval': sum(intervals) / len(intervals) if intervals else 0,
                'first_seen': min(timestamps) if timestamps else 0,
                'last_seen': max(timestamps) if timestamps else 0,
                'duration': max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
            }
        
        return stats
