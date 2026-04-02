#!/usr/bin/env python3
"""
IOC-U Enhanced: Advanced Blue Team Detection & Intelligence Tool for Red Team Operations
Version 2.0 - Detecting Blue Team IR/SOC Activities with 2024-2025 capabilities
"""

import argparse
import subprocess
import threading
import os
import json
import sys
import time
import signal
import logging

# Ops hook (safe no-op if c2itall not available)
try:
    sys.path.insert(0, os.path.expanduser("~/tools/c2itall"))
    from utils.ops_hook import OpsHook as _OpsHook
except ImportError:
    _OpsHook = None
import socket
import ipaddress
import re
import hashlib
import struct
import base64
from datetime import datetime, timedelta
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list, DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Warning: scapy not available. Install with: pip install scapy")
from collections import defaultdict, deque, Counter
from typing import Dict, List, Tuple, Optional, Set, Any

# Try to import ML libraries, but make them optional
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  Warning: ML libraries not available. Install with: pip install numpy scikit-learn")

CONFIG_PATH = os.path.expanduser("~/.ioc_u_config.json")
PID_FILE = "/tmp/.ioc_u.pid"
LOG_FILE = "/tmp/.ioc_u.log"
INTELLIGENCE_LOG = os.path.expanduser("~/.ioc_u_intelligence.json")
BEHAVIORAL_MODEL = os.path.expanduser("~/.ioc_u_behavioral_model.pkl")

# Enhanced configuration with AI/ML and modern blue team detection patterns
default_config = {
    "email_enabled": False,
    "alert_email": "",
    "gpg_recipient": "",
    "smtp_configured": False,
    "interface": "auto",
    "detection_threshold": 3,
    "alert_cooldown": 30,
    "stealth_mode": True,
    "canary_ports": [2222, 8888, 5900, 9999, 1433, 3389, 445, 139],
    
    # Enhanced blue team detection settings
    "evidence_collection_threshold": 3,
    "investigation_time_window": 300,
    "systematic_investigation_threshold": 5,
    "behavioral_anomaly_threshold": 0.85,
    
    # AI/ML detection settings
    "enable_ml_detection": True and ML_AVAILABLE,
    "ml_model_update_interval": 3600,
    "anomaly_detection_sensitivity": 0.05,
    
    # Modern SIEM detection patterns (Blue Team Tools)
    "siem_detection_patterns": {
        "splunk": {
            "ports": [8089, 8000, 9997, 8088],
            "patterns": ["splunkd", "search?", "servicesNS", "en-US/app", "SPL-"],
            "risk_based_alerting": ["risk_score", "risk_object", "risk_notable"],
            "charlotte_ai": ["charlotte_ai", "spl_generation", "automated_investigation"]
        },
        "elastic": {
            "ports": [9200, 5601, 9300],
            "patterns": ["_search", "_msearch", ".kibana", "_ml/anomaly_detectors"],
            "ai_patterns": ["attack_discovery", "security_assistant", "ml_job"]
        },
        "sentinel": {
            "ports": [443],
            "patterns": ["SecurityInsights", "ThreatIntelligence", "incidents/", "sentinel"],
            "kql_patterns": ["Kusto.Language", "summarize", "project", "where"]
        },
        "chronicle": {
            "ports": [443],
            "patterns": ["chronicle.security", "yaral", "udm_search", "retrohunt"],
            "detection_patterns": ["rule_engine", "threat_graph", "entity_graph"]
        },
        "qradar": {
            "ports": [443, 514, 1514],
            "patterns": ["console/restapi", "ariel", "reference_data", "offense"],
            "offense_patterns": ["offense_id", "rule_id", "qidmap"]
        },
        "sumo_logic": {
            "ports": [443],
            "patterns": ["sumologic", "api/v1/search", "insight_trainer"],
            "ml_patterns": ["outlier_detection", "baseline_learning"]
        }
    },
    
    # EDR/XDR detection patterns (Blue Team Endpoint Tools)
    "edr_detection_patterns": {
        "crowdstrike": {
            "ports": [443, 8080],
            "patterns": ["falcon", "cs-falcon", "crowdstrike", "falconhoseclient"],
            "behavioral_ioas": ["ProcessRollup", "DnsRequest", "NetworkConnect"],
            "hardware_enhanced": ["intel_processor_trace", "rop_detection"],
            "charlotte_ai": ["threat_graph", "automated_remediation"]
        },
        "sentinelone": {
            "ports": [443],
            "patterns": ["sentinelone", "mgmt.sentinelone", "sentinelagent", "s1-"],
            "ai_engine": ["static_ai", "behavioral_ai", "purple_ai"],
            "dbt_tracking": ["dynamic_behavioral_tracking", "storyline"]
        },
        "defender": {
            "ports": [443],
            "patterns": ["defender", "mdatp", "windowsdefender", "sense.exe", "mssense"],
            "advanced_hunting": ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents"],
            "edr_block_mode": ["passive_mode_block", "post_breach_detection"]
        },
        "cortex_xdr": {
            "ports": [443],
            "patterns": ["cortex", "xdr", "paloaltonetworks", "traps"],
            "ml_models": ["ensemble_learning", "local_analysis", "causality_analysis"],
            "behavioral_threat": ["bioc", "analytics_engine"]
        },
        "carbon_black": {
            "ports": [443],
            "patterns": ["carbonblack", "cb.defense", "cbcloud", "confer"],
            "live_response": ["lr_session", "process_search", "cblr"]
        },
        "cybereason": {
            "ports": [443, 8443],
            "patterns": ["cybereason", "malop", "cybereason-sensor"],
            "ai_detection": ["malop_detection", "root_cause_analysis"]
        }
    },
    
    # Network monitoring and NDR patterns (Blue Team Network Tools)
    "ndr_patterns": {
        "darktrace": {
            "ports": [443],
            "patterns": ["darktrace", "immune_system", "antigena", "cyber-ai"],
            "ai_patterns": ["pattern_of_life", "self_learning", "autonomous_response", "threat_visualizer"]
        },
        "vectra": {
            "ports": [443, 8443],
            "patterns": ["vectra", "cognito", "attack_signal", "vectra-brain"],
            "detection_types": ["account_takeover", "lateral_movement", "data_smuggling", "command_control"]
        },
        "extrahop": {
            "ports": [443],
            "patterns": ["extrahop", "revealx", "extrahop-monitor"],
            "protocol_analysis": ["wire_data", "l7_visibility", "ssl_decrypt"]
        },
        "corelight": {
            "ports": [443, 47760],
            "patterns": ["corelight", "zeek", "bro-", "corelight-sensor"],
            "log_types": ["conn.log", "dns.log", "http.log", "ssl.log", "files.log"]
        },
        "netwitness": {
            "ports": [443, 50103, 56003],
            "patterns": ["netwitness", "rsa-nw", "decoder", "concentrator"],
            "analysis": ["meta_extraction", "session_reconstruction"]
        }
    },
    
    # Advanced forensic patterns (Blue Team Investigation Tools)
    "forensic_patterns": {
        "memory_analysis": [
            r'volatility', r'rekall', r'winpmem', r'dumpit', r'redline',
            r'malfind', r'psscan', r'dlllist', r'handles', r'vadscan',
            r'\.vmem$', r'\.raw$', r'\.dmp$', r'hiberfil\.sys', r'pagefile\.sys'
        ],
        "artifact_collection": [
            r'kape\.exe', r'ftk', r'encase', r'x-ways', r'axiom', r'autopsy',
            r'MFT', r'USN.*journal', r'\.evtx', r'prefetch', r'jumplist',
            r'shimcache', r'amcache', r'registry.*hive', r'ntuser\.dat'
        ],
        "cloud_forensics": [
            r'cloudtrail', r'azure.*activity', r'stackdriver', r'flowlogs',
            r'snapshot', r'forensic.*image', r'vpc.*flow', r'cloud.*logs'
        ],
        "threat_hunting": [
            r'osquery', r'velociraptor', r'grr.*client', r'fleet',
            r'yara', r'sigma', r'hayabusa', r'chainsaw', r'deepsearch'
        ]
    },
    
    # Blue team PowerShell commands
    "powershell_investigation": [
        "Get-WinEvent", "Get-EventLog", "Get-Process", "Get-Service",
        "Get-NetTCPConnection", "Get-NetUDPEndpoint", "Get-SmbConnection",
        "Get-ChildItem", "Get-Content", "Get-FileHash", "Get-ItemProperty",
        "Get-LocalUser", "Get-LocalGroupMember", "Get-ScheduledTask",
        "Get-CimInstance", "Invoke-Command", "Enter-PSSession"
    ],
    
    # WMI investigation queries
    "wmi_investigation": [
        "Win32_Process", "Win32_Service", "Win32_LoggedOnUser",
        "Win32_NetworkConnection", "Win32_StartupCommand",
        "Win32_ScheduledJob", "Win32_Share", "Win32_UserAccount"
    ],
    
    # SOAR platform patterns (Blue Team Automation)
    "soar_patterns": {
        "platforms": ["phantom", "xsoar", "swimlane", "siemplify", "securonix", "resilient"],
        "playbooks": ["automated_response", "enrichment", "containment", "remediation"],
        "integrations": ["threat_intel", "sandbox_analysis", "reputation_check"]
    },
    
    # Operational filtering (Red Team Protection)
    "trusted_networks": [],
    "operator_ips": [],
    "reverse_shell_ports": list(range(4444, 4500)) + list(range(8080, 8090)) + [1337, 31337, 9001],
    "session_timeout": 3600,
    
    # Intelligence settings
    "intelligence_mode": True,
    "intelligence_retention_days": 7,
    "alert_on_investigation_only": True,
    
    # Purple team settings
    "purple_team_mode": False,
    "noise_escalation_level": 1,
    "detection_testing_mode": False
}

class BlueTeamActivityDetector:
    """Detects blue team IR and SOC investigation activities"""
    
    def __init__(self, config):
        self.config = config
        
        # Blue team investigation patterns
        self.investigation_commands = [
            # Windows commands
            r'tasklist', r'netstat', r'net\s+\w+', r'wmic', r'systeminfo',
            r'reg\s+query', r'dir\s*/s', r'findstr', r'type\s+\w+\.log',
            
            # Linux commands  
            r'ps\s+aux', r'netstat\s+-[tulpn]+', r'lsof', r'find\s+/', 
            r'grep\s+-r', r'tail\s+-f', r'journalctl', r'ausearch',
            
            # Investigation tools
            r'nmap', r'masscan', r'zmap', r'shodan', r'censys',
            r'nikto', r'dirb', r'gobuster', r'burpsuite', r'zap'
        ]
        
        # Blue team user agents
        self.blue_team_agents = [
            r'splunk', r'elastic', r'kibana', r'qradar', r'sentinel',
            r'crowdstrike', r'sentinelone', r'carbon.*black', r'defender',
            r'python.*requests', r'powershell', r'curl/', r'wget/'
        ]
        
        # Evidence collection indicators
        self.evidence_indicators = [
            'collect', 'acquire', 'evidence', 'forensic', 'artifact',
            'investigation', 'incident', 'compromise', 'breach', 'malware'
        ]

class NetworkFlowAnalyzer:
    """Analyzes network flows for blue team investigation patterns"""
    
    def __init__(self, config):
        self.config = config
        self.connection_tracker = defaultdict(list)
        self.investigation_patterns = defaultdict(Counter)
        
    def track_connection(self, src_ip, dst_ip, dst_port, payload, timestamp):
        """Track connections for pattern analysis"""
        connection = {
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'timestamp': timestamp,
            'payload_size': len(payload) if payload else 0,
            'payload_hash': hashlib.md5(payload.encode() if payload else b'').hexdigest()
        }
        
        self.connection_tracker[src_ip].append(connection)
        
        # Keep only recent connections
        cutoff = timestamp - self.config['investigation_time_window']
        self.connection_tracker[src_ip] = [
            c for c in self.connection_tracker[src_ip] 
            if c['timestamp'] > cutoff
        ]
    
    def detect_systematic_investigation(self, src_ip):
        """Detect systematic blue team investigation patterns"""
        connections = self.connection_tracker.get(src_ip, [])
        
        if len(connections) < self.config['systematic_investigation_threshold']:
            return None
        
        # Pattern 1: Multiple hosts being investigated (IOC sweeping)
        unique_targets = len(set(c['dst_ip'] for c in connections))
        if unique_targets >= 5:
            return {
                'type': 'BLUE_TEAM_IOC_SWEEP',
                'details': f'Blue team scanning {unique_targets} hosts',
                'severity': 'HIGH'
            }
        
        # Pattern 2: Multiple ports on same host (host investigation)
        for dst_ip in set(c['dst_ip'] for c in connections):
            host_connections = [c for c in connections if c['dst_ip'] == dst_ip]
            unique_ports = len(set(c['dst_port'] for c in host_connections))
            
            if unique_ports >= 10:
                return {
                    'type': 'BLUE_TEAM_HOST_INVESTIGATION',
                    'details': f'Blue team investigating {dst_ip} ({unique_ports} ports)',
                    'severity': 'HIGH'
                }
        
        # Pattern 3: Repeated queries (persistence checking)
        payload_counts = Counter(c['payload_hash'] for c in connections)
        repeated_queries = [h for h, count in payload_counts.items() if count >= 3]
        
        if repeated_queries:
            return {
                'type': 'BLUE_TEAM_PERSISTENCE_CHECK',
                'details': 'Blue team checking for persistence/IOCs repeatedly',
                'severity': 'MEDIUM'
            }
        
        return None

class BlueTeamIntelligence:
    """Intelligence gathering on blue team activities"""
    
    def __init__(self, config):
        self.config = config
        self.blue_team_activities = defaultdict(list)
        self.investigation_timeline = defaultdict(list)
        self.detected_platforms = Counter()
        self.investigation_techniques = Counter()
        self.load_intelligence()
    
    def load_intelligence(self):
        """Load existing intelligence data"""
        if os.path.exists(INTELLIGENCE_LOG):
            try:
                with open(INTELLIGENCE_LOG, 'r') as f:
                    data = json.load(f)
                    
                    # Restore counters and data
                    if 'detected_platforms' in data:
                        self.detected_platforms = Counter(data['detected_platforms'])
                    
                    if 'investigation_techniques' in data:
                        self.investigation_techniques = Counter(data['investigation_techniques'])
                        
            except Exception as e:
                logging.error(f"Could not load intelligence: {e}")
    
    def save_intelligence(self):
        """Save intelligence data"""
        try:
            data = {
                'last_updated': datetime.now().isoformat(),
                'detected_platforms': dict(self.detected_platforms),
                'investigation_techniques': dict(self.investigation_techniques),
                'timeline_entries': len(self.investigation_timeline)
            }
            
            with open(INTELLIGENCE_LOG, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logging.error(f"Could not save intelligence: {e}")
    
    def record_blue_team_activity(self, src_ip, activity_type, platform, details):
        """Record blue team activity"""
        timestamp = datetime.now()
        
        activity = {
            'timestamp': timestamp.isoformat(),
            'src_ip': src_ip,
            'type': activity_type,
            'platform': platform,
            'details': details
        }
        
        self.blue_team_activities[src_ip].append(activity)
        self.investigation_timeline[timestamp.date().isoformat()].append(activity)
        
        if platform:
            self.detected_platforms[platform] += 1
        
        self.investigation_techniques[activity_type] += 1
    
    def get_threat_assessment(self):
        """Generate blue team threat assessment"""
        assessment = {
            'active_investigators': [],
            'investigation_intensity': 'LOW',
            'primary_platforms': [],
            'investigation_focus': [],
            'recommendations': []
        }
        
        # Analyze active investigators
        current_time = datetime.now()
        for src_ip, activities in self.blue_team_activities.items():
            recent_activities = [
                a for a in activities 
                if (current_time - datetime.fromisoformat(a['timestamp'])).seconds < 3600
            ]
            
            if recent_activities:
                assessment['active_investigators'].append({
                    'ip': src_ip,
                    'activity_count': len(recent_activities),
                    'platforms': list(set(a.get('platform', 'Unknown') for a in recent_activities))
                })
        
        # Determine investigation intensity
        total_recent_activities = sum(
            len([a for a in activities 
                 if (current_time - datetime.fromisoformat(a['timestamp'])).seconds < 3600])
            for activities in self.blue_team_activities.values()
        )
        
        if total_recent_activities > 50:
            assessment['investigation_intensity'] = 'CRITICAL'
        elif total_recent_activities > 20:
            assessment['investigation_intensity'] = 'HIGH'
        elif total_recent_activities > 5:
            assessment['investigation_intensity'] = 'MEDIUM'
        
        # Primary platforms
        assessment['primary_platforms'] = [
            platform for platform, count in self.detected_platforms.most_common(5)
        ]
        
        # Investigation focus
        assessment['investigation_focus'] = [
            technique for technique, count in self.investigation_techniques.most_common(5)
        ]
        
        # Generate recommendations
        if assessment['investigation_intensity'] in ['HIGH', 'CRITICAL']:
            assessment['recommendations'].append(
                "CRITICAL: Active blue team investigation detected. Consider pausing operations."
            )
        
        if 'EDR' in str(assessment['primary_platforms']):
            assessment['recommendations'].append(
                "HIGH: EDR platform active. Ensure anti-EDR measures are in place."
            )
        
        if 'MEMORY_FORENSICS' in assessment['investigation_focus']:
            assessment['recommendations'].append(
                "HIGH: Memory forensics detected. Clear memory artifacts and avoid process injection."
            )
        
        return assessment

if ML_AVAILABLE:
    class MLBehavioralEngine:
        """ML-based behavioral analysis for blue team detection"""
        
        def __init__(self, config):
            self.config = config
            self.scaler = StandardScaler()
            self.anomaly_detector = IsolationForest(
                contamination=config['anomaly_detection_sensitivity'],
                random_state=42,
                n_estimators=100
            )
            self.baselines = defaultdict(lambda: deque(maxlen=1000))
            self.is_trained = False
        
        def extract_features(self, connection_data):
            """Extract features for ML analysis"""
            features = []
            
            # Connection patterns
            features.append(len(connection_data))  # Connection count
            features.append(len(set(c.get('dst_ip', '') for c in connection_data)))  # Unique destinations
            features.append(len(set(c.get('dst_port', 0) for c in connection_data)))  # Unique ports
            
            # Temporal patterns
            if len(connection_data) > 1:
                timestamps = [c.get('timestamp', 0) for c in connection_data]
                time_deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                features.append(np.mean(time_deltas) if time_deltas else 0)
                features.append(np.std(time_deltas) if time_deltas else 0)
            else:
                features.extend([0, 0])
            
            # Data transfer patterns
            total_bytes = sum(c.get('bytes', 0) for c in connection_data)
            features.append(total_bytes)
            
            return np.array(features).reshape(1, -1)
        
        def detect_anomaly(self, src_ip, connection_data):
            """Detect anomalous blue team behavior"""
            if len(connection_data) < 10:
                return None
            
            features = self.extract_features(connection_data)
            
            # Update baseline
            self.baselines[src_ip].extend(connection_data)
            
            # Need enough data to train
            if len(self.baselines[src_ip]) < 100:
                return None
            
            # Train or update model
            if not self.is_trained or len(self.baselines[src_ip]) % 100 == 0:
                all_features = []
                for baseline_data in self.baselines.values():
                    if len(baseline_data) >= 50:
                        all_features.append(self.extract_features(list(baseline_data)))
                
                if len(all_features) >= 5:
                    X = np.vstack(all_features)
                    X_scaled = self.scaler.fit_transform(X)
                    self.anomaly_detector.fit(X_scaled)
                    self.is_trained = True
            
            if self.is_trained:
                # Detect anomaly
                scaled_features = self.scaler.transform(features)
                anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
                is_anomaly = self.anomaly_detector.predict(scaled_features)[0] == -1
                
                if is_anomaly:
                    return {
                        'type': 'ML_BLUE_TEAM_ANOMALY',
                        'details': f'Anomalous blue team behavior detected (score: {anomaly_score:.2f})',
                        'severity': 'HIGH' if anomaly_score < -0.5 else 'MEDIUM'
                    }
            
            return None

class ModernSIEMDetector:
    """Detection engine for modern SIEM platforms used by blue teams"""
    
    def __init__(self, config):
        self.config = config
        self.siem_patterns = config['siem_detection_patterns']
    
    def detect_siem_activity(self, src_ip, dst_ip, dst_port, payload):
        """Detect SIEM platform activities from blue teams"""
        if not payload:
            return None
        
        payload_lower = payload.lower()
        
        # Check each SIEM platform
        for platform, patterns in self.siem_patterns.items():
            # Port-based detection
            if dst_port in patterns['ports']:
                # Check standard patterns
                for pattern in patterns['patterns']:
                    if pattern.lower() in payload_lower:
                        return {
                            'type': 'BLUE_TEAM_SIEM_QUERY',
                            'platform': platform.upper(),
                            'details': f'{platform} SIEM query detected: {pattern}',
                            'severity': 'HIGH'
                        }
                
                # Check AI-enhanced patterns
                if 'charlotte_ai' in patterns:
                    for ai_pattern in patterns['charlotte_ai']:
                        if ai_pattern in payload_lower:
                            return {
                                'type': 'BLUE_TEAM_AI_INVESTIGATION',
                                'platform': platform.upper(),
                                'details': f'{platform} AI-powered investigation: {ai_pattern}',
                                'severity': 'CRITICAL'
                            }
                
                # Risk-based alerting (Splunk)
                if platform == 'splunk' and 'risk_based_alerting' in patterns:
                    for rba_pattern in patterns['risk_based_alerting']:
                        if rba_pattern in payload_lower:
                            return {
                                'type': 'BLUE_TEAM_RISK_INVESTIGATION',
                                'platform': 'SPLUNK',
                                'details': 'Splunk Risk-Based Alerting investigation',
                                'severity': 'HIGH'
                            }
                
                # KQL queries (Sentinel)
                if platform == 'sentinel' and 'kql_patterns' in patterns:
                    for kql_pattern in patterns['kql_patterns']:
                        if kql_pattern in payload_lower:
                            return {
                                'type': 'BLUE_TEAM_KQL_HUNTING',
                                'platform': 'SENTINEL',
                                'details': 'Microsoft Sentinel KQL threat hunting',
                                'severity': 'HIGH'
                            }
        
        return None

class EDRXDRDetector:
    """Detection for EDR/XDR platforms used by blue teams"""
    
    def __init__(self, config):
        self.config = config
        self.edr_patterns = config['edr_detection_patterns']
    
    def detect_edr_activity(self, src_ip, dst_ip, dst_port, payload):
        """Detect EDR/XDR blue team activities"""
        if not payload:
            return None
        
        payload_lower = payload.lower()
        
        for platform, patterns in self.edr_patterns.items():
            if dst_port in patterns['ports']:
                # Standard pattern detection
                for pattern in patterns['patterns']:
                    if pattern.lower() in payload_lower:
                        return {
                            'type': 'BLUE_TEAM_EDR_SCAN',
                            'platform': platform.upper(),
                            'details': f'{platform} EDR scanning activity',
                            'severity': 'HIGH'
                        }
                
                # Behavioral IOA detection
                if 'behavioral_ioas' in patterns:
                    for ioa in patterns['behavioral_ioas']:
                        if ioa.lower() in payload_lower:
                            return {
                                'type': 'BLUE_TEAM_BEHAVIORAL_DETECTION',
                                'platform': platform.upper(),
                                'details': f'{platform} behavioral analysis: {ioa}',
                                'severity': 'CRITICAL'
                            }
                
                # Advanced hunting (Defender)
                if platform == 'defender' and 'advanced_hunting' in patterns:
                    for hunt_query in patterns['advanced_hunting']:
                        if hunt_query.lower() in payload_lower:
                            return {
                                'type': 'BLUE_TEAM_ADVANCED_HUNTING',
                                'platform': 'DEFENDER',
                                'details': f'Defender ATP hunting: {hunt_query}',
                                'severity': 'HIGH'
                            }
        
        return None

class NetworkMonitorDetector:
    """Detection for NDR and network monitoring by blue teams"""
    
    def __init__(self, config):
        self.config = config
        self.ndr_patterns = config['ndr_patterns']
    
    def detect_ndr_activity(self, src_ip, dst_ip, dst_port, payload):
        """Detect network monitoring by blue teams"""
        if not payload:
            return None
        
        payload_lower = payload.lower()
        
        for platform, patterns in self.ndr_patterns.items():
            if dst_port in patterns.get('ports', []):
                for pattern in patterns['patterns']:
                    if pattern.lower() in payload_lower:
                        # Check for AI patterns
                        if 'ai_patterns' in patterns:
                            for ai_pattern in patterns['ai_patterns']:
                                if ai_pattern.lower() in payload_lower:
                                    return {
                                        'type': 'BLUE_TEAM_AI_NDR',
                                        'platform': platform.upper(),
                                        'details': f'{platform} AI network analysis: {ai_pattern}',
                                        'severity': 'CRITICAL'
                                    }
                        
                        return {
                            'type': 'BLUE_TEAM_NETWORK_MONITORING',
                            'platform': platform.upper(),
                            'details': f'{platform} network monitoring detected',
                            'severity': 'MEDIUM'
                        }
        
        return None

class ForensicsDetector:
    """Detection for blue team forensics and threat hunting"""
    
    def __init__(self, config):
        self.config = config
        self.forensic_patterns = config['forensic_patterns']
        self.powershell_cmds = config['powershell_investigation']
        self.wmi_queries = config['wmi_investigation']
    
    def detect_forensic_activity(self, payload):
        """Detect forensic investigation by blue teams"""
        if not payload:
            return None
        
        payload_lower = payload.lower()
        
        # Memory forensics detection
        for pattern in self.forensic_patterns['memory_analysis']:
            if re.search(pattern, payload_lower):
                return {
                    'type': 'BLUE_TEAM_MEMORY_FORENSICS',
                    'details': f'Memory forensics detected: {pattern}',
                    'severity': 'CRITICAL'
                }
        
        # Artifact collection
        for pattern in self.forensic_patterns['artifact_collection']:
            if re.search(pattern, payload_lower):
                return {
                    'type': 'BLUE_TEAM_ARTIFACT_COLLECTION',
                    'details': f'Artifact collection detected: {pattern}',
                    'severity': 'HIGH'
                }
        
        # PowerShell investigation
        for cmd in self.powershell_cmds:
            if cmd.lower() in payload_lower:
                return {
                    'type': 'BLUE_TEAM_POWERSHELL_INVESTIGATION',
                    'details': f'PowerShell investigation command: {cmd}',
                    'severity': 'HIGH'
                }
        
        # WMI queries
        for query in self.wmi_queries:
            if query.lower() in payload_lower:
                return {
                    'type': 'BLUE_TEAM_WMI_QUERY',
                    'details': f'WMI investigation query: {query}',
                    'severity': 'HIGH'
                }
        
        # Threat hunting tools
        for pattern in self.forensic_patterns['threat_hunting']:
            if re.search(pattern, payload_lower):
                return {
                    'type': 'BLUE_TEAM_THREAT_HUNTING',
                    'details': f'Threat hunting tool detected: {pattern}',
                    'severity': 'HIGH'
                }
        
        return None

class EnhancedBlueTeamDetector:
    """Main detection engine for blue team activities"""
    
    def __init__(self, config):
        self.config = config
        
        # Initialize detectors
        self.activity_detector = BlueTeamActivityDetector(config)
        self.flow_analyzer = NetworkFlowAnalyzer(config)
        self.intelligence = BlueTeamIntelligence(config)
        self.siem_detector = ModernSIEMDetector(config)
        self.edr_detector = EDRXDRDetector(config)
        self.ndr_detector = NetworkMonitorDetector(config)
        self.forensics_detector = ForensicsDetector(config)
        
        if ML_AVAILABLE and config.get('enable_ml_detection'):
            self.ml_engine = MLBehavioralEngine(config)
        else:
            self.ml_engine = None
        
        # Tracking
        self.activity_tracker = defaultdict(lambda: {
            'connections': deque(maxlen=1000),
            'detections': deque(maxlen=100),
            'last_seen': time.time()
        })
        
        # Process management
        self.running = True
        self.canary_threads = []
        self.local_ip = self.get_local_ip()
        self.last_alert_time = defaultdict(float)
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        if self.config.get('stealth_mode'):
            logging.basicConfig(level=logging.WARNING, format=log_format)
        else:
            logging.basicConfig(
                level=logging.INFO,
                format=log_format,
                handlers=[
                    logging.FileHandler(LOG_FILE),
                    logging.StreamHandler()
                ]
            )
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def packet_inspector(self, pkt):
        """Inspect packets for blue team activity"""
        if not IP in pkt:
            return
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Skip trusted traffic (red team's own traffic)
        if self._is_trusted_traffic(src_ip, dst_ip):
            return
        
        # Extract packet info
        packet_info = self._extract_packet_info(pkt)
        if not packet_info:
            return
        
        packet_info['dst_ip'] = dst_ip
        
        # Track connections
        self.flow_analyzer.track_connection(
            src_ip, dst_ip, 
            packet_info.get('dst_port', 0),
            packet_info.get('payload', ''),
            packet_info['timestamp']
        )
        
        # Update activity tracking
        self._update_activity_tracking(src_ip, packet_info)
        
        # Perform detection
        detections = self._perform_detection(src_ip, dst_ip, packet_info)
        
        # Process detections
        if detections:
            self._process_detections(src_ip, dst_ip, detections)
    
    def _extract_packet_info(self, pkt):
        """Extract relevant packet information"""
        info = {
            'timestamp': time.time(),
            'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
        }
        
        if TCP in pkt:
            info['src_port'] = pkt[TCP].sport
            info['dst_port'] = pkt[TCP].dport
            info['tcp_flags'] = str(pkt[TCP].flags)
        elif UDP in pkt:
            info['src_port'] = pkt[UDP].sport
            info['dst_port'] = pkt[UDP].dport
        else:
            return None
        
        if Raw in pkt:
            try:
                info['payload'] = pkt[Raw].load.decode(errors='ignore')
                info['payload_size'] = len(pkt[Raw].load)
            except:
                info['payload'] = None
                info['payload_size'] = 0
        else:
            info['payload'] = None
            info['payload_size'] = 0
        
        return info
    
    def _update_activity_tracking(self, src_ip, packet_info):
        """Update activity tracking"""
        tracker = self.activity_tracker[src_ip]
        
        conn_info = {
            'timestamp': packet_info['timestamp'],
            'dst_ip': packet_info.get('dst_ip', ''),
            'dst_port': packet_info.get('dst_port', 0),
            'protocol': packet_info['protocol'],
            'bytes': packet_info.get('payload_size', 0)
        }
        
        tracker['connections'].append(conn_info)
        tracker['last_seen'] = packet_info['timestamp']
    
    def _perform_detection(self, src_ip, dst_ip, packet_info):
        """Perform multi-engine detection"""
        detections = []
        
        # SIEM detection
        siem_result = self.siem_detector.detect_siem_activity(
            src_ip, dst_ip,
            packet_info.get('dst_port', 0),
            packet_info.get('payload', '')
        )
        if siem_result:
            detections.append(siem_result)
        
        # EDR detection
        edr_result = self.edr_detector.detect_edr_activity(
            src_ip, dst_ip,
            packet_info.get('dst_port', 0),
            packet_info.get('payload', '')
        )
        if edr_result:
            detections.append(edr_result)
        
        # NDR detection
        ndr_result = self.ndr_detector.detect_ndr_activity(
            src_ip, dst_ip,
            packet_info.get('dst_port', 0),
            packet_info.get('payload', '')
        )
        if ndr_result:
            detections.append(ndr_result)
        
        # Forensics detection
        forensics_result = self.forensics_detector.detect_forensic_activity(
            packet_info.get('payload', '')
        )
        if forensics_result:
            detections.append(forensics_result)
        
        # Flow analysis
        flow_result = self.flow_analyzer.detect_systematic_investigation(src_ip)
        if flow_result:
            detections.append(flow_result)
        
        # ML detection if available
        if self.ml_engine:
            ml_result = self.ml_engine.detect_anomaly(
                src_ip,
                list(self.activity_tracker[src_ip]['connections'])
            )
            if ml_result:
                detections.append(ml_result)
        
        # Canary detection
        if packet_info.get('dst_port', 0) in self.config['canary_ports']:
            detections.append({
                'type': 'BLUE_TEAM_CANARY_INVESTIGATION',
                'details': f'Blue team accessed canary port {packet_info["dst_port"]}',
                'severity': 'CRITICAL'
            })
        
        return detections
    
    def _process_detections(self, src_ip, dst_ip, detections):
        """Process and handle detections"""
        # Update tracking
        tracker = self.activity_tracker[src_ip]
        for detection in detections:
            tracker['detections'].append({
                'timestamp': time.time(),
                'detection': detection
            })
            
            # Record in intelligence
            platform = detection.get('platform', 'Unknown')
            self.intelligence.record_blue_team_activity(
                src_ip,
                detection['type'],
                platform,
                detection['details']
            )
        
        # Determine if alert needed
        highest_severity = self._get_highest_severity(detections)
        
        should_alert = False
        if self.config.get('alert_on_investigation_only'):
            # Only alert on active investigation
            investigation_types = [
                'BLUE_TEAM_CANARY_INVESTIGATION',
                'BLUE_TEAM_MEMORY_FORENSICS',
                'BLUE_TEAM_HOST_INVESTIGATION',
                'BLUE_TEAM_AI_INVESTIGATION',
                'ML_BLUE_TEAM_ANOMALY'
            ]
            should_alert = any(d['type'] in investigation_types for d in detections)
        else:
            should_alert = highest_severity in ['HIGH', 'CRITICAL']
        
        # Alert if targeting our machine
        if dst_ip == self.local_ip:
            should_alert = True
        
        if should_alert and self._check_alert_cooldown(src_ip):
            self._handle_alert(src_ip, detections, highest_severity)
    
    def _get_highest_severity(self, detections):
        """Get highest severity from detections"""
        severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        
        if not detections:
            return 'LOW'
        
        highest = max(detections, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 0))
        return highest.get('severity', 'MEDIUM')
    
    def _check_alert_cooldown(self, src_ip):
        """Check alert cooldown"""
        current_time = time.time()
        if current_time - self.last_alert_time[src_ip] < self.config["alert_cooldown"]:
            return False
        self.last_alert_time[src_ip] = current_time
        return True
    
    def _handle_alert(self, src_ip, detections, severity):
        """Handle blue team detection alerts"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build alert
        alert_lines = [f"\n{'='*60}"]
        alert_lines.append(f"🚨 BLUE TEAM DETECTION - {severity}")
        alert_lines.append(f"Time: {timestamp}")
        alert_lines.append(f"Source: {src_ip}")
        alert_lines.append(f"{'='*60}")
        
        for detection in detections:
            alert_lines.append(f"\n🔍 {detection['type']}")
            alert_lines.append(f"   {detection['details']}")
            if 'platform' in detection:
                alert_lines.append(f"   Platform: {detection['platform']}")
            alert_lines.append(f"   Severity: {detection.get('severity', 'UNKNOWN')}")
        
        # Add recommendations
        recommendations = self._generate_recommendations(detections)
        if recommendations:
            alert_lines.append(f"\n💡 RECOMMENDATIONS:")
            for rec in recommendations:
                alert_lines.append(f"   • {rec}")
        
        alert_lines.append(f"\n{'='*60}\n")
        
        alert_message = '\n'.join(alert_lines)
        
        # Output alert
        print(alert_message)
        logging.warning(alert_message)
        
        # CLI notification
        self._cli_notification(src_ip, severity, detections[0]['type'])
        
        # Email alert if configured
        if self.config["email_enabled"]:
            threading.Thread(
                target=self._send_encrypted_email,
                args=(f"[IOC-U] Blue Team {severity} Alert", alert_message),
                daemon=True
            ).start()
    
    def _generate_recommendations(self, detections):
        """Generate recommendations based on detections"""
        recommendations = []
        
        detection_types = [d['type'] for d in detections]
        
        if 'BLUE_TEAM_MEMORY_FORENSICS' in detection_types:
            recommendations.append("CRITICAL: Memory forensics detected - clear memory artifacts immediately")
            recommendations.append("Avoid process injection and in-memory techniques")
        
        if 'BLUE_TEAM_CANARY_INVESTIGATION' in detection_types:
            recommendations.append("CRITICAL: Canary triggered - blue team is actively investigating")
            recommendations.append("Consider pausing all operations")
        
        if any('EDR' in d.get('platform', '') for d in detections):
            recommendations.append("HIGH: EDR platform detected - verify anti-EDR measures")
            recommendations.append("Use encrypted communications and obfuscation")
        
        if any('AI' in d['type'] for d in detections):
            recommendations.append("HIGH: AI-powered investigation detected")
            recommendations.append("Vary tactics and avoid patterns")
        
        if 'BLUE_TEAM_IOC_SWEEP' in detection_types:
            recommendations.append("MEDIUM: IOC sweep in progress - rotate infrastructure")
        
        return recommendations
    
    def _cli_notification(self, src_ip, severity, detection_type):
        """CLI notification for blue team detection"""
        import shlex
        timestamp = datetime.now().strftime("%H:%M:%S")

        severity_config = {
            "CRITICAL": {"repeat": 10, "color": "\033[91m"},  # Red
            "HIGH": {"repeat": 6, "color": "\033[93m"},       # Yellow
            "MEDIUM": {"repeat": 3, "color": "\033[94m"},     # Blue
            "LOW": {"repeat": 1, "color": "\033[92m"}         # Green
        }

        config = severity_config.get(severity, severity_config["MEDIUM"])

        # Sanitize all external inputs to prevent shell injection
        safe_src_ip = shlex.quote(str(src_ip))
        safe_severity = shlex.quote(str(severity))
        safe_detection_type = shlex.quote(str(detection_type))
        safe_timestamp = shlex.quote(timestamp)

        notification_cmd = f"""
        (for i in {{1..{config['repeat']}}}; do
            echo -ne "\\a\\033[?5h";
            sleep 0.2;
            echo -ne "\\033[?5l";
            sleep 0.2;
        done && echo -e "\\n{config['color']}[{safe_severity}] [{safe_timestamp}] BLUE TEAM: {safe_detection_type} from {safe_src_ip}\\033[0m") &
        """

        subprocess.Popen(notification_cmd, shell=True, executable='/bin/bash')
    
    def _send_encrypted_email(self, subject, message):
        """Send encrypted email alert"""
        try:
            # Prepare email
            email_body = f"Subject: {subject}\n"
            email_body += f"From: IOC-U Blue Team Detection\n"
            email_body += f"To: {self.config['alert_email']}\n\n"
            email_body += message
            email_body += f"\n\nTarget: {self.local_ip}"
            
            # Encrypt with GPG
            gpg_process = subprocess.Popen(
                ['gpg', '--encrypt', '--armor', '--trust-model', 'always', 
                 '-r', self.config["gpg_recipient"]],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            encrypted_data, _ = gpg_process.communicate(email_body.encode())
            
            if gpg_process.returncode != 0:
                logging.error("GPG encryption failed")
                return False
            
            # Send via ssmtp
            ssmtp_process = subprocess.Popen(
                ['ssmtp', self.config["alert_email"]],
                stdin=subprocess.PIPE, stderr=subprocess.PIPE
            )
            ssmtp_process.communicate(encrypted_data)
            
            return ssmtp_process.returncode == 0
            
        except Exception as e:
            logging.error(f"Email alert error: {e}")
            return False
    
    def _is_trusted_traffic(self, src_ip, dst_ip):
        """Check if traffic is from trusted sources (red team)"""
        try:
            src_ip_obj = ipaddress.ip_address(src_ip)
            
            # Check operator IPs
            if src_ip in self.config['operator_ips']:
                return True
            
            # Check trusted networks
            for network in self.config['trusted_networks']:
                if src_ip_obj in ipaddress.ip_network(network, strict=False):
                    return True
            
            # Skip localhost
            if src_ip_obj.is_loopback:
                return True
                
        except:
            pass
        
        return False
    
    def deploy_canaries(self):
        """Deploy canary services to detect blue team scanning"""
        canary_configs = [
            (2222, "SSH", self._ssh_canary),
            (8888, "HTTP", self._http_canary),
            (5900, "VNC", self._vnc_canary),
            (9999, "Admin", self._admin_canary),
            (1433, "MSSQL", self._mssql_canary),
            (3389, "RDP", self._rdp_canary),
            (445, "SMB", self._smb_canary),
            (139, "NetBIOS", self._netbios_canary)
        ]
        
        print("\n🍯 Deploying Canary Services to Detect Blue Teams...")
        print("─" * 50)
        
        for port, service_type, handler_func in canary_configs:
            if port in self.config["canary_ports"]:
                try:
                    thread = threading.Thread(
                        target=handler_func,
                        args=(port,),
                        daemon=True,
                        name=f"canary_{service_type}_{port}"
                    )
                    thread.start()
                    self.canary_threads.append(thread)
                    print(f"   ✓ {service_type:<8} canary on port {port}")
                except Exception as e:
                    print(f"   ✗ {service_type:<8} failed on port {port}: {e}")
        
        print("─" * 50)
        print("✅ Canaries deployed - Blue team scans will trigger alerts\n")
    
    def _ssh_canary(self, port):
        """SSH canary service"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    # Send SSH banner
                    client_socket.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
                    logging.info(f"Blue team SSH canary triggered from {address[0]}")
                    client_socket.close()
                except socket.timeout:
                    continue
                except:
                    pass
                    
        except Exception as e:
            logging.error(f"SSH canary error: {e}")
    
    def _http_canary(self, port):
        """HTTP canary service"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    client_socket.settimeout(5)
                    
                    # Receive request
                    request = client_socket.recv(4096)
                    
                    # Send response
                    response = b"HTTP/1.1 401 Unauthorized\r\n"
                    response += b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                    response += b"WWW-Authenticate: Basic realm=\"Admin Portal\"\r\n"
                    response += b"Content-Length: 0\r\n\r\n"
                    
                    client_socket.send(response)
                    logging.info(f"Blue team HTTP canary triggered from {address[0]}")
                    client_socket.close()
                    
                except socket.timeout:
                    continue
                except:
                    pass
                    
        except Exception as e:
            logging.error(f"HTTP canary error: {e}")
    
    def _vnc_canary(self, port):
        """VNC canary service"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    client_socket.send(b"RFB 003.008\n")
                    logging.info(f"Blue team VNC canary triggered from {address[0]}")
                    client_socket.close()
                except:
                    pass
                    
        except Exception as e:
            logging.error(f"VNC canary error: {e}")
    
    def _admin_canary(self, port):
        """Admin portal canary"""
        self._http_canary(port)
    
    def _mssql_canary(self, port):
        """MSSQL canary service"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    client_socket.send(b"\x04\x01\x00\x25\x00\x00\x00\x00")
                    logging.info(f"Blue team MSSQL canary triggered from {address[0]}")
                    client_socket.close()
                except:
                    pass
                    
        except Exception as e:
            logging.error(f"MSSQL canary error: {e}")
    
    def _rdp_canary(self, port):
        """RDP canary service"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    client_socket.send(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x00\x00\x00")
                    logging.info(f"Blue team RDP canary triggered from {address[0]}")
                    client_socket.close()
                except:
                    pass
                    
        except Exception as e:
            logging.error(f"RDP canary error: {e}")
    
    def _smb_canary(self, port):
        """SMB canary service"""
        self._netbios_canary(port)
    
    def _netbios_canary(self, port):
        """NetBIOS canary service"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    logging.info(f"Blue team NetBIOS canary triggered from {address[0]}")
                    client_socket.close()
                except:
                    pass
                    
        except Exception as e:
            logging.error(f"NetBIOS canary error: {e}")
    
    def get_network_interface(self):
        """Select network interface"""
        if self.config["interface"] != "auto":
            return self.config["interface"]

        if not SCAPY_AVAILABLE:
            logging.error("scapy not installed — cannot list interfaces")
            return "eth0"

        interfaces = get_if_list()
        preferred = ['eth0', 'ens33', 'ens192', 'ens160', 'enp0s3', 'wlan0']
        
        for iface in preferred:
            if iface in interfaces:
                return iface
        
        for iface in interfaces:
            if iface != 'lo' and not iface.startswith('docker'):
                return iface
        
        return 'eth0'
    
    def generate_intelligence_report(self):
        """Generate blue team intelligence report"""
        assessment = self.intelligence.get_threat_assessment()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'blue_team_threat_level': assessment['investigation_intensity'],
            'active_blue_team_ips': assessment['active_investigators'],
            'detected_platforms': assessment['primary_platforms'],
            'investigation_techniques': assessment['investigation_focus'],
            'recommendations': assessment['recommendations'],
            'statistics': {
                'total_detections': sum(self.intelligence.investigation_techniques.values()),
                'unique_investigators': len(self.intelligence.blue_team_activities),
                'platforms_detected': len(self.intelligence.detected_platforms)
            }
        }
        
        return report
    
    def cleanup(self, signum=None, frame=None):
        """Cleanup on shutdown"""
        print("\n🛑 Shutting down Blue Team Detector...")
        
        self.running = False
        
        # Save intelligence
        self.intelligence.save_intelligence()
        
        # Generate final report
        if not self.config.get('stealth_mode'):
            report = self.generate_intelligence_report()
            report_file = f"blue_team_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"📊 Final report saved to {report_file}")
        
        # Remove PID file
        try:
            os.remove(PID_FILE)
        except:
            pass
        
        print("✅ Shutdown complete")
        sys.exit(0)
    
    def daemonize(self):
        """Run as daemon"""
        # First fork
        try:
            if os.fork() > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #1 failed: {e}\n")
            sys.exit(1)
        
        # Decouple
        os.chdir("/")
        os.setsid()
        os.umask(0)
        
        # Second fork
        try:
            if os.fork() > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #2 failed: {e}\n")
            sys.exit(1)
        
        # Write PID
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        
        # Redirect file descriptors
        if self.config.get("stealth_mode", True):
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, sys.stdin.fileno())
            os.dup2(devnull, sys.stdout.fileno())
            os.dup2(devnull, sys.stderr.fileno())
    
    def run(self):
        """Main detection loop"""
        if not SCAPY_AVAILABLE:
            print("❌ scapy is required for packet capture. Install with: pip install scapy")
            return

        # Signal handlers
        signal.signal(signal.SIGTERM, self.cleanup)
        signal.signal(signal.SIGINT, self.cleanup)

        # Get interface
        interface = self.get_network_interface()
        
        # Display banner
        self._display_banner(interface)
        
        # Start sniffing
        try:
            print(f"\n🚀 Starting blue team detection on {interface}...")
            print("   Press Ctrl+C to stop\n")
            
            sniff(
                iface=interface,
                prn=self.packet_inspector,
                store=False,
                stop_filter=lambda x: not self.running
            )
            
        except PermissionError:
            print("\n❌ Error: Root privileges required")
            print("   Run with: sudo python3 ioc-u-enhanced.py")
            self.cleanup()
        except Exception as e:
            print(f"\n❌ Fatal error: {e}")
            self.cleanup()
    
    def _display_banner(self, interface):
        """Display startup banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║          IOC-U Enhanced v2.0 - Blue Team Detector                ║
║         Detecting Blue Team IR/SOC Investigation Activities      ║
╠══════════════════════════════════════════════════════════════════╣
║  Detects:                                                        ║
║  • SIEM Queries & Threat Hunting    • EDR/XDR Scanning         ║
║  • Memory & Disk Forensics          • Network Monitoring        ║
║  • PowerShell Investigation         • WMI Queries               ║
║  • AI-Powered Analysis              • IOC Sweeps                ║
╚══════════════════════════════════════════════════════════════════╝
        """
        
        print(banner)
        print(f"\n📡 Configuration:")
        print(f"   • Interface: {interface}")
        print(f"   • Local IP: {self.local_ip}")
        print(f"   • ML Detection: {'Enabled' if self.ml_engine else 'Disabled'}")
        print(f"   • Alert Mode: {'Investigations Only' if self.config.get('alert_on_investigation_only') else 'All Activity'}")
        print(f"   • Canary Ports: {len(self.config.get('canary_ports', []))}")

# Utility functions
def load_config():
    """Load configuration"""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                loaded_config = json.load(f)
                config = default_config.copy()
                config.update(loaded_config)
                return config
        except:
            pass
    return default_config.copy()

def save_config(config):
    """Save configuration"""
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except:
        return False

def show_intelligence_report():
    """Show blue team intelligence report"""
    config = load_config()
    intelligence = BlueTeamIntelligence(config)
    assessment = intelligence.get_threat_assessment()
    
    print("\n" + "="*70)
    print(" "*15 + "BLUE TEAM INTELLIGENCE REPORT")
    print("="*70)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    # Threat level
    threat_colors = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',      # Yellow  
        'MEDIUM': '\033[94m',    # Blue
        'LOW': '\033[92m'        # Green
    }
    
    color = threat_colors.get(assessment['investigation_intensity'], '')
    print(f"\n🚨 BLUE TEAM THREAT LEVEL: {color}{assessment['investigation_intensity']}\033[0m")
    
    # Active investigators
    if assessment['active_investigators']:
        print(f"\n👮 ACTIVE BLUE TEAM INVESTIGATORS:")
        for investigator in assessment['active_investigators']:
            print(f"   • {investigator['ip']}")
            print(f"     Activity: {investigator['activity_count']} actions")
            print(f"     Platforms: {', '.join(investigator['platforms'])}")
    else:
        print(f"\n✅ No active blue team investigators detected")
    
    # Detected platforms
    if assessment['primary_platforms']:
        print(f"\n🛡️ DETECTED SECURITY PLATFORMS:")
        for platform in assessment['primary_platforms']:
            print(f"   • {platform}")
    
    # Investigation techniques
    if assessment['investigation_focus']:
        print(f"\n🔍 BLUE TEAM TECHNIQUES OBSERVED:")
        for technique in assessment['investigation_focus']:
            print(f"   • {technique}")
    
    # Recommendations
    if assessment['recommendations']:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in assessment['recommendations']:
            print(f"   • {rec}")
    
    print("\n" + "="*70)

def setup_operational_config():
    """Configure operational settings"""
    config = load_config()
    
    print("\n🔧 Blue Team Detector Configuration")
    print("=" * 50)
    
    # Trusted networks
    print("\n1️⃣ TRUSTED NETWORKS (Your Red Team Networks)")
    print(f"Current: {config.get('trusted_networks', [])}")
    
    while True:
        network = input("Add trusted network (CIDR) or 'done': ").strip()
        if network.lower() == 'done':
            break
        if network:
            try:
                ipaddress.ip_network(network, strict=False)
                if network not in config["trusted_networks"]:
                    config["trusted_networks"].append(network)
                    print(f"   ✅ Added {network}")
            except:
                print(f"   ❌ Invalid network: {network}")
    
    # Operator IPs
    print("\n2️⃣ OPERATOR IPs (Your Red Team IPs)")
    print(f"Current: {config.get('operator_ips', [])}")
    
    while True:
        ip = input("Add operator IP or 'done': ").strip()
        if ip.lower() == 'done':
            break
        if ip:
            try:
                ipaddress.ip_address(ip)
                if ip not in config["operator_ips"]:
                    config["operator_ips"].append(ip)
                    print(f"   ✅ Added {ip}")
            except:
                print(f"   ❌ Invalid IP: {ip}")
    
    # Alert settings
    print("\n3️⃣ ALERT SETTINGS")
    
    alert_choice = input("Alert on active investigations only? (Y/n): ").strip()
    config["alert_on_investigation_only"] = alert_choice.lower() != 'n'
    
    # ML detection
    if ML_AVAILABLE:
        print("\n4️⃣ ML DETECTION")
        ml_choice = input("Enable ML-based detection? (Y/n): ").strip()
        config["enable_ml_detection"] = ml_choice.lower() != 'n'
    
    # Canary ports
    print("\n5️⃣ CANARY SERVICES")
    print("Recommended: 2222,8888,5900,9999,1433,3389,445,139")
    
    use_default = input("Use recommended canary ports? (Y/n): ").strip()
    if use_default.lower() == 'n':
        custom_ports = input("Enter custom ports (comma-separated): ").strip()
        if custom_ports:
            try:
                config["canary_ports"] = [int(p.strip()) for p in custom_ports.split(',')]
            except:
                print("Invalid port format, using defaults")
    
    save_config(config)
    print("\n✅ Configuration saved!")

def setup_email():
    """Configure email alerts"""
    config = load_config()
    
    print("\n📧 Email Alert Configuration")
    print("=" * 40)
    
    config["alert_email"] = input("Alert email address: ").strip()
    config["gpg_recipient"] = input("GPG recipient: ").strip()
    
    if config["alert_email"] and config["gpg_recipient"]:
        config["email_enabled"] = True
        config["smtp_configured"] = True
        save_config(config)
        print("✅ Email alerts configured")
    else:
        print("❌ Email configuration incomplete")

def show_status():
    """Show detector status"""
    config = load_config()
    
    print("\n📊 Blue Team Detector Status")
    print("=" * 40)
    
    # Check if running
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = f.read().strip()
            os.kill(int(pid), 0)
            print(f"🟢 Status: Running (PID: {pid})")
        except:
            print("🔴 Status: Not running")
            os.remove(PID_FILE)
    else:
        print("🔴 Status: Not running")
    
    # Configuration
    print(f"\n⚙️ Configuration:")
    print(f"   ML Detection: {'Enabled' if config.get('enable_ml_detection') and ML_AVAILABLE else 'Disabled'}")
    print(f"   Email Alerts: {'Enabled' if config.get('email_enabled') else 'Disabled'}")
    print(f"   Alert Mode: {'Investigations Only' if config.get('alert_on_investigation_only') else 'All Activity'}")
    print(f"   Canary Ports: {config.get('canary_ports', [])}")

def stop_detector():
    """Stop running detector"""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(2)
            print("✅ Detector stopped")
        except:
            print("❌ Could not stop detector")
    else:
        print("❌ Detector not running")

def main():
    """Main entry point"""
    global PID_FILE, LOG_FILE
    parser = argparse.ArgumentParser(
        description="IOC-U Enhanced v2.0 - Blue Team Detection Tool",
        epilog="Detects blue team IR/SOC activities targeting red team operations"
    )
    
    # Configuration
    parser.add_argument("--config-operational", action="store_true",
                       help="Configure operational settings")
    parser.add_argument("--config-email", action="store_true",
                       help="Configure email alerts")
    
    # Control
    parser.add_argument("--status", action="store_true",
                       help="Show detector status")
    parser.add_argument("--stop", action="store_true",
                       help="Stop detector")
    parser.add_argument("--foreground", action="store_true",
                       help="Run in foreground")
    
    # Intelligence
    parser.add_argument("--intelligence", action="store_true",
                       help="Show blue team intelligence report")
    
    # Deployment
    parser.add_argument("--deploy-canaries", action="store_true",
                       help="Deploy canary services")
    parser.add_argument("--no-canaries", action="store_true",
                       help="Start without canaries")
    
    # Runtime options
    parser.add_argument("--interface", help="Network interface")
    parser.add_argument("--ml-disable", action="store_true",
                       help="Disable ML detection")

    # Sentry / daemon mode for OPSEC integration
    parser.add_argument("--daemon", action="store_true",
                       help="Run as background sentry daemon (alerts to log)")
    parser.add_argument("--alert-hook", default=None,
                       help="Command to run on detection (receives alert JSON via stdin)")
    parser.add_argument("--sentry-pid", default="/var/run/opsec-ioc-u.pid",
                       help="PID file for sentry mode")
    parser.add_argument("--sentry-log", default="/var/log/opsec-ioc-u.log",
                       help="Log file for sentry mode")

    args = parser.parse_args()

    # Ops hook
    _hook = _OpsHook("ioc-u") if _OpsHook else None
    if _hook:
        _hook.register()

    # Handle commands
    if args.config_operational:
        setup_operational_config()
        return
    
    if args.config_email:
        setup_email()
        return
    
    if args.status:
        show_status()
        return
    
    if args.intelligence:
        show_intelligence_report()
        return
    
    if args.stop:
        stop_detector()
        return
    
    # Check root
    if os.geteuid() != 0:
        print("❌ Root privileges required")
        print("   Run with: sudo python3 ioc-u-enhanced.py")
        return
    
    # Check if already running
    if os.path.exists(PID_FILE) and not args.foreground:
        print("⚠️ Detector already running. Use --stop first.")
        return
    
    # Load config and apply overrides
    config = load_config()
    
    if args.interface:
        config["interface"] = args.interface
    
    if args.ml_disable:
        config["enable_ml_detection"] = False
    
    # Sentry daemon mode — override PID/LOG paths and suppress interactive prompts
    if args.daemon:
        PID_FILE = args.sentry_pid
        LOG_FILE = args.sentry_log
        config["alert_hook"] = args.alert_hook
        # Configure logging to file for daemon mode
        logging.basicConfig(
            filename=args.sentry_log,
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )

    # Start detector
    print("\n🚀 Starting IOC-U Enhanced Blue Team Detector...")

    try:
        detector = EnhancedBlueTeamDetector(config)

        # Deploy canaries
        if not args.no_canaries:
            detector.deploy_canaries()
            if not args.foreground and not args.daemon:
                input("\nPress Enter to start detection...")

        # Run
        if args.daemon:
            print("Starting as sentry daemon...")
            detector.daemonize()
        elif not args.foreground:
            print("Starting in daemon mode...")
            detector.daemonize()

        detector.run()

    except KeyboardInterrupt:
        print("\n⚠️ Interrupted")
        if 'detector' in locals():
            detector.cleanup()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if 'detector' in locals():
            detector.cleanup()

if __name__ == "__main__":
    main()