
#!/usr/bin/env python3
"""
Secure configuration management for C2 detection system
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class SecureConfig:
    """Secure configuration management with encryption support"""
    
    def __init__(self, config_path: str = 'config/secure_config.yaml'):
        self.config_path = config_path
        self.config = {}
        self._encryption_key = None
        self._load_config()
        self._validate_config()
        
    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                self._create_default_config()
            
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
                
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.config = self._get_default_config()
    
    def _create_default_config(self):
        """Create default configuration file"""
        default_config = self._get_default_config()
        
        # Create config directory if it doesn't exist
        config_dir = Path(self.config_path).parent
        config_dir.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            'threat_weights': {
                'signature_detections': {'base': 0.45, 'max_weight': 0.6},
                'ml_classifications': {'base': 0.35, 'max_weight': 0.5},
                'beaconing_patterns': {'base': 0.15, 'max_weight': 0.3},
                'behavioral_anomalies': {'base': 0.05, 'max_weight': 0.2}
            },
            'thresholds': {
                'CRITICAL': {'score': 0.8, 'confidence': 0.7},
                'HIGH': {'score': 0.6, 'confidence': 0.6},
                'MEDIUM_HIGH': {'score': 0.4, 'confidence': 0.5},
                'MEDIUM': {'score': 0.25, 'confidence': 0.4},
                'LOW_MEDIUM': {'score': 0.15, 'confidence': 0.3},
                'LOW': {'score': 0.0, 'confidence': 0.0}
            },
            'confidence_thresholds': {
                'VERY_HIGH': 0.8,
                'HIGH': 0.6,
                'MEDIUM': 0.4,
                'LOW': 0.2,
                'VERY_LOW': 0.0
            },
            'security': {
                'max_detection_age_hours': 24,
                'max_correlation_count': 10,
                'max_frequency_threshold': 100
            }
        }
    
    def _validate_config(self):
        """Validate configuration values"""
        required_keys = ['threat_weights', 'thresholds', 'confidence_thresholds']
        
        for key in required_keys:
            if key not in self.config:
                logger.warning(f"Missing configuration key: {key}")
                self.config[key] = self._get_default_config()[key]
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_threat_weights(self) -> Dict[str, Dict[str, float]]:
        """Get threat scoring weights"""
        return self.config.get('threat_weights', {})
    
    def get_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Get threat level thresholds"""
        return self.config.get('thresholds', {})
    
    def get_confidence_thresholds(self) -> Dict[str, float]:
        """Get confidence level thresholds"""
        return self.config.get('confidence_thresholds', {})
