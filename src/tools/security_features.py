
#!/usr/bin/env python3
"""
Security features for C2 detection system
"""

import re
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Base security error"""
    def __init__(self, message: str, details: Dict[str, Any] = None):
        super().__init__(message)
        self.details = details or {}

class ValidationError(SecurityError):
    """Validation error"""
    pass

class SecurityFeatures:
    """Security validation and sanitization utilities"""
    
    @staticmethod
    def validate_timestamp(timestamp: datetime, max_age_hours: int = 24) -> None:
        """Validate timestamp is within acceptable range"""
        if not isinstance(timestamp, datetime):
            raise ValidationError("Invalid timestamp type")
        
        now = datetime.now()
        max_age = timedelta(hours=max_age_hours)
        
        if now - timestamp > max_age:
            raise ValidationError(f"Timestamp too old: {timestamp}")
        
        if timestamp > now + timedelta(minutes=5):  # Allow small clock skew
            raise ValidationError(f"Timestamp in future: {timestamp}")
    
    @staticmethod
    def validate_frequency(frequency: int, max_threshold: int = 100) -> None:
        """Validate detection frequency"""
        if not isinstance(frequency, int) or frequency < 0:
            raise ValidationError("Frequency must be non-negative integer")
        
        if frequency > max_threshold:
            raise ValidationError(f"Frequency {frequency} exceeds threshold {max_threshold}")
    
    @staticmethod
    def validate_correlation_count(count: int, max_count: int = 10) -> None:
        """Validate correlation count"""
        if not isinstance(count, int) or count < 0:
            raise ValidationError("Correlation count must be non-negative integer")
        
        if count > max_count:
            raise ValidationError(f"Correlation count {count} exceeds maximum {max_count}")
    
    @staticmethod
    def sanitize_string(data: str, max_length: int = 1024) -> str:
        """Sanitize string input"""
        if not isinstance(data, str):
            return str(data)
        
        # Truncate if too long
        if len(data) > max_length:
            data = data[:max_length]
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'\&\x00-\x1f\x7f-\x9f]', '', data)
        
        return sanitized.strip()
    
    @staticmethod
    def sanitize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize metadata dictionary"""
        if not isinstance(metadata, dict):
            return {}
        
        sanitized = {}
        for key, value in metadata.items():
            # Sanitize key
            clean_key = SecurityFeatures.sanitize_string(str(key), 64)
            if not clean_key:
                continue
            
            # Sanitize value based on type
            if isinstance(value, str):
                sanitized[clean_key] = SecurityFeatures.sanitize_string(value)
            elif isinstance(value, (int, float, bool)):
                sanitized[clean_key] = value
            elif isinstance(value, list):
                sanitized[clean_key] = [SecurityFeatures.sanitize_string(str(v)) for v in value[:10]]
            else:
                sanitized[clean_key] = SecurityFeatures.sanitize_string(str(value))
        
        return sanitized

class SecurityLogger:
    """Enhanced security logging"""
    
    def __init__(self, logger_instance: logging.Logger):
        self.logger = logger_instance
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log security events"""
        log_entry = {
            "event_type": event_type,
            "timestamp": datetime.now().isoformat(),
            "details": SecurityFeatures.sanitize_metadata(details),
            "severity": details.get("severity", "INFO")
        }
        
        self.logger.info(f"SECURITY_EVENT: {json.dumps(log_entry)}")
    
    def log_security_error(self, error_type: str, details: Dict[str, Any]) -> None:
        """Log security errors"""
        log_entry = {
            "error_type": error_type,
            "timestamp": datetime.now().isoformat(),
            "details": SecurityFeatures.sanitize_metadata(details),
            "severity": "ERROR"
        }
        
        self.logger.error(f"SECURITY_ERROR: {json.dumps(log_entry)}")
    
    def log_validation_error(self, validation_type: str, error_message: str, context: Dict[str, Any] = None) -> None:
        """Log validation errors"""
        details = {
            "validation_type": validation_type,
            "error_message": error_message,
            "context": SecurityFeatures.sanitize_metadata(context or {})
        }
        
        self.log_security_error("VALIDATION_ERROR", details)
