# utils/exceptions.py
class AWSMonitorError(Exception):
    """Base exception for AWS Resource Exposure Monitor"""
    pass

class ConfigurationError(AWSMonitorError):
    """Configuration related errors"""
    pass

class ScannerError(AWSMonitorError):
    """Scanner related errors"""
    pass

class RateLimitError(AWSMonitorError):
    """AWS API rate limit related errors"""
    pass

class NotificationError(AWSMonitorError):
    """Notification delivery related errors"""
    pass
