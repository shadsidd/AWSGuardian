# aws_security_scanner/core/exceptions.py
class SecurityScannerError(Exception):
    """Base exception for security scanner"""
    pass

class ConfigurationError(SecurityScannerError):
    """Configuration related errors"""
    pass

class ScannerError(SecurityScannerError):
    """Scanner related errors"""
    pass

class ReportingError(SecurityScannerError):
    """Reporting related errors"""
    pass

class AlertError(SecurityScannerError):
    """Alert related errors"""
    pass
