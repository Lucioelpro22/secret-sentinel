"""Offline, read-only secret detection primitives."""

from .models import Finding, ScanConfig, ScanReport
from .scanner import Scanner

__all__ = ["Finding", "ScanConfig", "ScanReport", "Scanner"]
__version__ = "0.3.0"
