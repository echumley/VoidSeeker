"""
VoidSeeker - Deep Web Infrastructure Scanner

A Python-based scanner for discovering and fingerprinting hidden services,
infrastructure, and administrative interfaces using multi-source intelligence.

Main exports:
- ShodanFingerprint: Multi-source fingerprinting with Shodan enrichment
- enhance_scan_results: Convenience function for Shodan enrichment
"""

from voidseeker.modules.shodan_module import ShodanFingerprint, enhance_scan_results

__version__ = "1.0.0"
__author__ = "VoidSeeker Contributors"
__all__ = [
    "ShodanFingerprint",
    "enhance_scan_results",
]
