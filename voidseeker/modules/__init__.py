"""
VoidSeeker Discovery and Intelligence Modules

Main modules:
- shodan_fingerprint: Shodan-based multi-source fingerprinting with rate limiting
- portscan: Port scanning functionality

Custom Module Development:
Users can add custom discovery modules here. Each module should implement:
- A function or class that performs discovery/enumeration
- Compatible input/output with the core VoidSeeker engine

Example module structure:
```python
def discover(target, **options):
    '''Discover resources on target'''
    results = []
    # Your discovery logic here
    return results
```
"""

from voidseeker.modules.shodan_module import ShodanFingerprint, enhance_scan_results

__all__ = [
    "ShodanFingerprint",
    "enhance_scan_results",
]
