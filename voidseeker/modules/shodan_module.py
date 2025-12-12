"""
Lightweight Shodan Integration for VoidSeeker

Minimal enrichment: adds organization and country context to local scan results.
Designed for deep web enumeration with minimal API quota usage.

Rate limiting: 1-second minimum interval between API calls with exponential backoff
on rate limit errors.
"""
from typing import Dict, List, Optional, Any, Callable
from shodan import Shodan
from shodan.exception import APIError
from rich.console import Console
import time
from threading import Lock
import logging

console = Console()

# Logger will be initialized lazily to avoid circular imports
_logger: Optional[logging.Logger] = None

def get_logger_instance() -> logging.Logger:
    """
    Get or initialize the logger for this module.
    
    Returns:
        Logger instance for shodan_module
    """
    global _logger
    if _logger is None:
        from config.logging_config import get_logger
        _logger = get_logger(__name__)
    return _logger


class ShodanFingerprint:
    """
    Minimal Shodan enrichment for VoidSeeker scanning.
    
    Enriches discovered services with organization, country, ports, and vulnerability
    data from the Shodan search engine. Includes rate limiting and error recovery.
    """
    
    # Class-level rate limiting (shared across instances)
    _last_api_call: float = 0
    _api_lock: Lock = Lock()
    _min_request_interval: float = 1.0  # 1 second between requests (conservative)
    _max_retries: int = 3
    _retry_base_delay: float = 2  # seconds
    
    def __init__(self, api_key: str):
        """
        Initialize Shodan API client with the provided API key.
        
        Args:
            api_key: Valid Shodan API key
        """
        if not api_key or not isinstance(api_key, str):
            raise ValueError("api_key must be a non-empty string")
        
        try:
            logger = get_logger_instance()
            logger.debug("Initializing Shodan API client")
            self.api = Shodan(api_key)
            logger.debug("Shodan instance created, validating API key")
            # Validate key by calling info() which requires valid authentication
            info_result = self._make_rate_limited_request(self.api.info)
            logger.debug(f"API validation successful, plan info: {info_result}")
            self.shodan_available = True
            logger.info("Shodan API initialized successfully")
        except (APIError, TypeError, ValueError) as e:
            logger = get_logger_instance()
            self.shodan_available = False
            logger.error(f"Shodan API initialization failed: {type(e).__name__}: {e}")
            console.print("[yellow]⚠ Shodan API unavailable - using local fingerprinting only[/yellow]")
    
    def _make_rate_limited_request(self, api_call: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        Execute API call with rate limiting and exponential backoff.
        
        Args:
            api_call: Callable Shodan API method
            *args, **kwargs: Arguments to pass to api_call
        
        Returns:
            Result from API call
        
        Raises:
            APIError: If call fails after all retries
        """
        for attempt in range(self._max_retries):
            with self._api_lock:
                # Wait until minimum interval has passed since last call
                elapsed = time.time() - ShodanFingerprint._last_api_call
                if elapsed < self._min_request_interval:
                    time.sleep(self._min_request_interval - elapsed)
                
                # Record this API call time
                ShodanFingerprint._last_api_call = time.time()
            
            try:
                return api_call(*args, **kwargs)
            
            except APIError as e:
                error_msg = str(e).lower()
                
                # Check for rate limiting errors - these are worth retrying
                if 'rate limit' in error_msg or '429' in error_msg:
                    if attempt < self._max_retries - 1:
                        backoff = self._retry_base_delay * (2 ** attempt)
                        time.sleep(backoff)
                        continue
                    else:
                        raise
                
                # Auth errors and others: fail fast
                raise
        
        raise APIError("Failed to execute API call after retries")
    
    def enrich_local_scan(self, target_ip: str, local_results: List[Dict]) -> List[Dict]:
        """
        Enrich local scan results with Shodan intelligence
        
        Extracts useful metadata: org, country, ISP, ASN, open ports, vulnerabilities, hostnames.
        Gracefully handles missing data (some fields may not be available for all IPs).
        
        Args:
            target_ip: IP address that was scanned
            local_results: Results from local web_scanner
        
        Returns:
            Results with Shodan metadata added
        """
        logger = get_logger_instance()
        if not self.shodan_available or not local_results:
            logger.debug(f"Shodan enrichment skipped for {target_ip} (not available or no results)")
            return local_results
        
        try:
            logger.debug(f"Enriching {len(local_results)} results with Shodan data for {target_ip}")
            # Fetch host data - try full response first, fall back to minified if needed
            host = None
            try:
                logger.debug(f"Requesting full Shodan host data for {target_ip}")
                host = self._make_rate_limited_request(self.api.host, target_ip)
                logger.debug(f"Shodan full API response received for {target_ip}")
            except APIError as e:
                error_msg = str(e)
                # If full request fails, try minified version
                logger.debug(f"Full request failed for {target_ip}, trying minified: {error_msg}")
                try:
                    host = self._make_rate_limited_request(self.api.host, target_ip, minify=True)
                    logger.debug(f"Shodan minified API response received for {target_ip}")
                except APIError as e2:
                    error_msg2 = str(e2)
                    logger.warning(f"Both full and minified Shodan requests failed for {target_ip}: {error_msg2}")
                    # Return results without Shodan enrichment if both fail
                    return local_results
            
            if not host:
                logger.debug(f"No Shodan data returned for {target_ip}")
                return local_results
            
            # Log the response structure for debugging
            logger.debug(f"Shodan response for {target_ip} contains keys: {list(host.keys())}")
            
            # Extract useful metadata from Shodan response
            org = host.get('org', '').strip() if isinstance(host.get('org'), str) else ''
            country = host.get('country_name', '').strip() if isinstance(host.get('country_name'), str) else ''
            isp = host.get('isp', '').strip() if isinstance(host.get('isp'), str) else ''
            asn = host.get('asn', '').strip() if isinstance(host.get('asn'), str) else ''
            
            logger.debug(f"Extracted Shodan metadata for {target_ip}: org={org}, country={country}, isp={isp}, asn={asn}")
            
            # Extract open ports discovered by Shodan
            ports = host.get('ports', [])
            detected_services = []
            if isinstance(ports, list):
                detected_services = [str(p) for p in ports]
            logger.debug(f"Extracted {len(detected_services)} open ports for {target_ip}: {detected_services[:10]}")
            
            # Extract vulnerabilities/CVEs if available
            vulns = host.get('vulns', {})
            vulnerability_count = 0
            if isinstance(vulns, dict):
                vulnerability_count = len(vulns)
            elif isinstance(vulns, list):
                vulnerability_count = len(vulns)
            logger.debug(f"Extracted {vulnerability_count} vulnerabilities for {target_ip}")
            
            # Extract hostnames if available
            hostnames = host.get('hostnames', [])
            hostname_str = ''
            if isinstance(hostnames, list) and hostnames:
                hostname_str = ', '.join(hostnames[:3])  # Limit to first 3
                logger.debug(f"Extracted {len(hostnames)} hostnames for {target_ip}: {hostname_str}")
            
            # Extract tags (if any interesting classifications)
            tags = host.get('tags', [])
            tags_str = ''
            if isinstance(tags, list) and tags:
                tags_str = ', '.join(tags[:3])  # Limit to first 3
            
            # Add all extracted data to results
            for result in local_results:
                if org:
                    result['shodan_org'] = org
                if country:
                    result['shodan_country'] = country
                if isp:
                    result['shodan_isp'] = isp
                if asn:
                    result['shodan_asn'] = asn
                
                # Add Shodan-discovered ports if we found any
                if detected_services:
                    result['shodan_ports'] = ', '.join(detected_services[:10])  # Limit to first 10
                
                # Add vulnerability count if vulnerabilities exist
                if vulnerability_count > 0:
                    result['shodan_vulns'] = vulnerability_count
                
                # Add hostnames if available
                if hostname_str:
                    result['shodan_hostnames'] = hostname_str
                
                # Add tags if available
                if tags_str:
                    result['shodan_tags'] = tags_str
            
            return local_results
        except APIError as e:
            # Log the error and continue without Shodan enrichment
            logger.warning(f"Shodan API error during enrichment: {e}")
            return local_results
        except Exception as e:
            # Catch any other unexpected errors
            logger.error(f"Unexpected error during Shodan enrichment: {e}", exc_info=True)
            return local_results


def enhance_scan_results(api_key: str, target_ip: str, local_results: List[Dict]) -> List[Dict]:
    """
    Convenience function to enhance local scan results with Shodan data
    
    Args:
        api_key: Shodan API key
        target_ip: IP that was scanned
        local_results: Results from local scanning
    
    Returns:
        Enhanced results with Shodan intelligence
    """
    try:
        fingerprinter = ShodanFingerprint(api_key)
        return fingerprinter.enrich_local_scan(target_ip, local_results)
    except Exception as e:
        console.print(f"[yellow]Could not enhance with Shodan: {str(e)}[/yellow]")
        return local_results
