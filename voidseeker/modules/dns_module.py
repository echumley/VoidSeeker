"""
VoidSeeker DNS Reconnaissance Module

Uses dnspython to gather DNS information about targets including:
- Reverse DNS (PTR records)
- Forward DNS (A/AAAA records)
- MX records (mail servers)
- NS records (nameservers)
- SOA records (authority information)
- TXT records (SPF, DMARC, verification)
- CNAME records

Provides comprehensive DNS intelligence for target profiling and alternative
access point discovery.
"""

import dns.resolver
import dns.reversename
import dns.exception
from typing import Dict, List, Optional, Tuple, Any
from rich.console import Console
import logging

console = Console()

# Logger will be initialized lazily to avoid circular imports
_logger: Optional[logging.Logger] = None

def get_logger_instance() -> logging.Logger:
    """
    Get or initialize the logger for this module.
    
    Returns:
        Logger instance for dns_module
    """
    global _logger
    if _logger is None:
        from config.logging_config import get_logger
        _logger = get_logger(__name__)
    return _logger


class DNSRecon:
    """
    DNS reconnaissance for target enumeration.
    
    Gathers comprehensive DNS information for targets including reverse DNS lookups,
    forward DNS queries, mail server information, and zone transfers (if permitted).
    """
    
    def __init__(self, timeout: int = 5):
        """
        Initialize DNS resolver.
        
        Args:
            timeout: DNS query timeout in seconds (default: 5)
        Args:
            timeout: DNS query timeout in seconds
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.results = {}
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            parts = target.split('.')
            if len(parts) == 4:
                return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            pass
        return False
    
    def get_reverse_dns(self, ip: str) -> Optional[str]:
        """
        Get reverse DNS (PTR record) for an IP
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None if no PTR record
        """
        try:
            addr = dns.reversename.from_address(ip)
            ptr_records = self.resolver.resolve(addr, "PTR")
            if ptr_records:
                return str(ptr_records[0]).rstrip('.')
        except (dns.exception.DNSException, Exception):
            pass
        return None
    
    def get_a_records(self, hostname: str) -> List[str]:
        """
        Get A records (IPv4) for a hostname
        
        Args:
            hostname: Domain or hostname
            
        Returns:
            List of IPv4 addresses
        """
        ips = []
        try:
            a_records = self.resolver.resolve(hostname, "A")
            ips.extend([str(rdata) for rdata in a_records])
        except (dns.exception.DNSException, Exception):
            pass
        return ips
    
    def get_aaaa_records(self, hostname: str) -> List[str]:
        """
        Get AAAA records (IPv6) for a hostname
        
        Args:
            hostname: Domain or hostname
            
        Returns:
            List of IPv6 addresses
        """
        ips = []
        try:
            aaaa_records = self.resolver.resolve(hostname, "AAAA")
            ips.extend([str(rdata) for rdata in aaaa_records])
        except (dns.exception.DNSException, Exception):
            pass
        return ips
    
    def get_cname_records(self, hostname: str) -> List[str]:
        """
        Get CNAME records for a hostname
        
        Args:
            hostname: Domain or hostname
            
        Returns:
            List of CNAME targets
        """
        cnames = []
        try:
            cname_records = self.resolver.resolve(hostname, "CNAME")
            cnames.extend([str(rdata.target).rstrip('.') for rdata in cname_records])
        except (dns.exception.DNSException, Exception):
            pass
        return cnames
    
    def get_mx_records(self, hostname: str) -> List[Tuple[int, str]]:
        """
        Get MX records (mail servers) for a hostname
        
        Args:
            hostname: Domain or hostname
            
        Returns:
            List of (priority, mail_server) tuples
        """
        mx_records = []
        try:
            mxs = self.resolver.resolve(hostname, "MX")
            for mx in mxs:
                priority = mx.preference
                exchange = str(mx.exchange).rstrip('.')
                mx_records.append((priority, exchange))
            mx_records.sort(key=lambda x: x[0])
        except (dns.exception.DNSException, Exception):
            pass
        return mx_records
    
    def get_ns_records(self, hostname: str) -> List[str]:
        """
        Get NS records (nameservers) for a hostname
        
        Args:
            hostname: Domain or hostname
            
        Returns:
            List of nameservers
        """
        nameservers = []
        try:
            ns_records = self.resolver.resolve(hostname, "NS")
            nameservers.extend([str(rdata.target).rstrip('.') for rdata in ns_records])
        except (dns.exception.DNSException, Exception):
            pass
        return nameservers
    
    def get_soa_record(self, hostname: str) -> Optional[Dict]:
        """
        Get SOA record (authority information) for a hostname
        
        Args:
            hostname: Domain or hostname
            
        Returns:
            Dictionary with SOA information or None
        """
        try:
            answer = self.resolver.resolve(hostname, "SOA")
            for rr in answer:
                return {
                    'mname': str(rr.mname).rstrip('.'),
                    'rname': str(rr.rname).rstrip('.'),
                    'serial': rr.serial,
                    'refresh': rr.refresh,
                    'retry': rr.retry,
                    'expire': rr.expire,
                    'minimum': rr.minimum
                }
        except (dns.exception.DNSException, Exception):
            pass
        return None
    
    def get_txt_records(self, hostname: str) -> List[str]:
        """
        Get TXT records for a hostname (SPF, DMARC, verification, etc.)
        
        Args:
            hostname: Domain or hostname
            
        Returns:
            List of TXT record values
        """
        txt_records = []
        try:
            txts = self.resolver.resolve(hostname, "TXT")
            for txt in txts:
                txt_str = b''.join(txt.strings).decode('utf-8', errors='ignore')
                txt_records.append(txt_str)
        except (dns.exception.DNSException, Exception):
            pass
        return txt_records
    
    def recon_target(self, target: str) -> Dict:
        """
        Perform comprehensive DNS reconnaissance on a target
        
        Args:
            target: IP address or hostname
            
        Returns:
            Dictionary with DNS reconnaissance results
        """
        logger = get_logger_instance()
        logger.info(f"Starting DNS reconnaissance on target: {target}")
        recon_data = {
            'target': target,
            'is_ip': self._is_ip(target),
            'reverse_dns': None,
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'ns_records': [],
            'soa_record': None,
            'txt_records': [],
            'interesting_findings': []
        }
        
        if recon_data['is_ip']:
            # It's an IP - do reverse DNS and maybe forward
            logger.debug(f"Target {target} is an IP, performing reverse DNS lookup")
            recon_data['reverse_dns'] = self.get_reverse_dns(target)
            logger.debug(f"Reverse DNS for {target}: {recon_data['reverse_dns']}")
            
            # If we got a hostname from reverse DNS, query it for more info
            if recon_data['reverse_dns']:
                hostname = recon_data['reverse_dns']
                logger.debug(f"Querying domain info for hostname {hostname}")
                # Extract domain from hostname for zone queries
                parts = hostname.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])
                    recon_data['mx_records'] = self.get_mx_records(domain)
                    recon_data['ns_records'] = self.get_ns_records(domain)
                    recon_data['txt_records'] = self.get_txt_records(domain)
                    recon_data['soa_record'] = self.get_soa_record(domain)
                    logger.debug(f"Zone query results for {domain}: MX={len(recon_data['mx_records'])}, NS={len(recon_data['ns_records'])}, TXT={len(recon_data['txt_records'])}")
        else:
            # It's a hostname - do forward lookups
            logger.debug(f"Target {target} is a hostname, performing forward DNS lookups")
            recon_data['a_records'] = self.get_a_records(target)
            recon_data['aaaa_records'] = self.get_aaaa_records(target)
            recon_data['cname_records'] = self.get_cname_records(target)
            recon_data['mx_records'] = self.get_mx_records(target)
            recon_data['ns_records'] = self.get_ns_records(target)
            recon_data['soa_record'] = self.get_soa_record(target)
            recon_data['txt_records'] = self.get_txt_records(target)
            logger.debug(f"Forward lookups for {target}: A={len(recon_data['a_records'])}, AAAA={len(recon_data['aaaa_records'])}, CNAME={len(recon_data['cname_records'])}, MX={len(recon_data['mx_records'])}, NS={len(recon_data['ns_records'])}")
        
        # Extract interesting findings
        recon_data['interesting_findings'] = self._extract_findings(recon_data)
        logger.info(f"DNS reconnaissance complete for {target}: {len(recon_data['interesting_findings'])} findings")
        
        return recon_data
    
    def _extract_findings(self, recon_data: Dict) -> List[str]:
        """
        Extract interesting/useful findings from DNS data
        
        Args:
            recon_data: DNS reconnaissance results
            
        Returns:
            List of interesting findings
        """
        findings = []
        
        # Reverse DNS findings
        if recon_data['reverse_dns']:
            findings.append(f"PTR: {recon_data['reverse_dns']}")
        
        # Forward DNS findings
        if recon_data['a_records']:
            findings.append(f"A: {', '.join(recon_data['a_records'][:3])}")
        
        if recon_data['aaaa_records']:
            findings.append(f"AAAA: {', '.join(recon_data['aaaa_records'][:3])}")
        
        if recon_data['cname_records']:
            findings.append(f"CNAME: {recon_data['cname_records'][0]}")
        
        # Mail server findings
        if recon_data['mx_records']:
            mx_list = ', '.join([f"{mx[1]}" for mx in recon_data['mx_records'][:3]])
            findings.append(f"MX: {mx_list}")
        
        # Nameserver findings
        if recon_data['ns_records']:
            findings.append(f"NS: {', '.join(recon_data['ns_records'][:2])}")
        
        # TXT record findings (SPF, DMARC, etc.)
        if recon_data['txt_records']:
            for txt in recon_data['txt_records']:
                if 'v=spf1' in txt:
                    findings.append("SPF: Configured")
                elif 'v=DMARC1' in txt:
                    findings.append("DMARC: Configured")
                elif 'google-site-verification' in txt or 'verification' in txt.lower():
                    findings.append("Domain verification: Present")
        
        return findings
    
    def enrich_scan_results(self, target: str, scan_results: List[Dict]) -> List[Dict]:
        """
        Enrich scan results with DNS intelligence
        
        Args:
            target: Original target (IP or hostname)
            scan_results: List of scan result dictionaries
            
        Returns:
            Enriched scan results with DNS data
        """
        recon = self.recon_target(target)
        
        # Add DNS info to each result
        for result in scan_results:
            result['dns_info'] = {
                'reverse_dns': recon['reverse_dns'],
                'a_records': recon['a_records'],
                'mx_records': recon['mx_records'],
                'ns_records': recon['ns_records'],
                'findings': recon['interesting_findings']
            }
        
        return scan_results
