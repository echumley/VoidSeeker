"""
VoidSeeker Port Scanning Module

Integrates Nmap-based port scanning with configurable intensity levels.
Designed for integration with the VoidSeeker menu system.

Supports multiple scan profiles:
- QUICK: Top 20 ports, fastest (no service detection)
- STANDARD: Top 100 ports with service detection
- INTENSIVE: Full range with OS detection
- THOROUGH: Comprehensive scan with all NSE scripts
"""
from typing import Dict, List, Optional, Any
import nmap
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import logging

console = Console()

# Logger will be initialized lazily to avoid circular imports
_logger: Optional[logging.Logger] = None

def get_logger_instance() -> logging.Logger:
    """
    Get or initialize the logger for this module.
    
    Returns:
        Logger instance for port_scan_module
    """
    global _logger
    if _logger is None:
        from config.logging_config import get_logger
        _logger = get_logger(__name__)
    return _logger


class PortScanIntensity:
    """
    Predefined scan intensity levels with different speed/accuracy tradeoffs.
    
    Supports balancing between scan speed and detection depth.
    """
    
    QUICK: Dict[str, str] = {
        'name': 'Quick Scan',
        'flags': '-sT',
        'ports': '--top-ports 20',
        'description': 'Scan top 20 ports, very fast (no service detection)'
    }
    
    STANDARD: Dict[str, str] = {
        'name': 'Standard Scan',
        'flags': '-sV',
        'ports': '--top-ports 100',
        'description': 'Top 100 ports with service detection'
    }
    
    INTENSIVE: Dict[str, str] = {
        'name': 'Intensive Scan',
        'flags': '-sV -O',
        'ports': '1-10000',
        'description': 'Scan 1-10000 ports with OS detection'
    }
    THOROUGH = {
        'name': 'Thorough Scan',
        'flags': '-sV -O --script vuln',
        'ports': '1-65535',
        'description': 'Full port range with vulnerability scripts (slow)'
    }
    
    @classmethod
    def list_intensities(cls) -> List[tuple]:
        """Return list of available intensities as (name, flags, ports, description)"""
        return [
            (cls.QUICK['name'], cls.QUICK['flags'], cls.QUICK['ports'], cls.QUICK['description']),
            (cls.STANDARD['name'], cls.STANDARD['flags'], cls.STANDARD['ports'], cls.STANDARD['description']),
            (cls.INTENSIVE['name'], cls.INTENSIVE['flags'], cls.INTENSIVE['ports'], cls.INTENSIVE['description']),
            (cls.THOROUGH['name'], cls.THOROUGH['flags'], cls.THOROUGH['ports'], cls.THOROUGH['description']),
        ]
    
    @classmethod
    def get_flags_and_ports(cls, intensity_name: str) -> tuple:
        """Get Nmap flags and port range for a given intensity name. Returns (flags, ports)"""
        for intensity in cls.list_intensities():
            if intensity[0].lower() == intensity_name.lower():
                return intensity[1], intensity[2]
        return cls.STANDARD['flags'], cls.STANDARD['ports']


class PortScanPlugin:
    """Port scanning plugin for VoidSeeker"""
    
    def __init__(self):
        self.nmap_available = self._check_nmap()
    
    def _check_nmap(self) -> bool:
        """Check if nmap is available on the system"""
        try:
            nm = nmap.PortScanner()
            return True
        except (OSError, nmap.PortScannerError):
            return False
    
    def clean_url(self, url: str) -> str:
        """
        Remove protocol and trailing slashes from URL
        
        Args:
            url: URL string to clean
        
        Returns:
            Cleaned hostname/IP
        """
        cleaned = url.strip()
        
        # Remove protocols
        if cleaned.startswith('https://'):
            cleaned = cleaned[8:]
        elif cleaned.startswith('http://'):
            cleaned = cleaned[7:]
        
        # Remove trailing slashes
        cleaned = cleaned.rstrip('/')
        
        # Remove port if present (use just the hostname)
        if ':' in cleaned and not cleaned.startswith('['):  # Not IPv6
            cleaned = cleaned.split(':')[0]
        
        return cleaned
    
    def scan_host(self, host: str, intensity: str = 'Standard Scan', timeout: int = 600) -> Dict:
        """
        Scan a host for open ports and services
        
        Args:
            host: IP address or hostname to scan
            intensity: Scan intensity name (Quick/Standard/Intensive/Thorough)
            timeout: Scan timeout in seconds (default 600 = 10 minutes)
        
        Returns:
            Dictionary with scan results and metadata
        """
        logger = get_logger_instance()
        logger.info(f"Starting port scan on {host} with {intensity} intensity")
        
        if not self.nmap_available:
            logger.error("Nmap is not available")
            return {
                'success': False,
                'error': 'Nmap is not installed. Install with: brew install nmap'
            }
        
        # Clean the target
        target = self.clean_url(host)
        logger.debug(f"Cleaned target: {target}")
        
        # Get Nmap flags and port range for the selected intensity
        flags, port_range = PortScanIntensity.get_flags_and_ports(intensity)
        logger.debug(f"Using Nmap flags: {flags}, port_range: {port_range}")
        
        nm = nmap.PortScanner()
        
        try:
            # Build scan command with ports from intensity
            # (Progress bar in main menu will show status)
            
            # Combine all arguments (flags + port specification)
            all_args = f"{flags} {port_range}"
            logger.debug(f"Executing Nmap scan with arguments: {all_args}")
            nm.scan(target, arguments=all_args, timeout=timeout)
            logger.debug(f"Nmap scan completed, parsing results")
            
            return self._parse_results(nm, target)
        
        except nmap.PortScannerError as e:
            error_msg = str(e)
            logger.error(f"Nmap scan error for {target}: {error_msg}")
            console.print(f"[yellow]Nmap error: {error_msg}[/yellow]")
            
            # Handle root privilege errors
            if 'requires root privileges' in error_msg:
                logger.warning(f"Root privileges required for {target}, retrying without OS detection")
                console.print("[yellow]⚠ Warning: OS detection (-O) requires root privileges[/yellow]")
                console.print("[yellow]Retrying without OS detection...[/yellow]\n")
                
                # Retry without OS detection
                flags_no_root = flags.replace('-O', '').strip()
                try:
                    all_args = f"{flags_no_root} {port_range}"
                    logger.debug(f"Retrying scan with modified arguments: {all_args}")
                    nm.scan(target, arguments=all_args, timeout=timeout)
                    logger.debug(f"Retry scan completed, parsing results")
                    return self._parse_results(nm, target)
                except Exception as retry_error:
                    logger.error(f"Retry failed for {target}: {str(retry_error)}", exc_info=True)
                    console.print(f"[red]Retry failed: {str(retry_error)}[/red]")
                    return {
                        'success': False,
                        'error': f'Scan failed: {str(retry_error)}'
                    }
            else:
                logger.error(f"Nmap scan failed for {target}: {error_msg}")
                return {
                    'success': False,
                    'error': f'Scan failed: {error_msg}'
                }
        
        except Exception as e:
            logger.error(f"Unexpected error during scan of {target}: {str(e)}", exc_info=True)
            console.print(f"[red]Unexpected error during scan: {str(e)}[/red]")
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
    
    def _parse_results(self, nm: nmap.PortScanner, target: str) -> Dict:
        """Parse nmap results into a structured format"""
        logger = get_logger_instance()
        results = {
            'success': True,
            'command': nm.command_line(),
            'target': target,
            'scan_info': nm.scaninfo(),
            'hosts': []
        }
        
        for scanned_host in nm.all_hosts():
            host_info = {
                'host': scanned_host,
                'hostname': nm[scanned_host].hostname() or 'N/A',
                'state': nm[scanned_host].state(),
                'protocols': {}
            }
            
            # Get protocols (tcp, udp, etc.)
            for proto in nm[scanned_host].all_protocols():
                host_info['protocols'][proto] = {}
                ports = sorted(list(nm[scanned_host][proto].keys()))
                logger.debug(f"Scanned {len(ports)} {proto.upper()} ports on {scanned_host}")
                
                for port in ports:
                    port_data = nm[scanned_host][proto][port]
                    state = port_data.get('state', 'unknown')
                    name = port_data.get('name', 'unknown')
                    
                    if state == 'open':
                        logger.debug(f"Open port {port}/{proto} on {scanned_host}: {name}")
                    
                    host_info['protocols'][proto][port] = {
                        'state': state,
                        'name': name,
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', ''),
                        'extrainfo': port_data.get('extrainfo', ''),
                        'scripts': port_data.get('script', {})
                    }
            
            results['hosts'].append(host_info)
        
        logger.info(f"Port scan of {target} complete: {len(results['hosts'])} host(s) scanned")
        return results
    
    def display_results(self, results: Dict, show_scripts: bool = False):
        """
        Display scan results in a formatted table
        
        Args:
            results: Results dictionary from scan_host()
            show_scripts: Whether to show NSE script output
        """
        if not results.get('success'):
            console.print(f"[red]✗ {results.get('error', 'Unknown error')}[/red]")
            return
        
        console.print(f"\n[bold cyan]Scan Results for {results['target']}[/bold cyan]")
        console.print(f"[dim]Command: {results['command']}[/dim]\n")
        
        if not results['hosts']:
            console.print("[yellow]No hosts found in scan results[/yellow]")
            return
        
        for host_info in results['hosts']:
            console.print(f"\n[cyan]Host: {host_info['host']}[/cyan]")
            if host_info['hostname'] != 'N/A':
                console.print(f"[cyan]Hostname: {host_info['hostname']}[/cyan]")
            console.print(f"[cyan]State: {host_info['state']}[/cyan]\n")
            
            # Display ports by protocol
            for proto, ports in host_info['protocols'].items():
                if not ports:
                    continue
                
                table = Table(title=f"{proto.upper()} Ports", show_header=True)
                table.add_column("Port", style="cyan", width=8)
                table.add_column("State", style="yellow", width=12)
                table.add_column("Service", style="magenta", width=20)
                table.add_column("Version", style="green", no_wrap=False)
                
                for port, port_info in ports.items():
                    service_name = port_info.get('name', 'unknown')
                    # Map domain service name to DNS
                    if port == 53 and service_name.lower() == 'domain':
                        service_name = 'dns'
                    state = port_info.get('state', 'unknown')
                    
                    # Build version string
                    version_parts = []
                    if port_info.get('product'):
                        version_parts.append(port_info['product'])
                    if port_info.get('version'):
                        version_parts.append(port_info['version'])
                    if port_info.get('extrainfo'):
                        version_parts.append(f"({port_info['extrainfo']})")
                    
                    version_str = " ".join(version_parts) if version_parts else ""
                    
                    table.add_row(
                        str(port),
                        state,
                        service_name,
                        version_str
                    )
                
                console.print(table)
                
                # Show NSE script output if requested
                if show_scripts:
                    has_scripts = any(p.get('scripts') for p in ports.values())
                    if has_scripts:
                        console.print(f"\n[cyan]NSE Script Results ({proto})[/cyan]")
                        for port, port_info in ports.items():
                            scripts = port_info.get('scripts', {})
                            if scripts:
                                console.print(f"\n  [yellow]Port {port}:[/yellow]")
                                for script_name, script_output in scripts.items():
                                    console.print(f"    [cyan]{script_name}[/cyan]:")
                                    # Indent output
                                    for line in script_output.split('\n'):
                                        if line.strip():
                                            console.print(f"      {line}")
    
    def export_results(self, results: Dict, output_file: str, format: str = 'txt'):
        """
        Export scan results to file
        
        Args:
            results: Results dictionary from scan_host()
            output_file: Output file path
            format: 'txt' or 'xml' (nmap native format)
        """
        if not results.get('success'):
            console.print(f"[red]Cannot export failed scan[/red]")
            return
        
        try:
            if format == 'txt':
                with open(output_file, 'w') as f:
                    f.write(f"Port Scan Results: {results['target']}\n")
                    f.write(f"Command: {results['command']}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for host_info in results['hosts']:
                        f.write(f"Host: {host_info['host']}\n")
                        if host_info['hostname'] != 'N/A':
                            f.write(f"Hostname: {host_info['hostname']}\n")
                        f.write(f"State: {host_info['state']}\n\n")
                        
                        for proto, ports in host_info['protocols'].items():
                            if ports:
                                f.write(f"Protocol: {proto.upper()}\n")
                                f.write("-" * 80 + "\n")
                                for port, port_info in sorted(ports.items()):
                                    f.write(f"  Port {port}: {port_info.get('state')} ")
                                    f.write(f"({port_info.get('name')})\n")
                                    if port_info.get('product'):
                                        f.write(f"    Product: {port_info['product']}")
                                        if port_info.get('version'):
                                            f.write(f" {port_info['version']}")
                                        f.write("\n")
                                f.write("\n")
                        
                        f.write("=" * 80 + "\n\n")
            
            console.print(f"[green]✓ Results exported to {output_file}[/green]")
        
        except Exception as e:
            console.print(f"[red]Error exporting results: {e}[/red]")
