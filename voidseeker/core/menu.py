#!/usr/bin/env python3
"""
VoidSeeker Interactive Menu System

A Metasploit-like CLI interface for deep web service enumeration and fingerprinting.
Provides configuration management and orchestration of discovery and analysis modules.
"""
import os
import sys
import csv
import logging
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from prettytable import PrettyTable
import urllib3

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from config.logging_config import get_logger

logger = get_logger(__name__)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from voidseeker.core.void_core import (
    read_targets, load_wordlist, load_fingerprints, create_session,
    scan_url
)
from voidseeker.modules.shodan_module import ShodanFingerprint
from voidseeker.modules.port_scan_module import PortScanPlugin, PortScanIntensity
from voidseeker.modules.dns_module import DNSRecon

console = Console()

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VoidSeekerMenu:
    """
    Interactive menu system for VoidSeeker reconnaissance.
    
    Manages user configuration, orchestrates scanning modules, and handles result output.
    """
    
    def __init__(self):
        """Initialize VoidSeekerMenu with default configuration."""
        logger.debug("Initializing VoidSeekerMenu")
        
        # Default configuration options
        self.options: Dict[str, Any] = {
            'targets': 'targets.txt',
            'wordlist': 'config/wordlists/common-subdirectories.txt',
            'fingerprints': 'config/fingerprints.json',
            'html_keywords': 'config/wordlists/html-keywords.txt',
            'output': None,
            'output_format': 'cli',  # cli, csv, txt, json
            'timeout': 8,
            'single_target': None,
            'use_shodan': False,
            'shodan_api_key': None,
            'port_scan_intensity': None,  # None = disabled, otherwise intensity name
        }
        
        # Module instances
        self.session: Optional[Any] = None
        self.common_paths: Optional[List[str]] = None
        self.fingerprints_db: Optional[Dict[str, Any]] = None
        self.shodan_client: Optional[ShodanFingerprint] = None
        self.port_scanner: PortScanPlugin = PortScanPlugin()
        self.dns_recon: DNSRecon = DNSRecon(timeout=5)
        
        logger.info("VoidSeekerMenu initialized successfully")
    
    def banner(self) -> None:
        """Display the VoidSeeker banner."""
        banner_text = """
╔═══════════════════════════════════════════════════════════╗
║          VoidSeeker - Service Enumeration Tool            ║
║     Deep Web Reconnaissance & Fingerprinting Engine       ║
╚═══════════════════════════════════════════════════════════╝
        """
        console.print(banner_text, style="bold cyan")
    
    def show_options(self) -> None:
        """Display current configuration in a formatted table."""
        table = Table(title="Current Configuration", show_header=True)
        table.add_column("Option", style="cyan")
        table.add_column("Value", style="green")
        
        # Safely get target count, handling missing file
        targets_display = "Single target" if self.options['single_target'] else (
            f"{len(read_targets(self.options['targets']))} targets" 
            if self.options['targets'] and Path(self.options['targets']).exists() else "Not set"
        )
        
        table.add_row("Targets", targets_display)
        table.add_row("Wordlist", os.path.basename(self.options['wordlist']))
        table.add_row("Fingerprints DB", os.path.basename(self.options['fingerprints']))
        table.add_row("HTML Keywords", os.path.basename(self.options['html_keywords']))
        table.add_row("Output Format", self.options['output_format'].upper())
        table.add_row("Output File", self.options['output'] or "Console (stdout)")
        table.add_row("Timeout", f"{self.options['timeout']}s")
        
        shodan_status = "[green]Enabled[/green]" if self.options['use_shodan'] else "[red]Disabled[/red]"
        table.add_row("Shodan Intelligence", shodan_status)
        
        console.print(table)
    
    def set_targets(self):
        """Set target(s)"""
        while True:
            console.print("\n[bold cyan]Target Configuration[/bold cyan]")
            console.print("[dim]Specify which target(s) to scan for service enumeration[/dim]\n")
            console.print("  [cyan]1.[/cyan] Single Target  [dim]→ Scan one domain or IP address[/dim]")
            console.print("  [cyan]2.[/cyan] Target File    [dim]→ Load targets from text file (one per line)[/dim]")
            console.print("  [cyan]3.[/cyan] Back           [dim]→ Return to main menu[/dim]\n")
            
            target_type = Prompt.ask("Select option", console=console)
            
            if target_type == "1":
                # Single target
                target = Prompt.ask("Enter target (domain/IP)", console=console)
                if not target.startswith("http"):
                    target = "https://" + target
                self.options['single_target'] = target
                self.options['targets'] = None
                console.print(f"\n[green]✓ Target set to {target}[/green]\n")
                break
            elif target_type == "2":
                # Target file
                filepath = Prompt.ask("Enter path to targets file", default="targets.txt", console=console)
                if os.path.exists(filepath):
                    try:
                        targets = read_targets(filepath)
                        self.options['targets'] = filepath
                        self.options['single_target'] = None
                        console.print(f"\n[green]✓ Loaded {len(targets)} targets[/green]\n")
                        break
                    except Exception as e:
                        console.print(f"[red]Error loading targets: {e}[/red]\n")
                else:
                    console.print(f"[red]File not found: {filepath}[/red]\n")
            elif target_type == "3":
                break
            else:
                console.print("[red]Invalid option[/red]")
    
    def set_wordlist(self):
        """Set wordlist"""
        while True:
            console.print("\n[bold cyan]Wordlist Configuration[/bold cyan]")
            console.print("[dim]Select paths to test for accessible services and endpoints[/dim]\n")
            
            # Show available wordlists
            wordlist_dir = Path("config/wordlists")
            if wordlist_dir.exists():
                wordlists = list(wordlist_dir.glob("*.txt"))
                if wordlists:
                    console.print("[cyan]Available wordlists:[/cyan]")
                    for i, wl in enumerate(wordlists, 1):
                        console.print(f"  [cyan]{i}.[/cyan] {wl.name}")
                    
                    console.print(f"  [cyan]{len(wordlists)+1}.[/cyan] Custom path")
                    console.print(f"  [cyan]{len(wordlists)+2}.[/cyan] Back\n")
                    
                    choice = Prompt.ask("Select option", console=console)
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(wordlists):
                            self.options['wordlist'] = str(wordlists[idx])
                            console.print(f"[green]✓ Wordlist set to {self.options['wordlist']}[/green]\n")
                            break
                        elif choice == str(len(wordlists) + 1):
                            # Custom path
                            custom = Prompt.ask("Enter custom wordlist path", console=console)
                            if os.path.exists(custom):
                                self.options['wordlist'] = custom
                                console.print(f"[green]✓ Wordlist set to {custom}[/green]\n")
                                break
                            else:
                                console.print(f"[red]File not found: {custom}[/red]\n")
                        elif choice == str(len(wordlists) + 2):
                            break
                        else:
                            console.print("[red]Invalid selection[/red]\n")
                    except ValueError:
                        console.print("[red]Invalid input[/red]\n")
    
    def set_output(self):
        """Set output options"""
        while True:
            console.print("\n[bold cyan]Output Configuration[/bold cyan]")
            console.print("[dim]Choose how to display and save scan results[/dim]\n")
            console.print("  [cyan]1.[/cyan] CLI  [dim]→ Display results in formatted table[/dim]")
            console.print("  [cyan]2.[/cyan] CSV  [dim]→ Save to CSV file for spreadsheet analysis[/dim]")
            console.print("  [cyan]3.[/cyan] TXT  [dim]→ Save to text file (human-readable)[/dim]")
            console.print("  [cyan]4.[/cyan] Back [dim]→ Return to main menu[/dim]\n")
            
            output_format = Prompt.ask("Select option", console=console)
            
            if output_format == "1":
                self.options['output_format'] = 'cli'
                console.print("[green]✓ Output format set to CLI[/green]\n")
                break
            elif output_format == "2":
                self.options['output_format'] = 'csv'
                filename = Prompt.ask("Enter output filename", default="results.csv", console=console)
                self.options['output'] = filename
                console.print(f"[green]✓ Output set to {filename}[/green]\n")
                break
            elif output_format == "3":
                self.options['output_format'] = 'txt'
                filename = Prompt.ask("Enter output filename", default="results.txt", console=console)
                self.options['output'] = filename
                console.print(f"[green]✓ Output set to {filename}[/green]\n")
                break
            elif output_format == "4":
                break
            else:
                console.print("[red]Invalid option[/red]\n")
    
    def set_advanced_options(self):
        """Set advanced options"""
        while True:
            console.print("\n[bold cyan]Advanced Options[/bold cyan]")
            console.print("[dim]Fine-tune scanner behavior[/dim]\n")
            console.print("  [cyan]1.[/cyan] Timeout               [dim]→ Request timeout in seconds[/dim]")
            console.print("  [cyan]2.[/cyan] Fingerprints DB       [dim]→ Path to fingerprints database[/dim]")
            console.print("  [cyan]3.[/cyan] HTML Keywords         [dim]→ Path to HTML body keywords file[/dim]")
            console.print("  [cyan]4.[/cyan] Back                  [dim]→ Return to main menu[/dim]\n")
            
            choice = Prompt.ask("Select option", console=console)
            
            if choice == "1":
                timeout = Prompt.ask(
                    "Request timeout (seconds)",
                    default="8",
                    console=console
                )
                try:
                    self.options['timeout'] = int(timeout)
                    console.print(f"[green]✓ Timeout set to {timeout}s[/green]\n")
                except ValueError:
                    console.print("[red]Invalid timeout value[/red]\n")
            elif choice == "2":
                fp_path = Prompt.ask(
                    "Fingerprints database path",
                    default=self.options['fingerprints'],
                    console=console
                )
                if os.path.exists(fp_path):
                    self.options['fingerprints'] = fp_path
                    console.print(f"[green]✓ Fingerprints set to {fp_path}[/green]\n")
                else:
                    console.print(f"[red]File not found: {fp_path}[/red]\n")
            elif choice == "3":
                kw_path = Prompt.ask(
                    "HTML keywords file path",
                    default=self.options['html_keywords'],
                    console=console
                )
                if os.path.exists(kw_path):
                    self.options['html_keywords'] = kw_path
                    console.print(f"[green]✓ HTML keywords set to {kw_path}[/green]\n")
                else:
                    console.print(f"[red]File not found: {kw_path}[/red]\n")
            elif choice == "4":
                break
            else:
                console.print("[red]Invalid option[/red]\n")
    
    def set_modules(self):
        """Configure external modules and intelligence sources"""
        while True:
            console.print("\n[bold cyan]Modules & Intelligence[/bold cyan]")
            console.print("[dim]Configure external data sources and scanning modules[/dim]\n")
            console.print("  [cyan]1.[/cyan] Shodan Intelligence    [dim]→ Enrich scans with real-world service data[/dim]")
            console.print("  [cyan]2.[/cyan] Port Scanning          [dim]→ Enable Nmap port scanning[/dim]")
            console.print("  [cyan]3.[/cyan] Back                   [dim]→ Return to main menu[/dim]\n")
            
            choice = Prompt.ask("Select option", console=console)
            
            if choice == "1":
                self._configure_shodan()
            elif choice == "2":
                self.run_port_scan()
            elif choice == "3":
                break
            else:
                console.print("[red]Invalid option[/red]\n")
    
    def _configure_shodan(self):
        """Configure Shodan API"""
        console.print("\n[bold cyan]Shodan Intelligence Configuration[/bold cyan]")
        console.print("[dim]Real-world service intelligence for confidence boosting[/dim]\n")
        
        shodan_status = "[green]Enabled[/green]" if self.options['use_shodan'] else "[red]Disabled[/red]"
        console.print(f"Current status: {shodan_status}\n")
        
        console.print("  [cyan]1.[/cyan] Enable Shodan")
        console.print("  [cyan]2.[/cyan] Disable Shodan")
        console.print("  [cyan]3.[/cyan] Back\n")
        
        choice = Prompt.ask("Select option", console=console)
        
        if choice == "1":
            api_key = Prompt.ask("Enter Shodan API Key", password=True, console=console)
            if api_key:
                try:
                    # Validate API key by creating ShodanFingerprint instance
                    shodan_test = ShodanFingerprint(api_key)
                    # Check if Shodan API is actually available (successful validation)
                    if shodan_test.shodan_available:
                        console.print("[green]✓ Shodan API key validated[/green]")
                        self.options['use_shodan'] = True
                        self.options['shodan_api_key'] = api_key
                        self.shodan_client = shodan_test
                        console.print("[green]✓ Shodan enrichment enabled[/green]\n")
                    else:
                        console.print(f"[red]✗ Shodan API key invalid or API unavailable[/red]\n")
                        self.options['use_shodan'] = False
                except Exception as e:
                    console.print(f"[red]✗ Invalid Shodan API key: {str(e)[:100]}[/red]\n")
                    self.options['use_shodan'] = False
            else:
                console.print("[red]No API key provided[/red]\n")
        elif choice == "2":
            self.options['use_shodan'] = False
            self.shodan_client = None
            console.print("[green]✓ Shodan enrichment disabled[/green]\n")
    
    def run_port_scan(self):
        """Ask if user wants port scanning and configure it"""
        if not self.port_scanner.nmap_available:
            console.print("[red]✗ Error: Nmap is not installed[/red]")
            console.print("[yellow]Install with: brew install nmap[/yellow]\n")
            return False
        
        console.print("\n[bold cyan]Port Scanning Options[/bold cyan]")
        console.print("[dim]Include port scanning in the full VoidSeeker scan[/dim]\n")
        
        do_port_scan = Confirm.ask("Enable port scanning?", default=False, console=console)
        
        if not do_port_scan:
            return False
        
        # Choose intensity
        console.print("\n[cyan]Port Scan Intensity:[/cyan]")
        intensities = PortScanIntensity.list_intensities()
        for idx, (name, flags, ports, description) in enumerate(intensities, 1):
            console.print(f"  [cyan]{idx}.[/cyan] {name:20} [dim]{description}[/dim]")
        console.print()
        
        intensity_choice = Prompt.ask("Select intensity", default="2", console=console)
        
        try:
            choice_idx = int(intensity_choice) - 1
            if 0 <= choice_idx < len(intensities):
                intensity_name = intensities[choice_idx][0]
                self.options['port_scan_intensity'] = intensity_name
                console.print(f"[green]✓ Port scanning enabled: {intensity_name}[/green]\n")
                return True
            else:
                console.print("[red]Invalid selection[/red]\n")
                return False
        except ValueError:
            console.print("[red]Invalid input[/red]\n")
            return False
    
    def validate_options(self) -> bool:
        """Validate that required options are set"""
        if not self.options['targets'] and not self.options['single_target']:
            console.print("[red]Error: No targets specified[/red]")
            return False
        
        # Check targets file exists if using file-based targets
        if self.options['targets'] and not self.options['single_target']:
            if not os.path.exists(self.options['targets']):
                console.print(f"\n[red]✗ Error: Targets file not found: {self.options['targets']}[/red]")
                console.print("[yellow]  Tip: You can either:[/yellow]")
                console.print("[yellow]    1. Create a targets.txt file with one target per line[/yellow]")
                console.print("[yellow]    2. Use Menu → Set targets → Single target to specify one manually[/yellow]\n")
                logger.warning(f"Scan validation failed: targets file missing: {self.options['targets']}")
                return False
        
        if not os.path.exists(self.options['wordlist']):
            console.print(f"[red]Error: Wordlist not found: {self.options['wordlist']}[/red]")
            return False
        
        if not os.path.exists(self.options['fingerprints']):
            console.print(f"[red]Error: Fingerprints DB not found: {self.options['fingerprints']}[/red]")
            return False
        
        return True
    
    def _port_results_to_web_format(self, port_results: Dict, target_host: str) -> List[Dict]:
        """Convert port scan results to web scan results format for output"""
        web_results = []
        
        # Extract ports from nmap results structure
        # Structure: port_results['hosts'] -> [{'protocols': {'tcp': {port: {state, name, ...}}}}]
        for host_info in port_results.get('hosts', []):
            protocols = host_info.get('protocols', {})
            
            # Process TCP ports
            for port, port_data in protocols.get('tcp', {}).items():
                state = port_data.get('state')
                if state == 'open':
                    service = port_data.get('name', 'Unknown')
                    # Map domain to DNS
                    if port == 53 and service.lower() == 'domain':
                        service = 'dns'
                    result = {
                        'url': f"{target_host}:{port}",
                        'final_url': f"{target_host}:{port}",
                        'status': 200,
                        'service': service,
                        'confidence': 'MEDIUM',
                        'fingerprint_score': '15',
                        'looks_like_login': False,
                        'title': f"Port {port} ({service})",
                        'is_port_scan': True
                    }
                    web_results.append(result)
            
            # Process UDP ports
            for port, port_data in protocols.get('udp', {}).items():
                state = port_data.get('state')
                if state == 'open':
                    service = port_data.get('name', 'Unknown')
                    # Map domain to DNS
                    if port == 53 and service.lower() == 'domain':
                        service = 'dns'
                    result = {
                        'url': f"{target_host}:{port}/udp",
                        'final_url': f"{target_host}:{port}/udp",
                        'status': 200,
                        'service': f"{service} (UDP)",
                        'confidence': 'MEDIUM',
                        'fingerprint_score': '15',
                        'looks_like_login': False,
                        'title': f"Port {port} UDP ({service})",
                        'is_port_scan': True
                    }
                    web_results.append(result)
        
        return web_results
    
    def run_scan(self):
        """Execute the scan"""
        logger.info("Starting scan execution")
        
        if not self.validate_options():
            logger.warning("Scan aborted due to validation failure")
            return
        
        console.print("\n[bold cyan]Starting Scan...[/bold cyan]\n")
        
        # Load configuration
        try:
            logger.debug(f"Loading configuration - wordlist: {self.options['wordlist']}")
            self.common_paths = load_wordlist(self.options['wordlist'])
            self.fingerprints_db = load_fingerprints(self.options['fingerprints'], self.options['html_keywords'])
            self.session = create_session()
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            console.print(f"[red]Error loading configuration: {e}[/red]")
            return
        
        # Determine targets
        if self.options['single_target']:
            targets = [self.options['single_target']]
        else:
            targets = read_targets(self.options['targets'])
        
        logger.info(f"Scan starting with {len(targets)} target(s)")
        console.print(f"[cyan]Targets: {len(targets)}[/cyan]")
        console.print(f"[cyan]Paths: {len(self.common_paths)}[/cyan]")
        console.print(f"[cyan]Services: {len(self.fingerprints_db.get('services', {}))}[/cyan]\n")
        
        # Perform DNS reconnaissance on all targets
        dns_results = {}
        console.print("[bold cyan]Performing DNS Reconnaissance...[/bold cyan]\n")
        
        for target in targets:
            try:
                # Extract hostname/IP from target
                target_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                logger.debug(f"Performing DNS reconnaissance on {target_host}")
                dns_data = self.dns_recon.recon_target(target_host)
                dns_results[target_host] = dns_data
                
                # Log DNS results summary
                if dns_data:
                    has_reverse = bool(dns_data.get('reverse_dns'))
                    mx_count = len(dns_data.get('mx_records', []))
                    ns_count = len(dns_data.get('ns_records', []))
                    logger.debug(f"DNS recon for {target_host}: reverse={has_reverse}, MX={mx_count}, NS={ns_count}")
                else:
                    logger.debug(f"No DNS records found for {target_host}")
                
                # Display DNS findings (show all targets even if no findings)
                console.print(f"[cyan]{target_host}[/cyan]")
                if dns_data['interesting_findings']:
                    for finding in dns_data['interesting_findings']:
                        console.print(f"  [dim]→[/dim] {finding}")
                else:
                    console.print(f"  [dim]→ (no DNS findings)[/dim]")
            except Exception as e:
                # DNS reconnaissance is optional - don't fail the scan
                console.print(f"[cyan]{target}[/cyan]")
                console.print(f"  [dim]→ DNS error: {type(e).__name__}[/dim]")
        
        console.print()
        
        # Organize results by target for grouped output
        results_by_target = {}
        total_requests = len(targets) * len(self.common_paths)
        
        # Scan targets with per-request progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning {len(targets)} target(s) with {len(self.common_paths)} paths", total=total_requests)
            
            def progress_callback(count):
                progress.advance(task, count)
            
            for target_num, target in enumerate(targets, 1):
                results_by_target[target] = {'web': [], 'port': [], 'all': [], 'dns': {}}
                
                # Get DNS info for this target if available
                target_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                if target_host in dns_results:
                    results_by_target[target]['dns'] = dns_results[target_host]
                
                try:
                    logger.debug(f"Scanning target: {target}")
                    results = scan_url(target, self.common_paths, self.options['timeout'], 
                                     self.session, self.fingerprints_db, progress_callback=progress_callback)
                    
                    # Filter for successful responses (include redirects - they indicate accessible services)
                    for res in results:
                        if res["status"] in [200, 301, 302, 303, 307, 308]:
                            # Attach DNS info to each result
                            if results_by_target[target]['dns']:
                                res['dns_info'] = results_by_target[target]['dns']
                            results_by_target[target]['web'].append(res)
                    
                    logger.info(f"Target {target}: {len(results_by_target[target]['web'])} result(s)")
                    
                    # Enrich with Shodan intelligence if enabled
                    # Only query Shodan once per IP on root path to conserve API quota
                    if self.options['use_shodan'] and self.shodan_client and self.shodan_client.shodan_available and results_by_target[target]['web']:
                        try:
                            # Extract target IP/domain for Shodan lookup
                            target_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                            logger.debug(f"Enriching results for {target_host} with Shodan")
                            
                            # Find root path result (/) to query Shodan
                            root_result = None
                            for res in results_by_target[target]['web']:
                                if res.get('path') == '/':
                                    root_result = res
                                    break
                            
                            # If root path exists, query Shodan once and apply to all results
                            if root_result:
                                logger.debug(f"Querying Shodan for {target_host}")
                                shodan_enriched = self.shodan_client.enrich_local_scan(target_host, [root_result])
                                if shodan_enriched and len(shodan_enriched) > 0:
                                    # Extract Shodan metadata from root result
                                    shodan_org = shodan_enriched[0].get('shodan_org')
                                    shodan_country = shodan_enriched[0].get('shodan_country')
                                    logger.info(f"Shodan enrichment for {target_host}: org={shodan_org}, country={shodan_country}")
                                    
                                    # Apply Shodan metadata to all results for this IP
                                    for res in results_by_target[target]['web']:
                                        if shodan_org:
                                            res['shodan_org'] = shodan_org
                                        if shodan_country:
                                            res['shodan_country'] = shodan_country
                            else:
                                logger.debug(f"No root path result for Shodan lookup on {target_host}")
                        except Exception as e:
                            # Silently skip Shodan errors - scanning should continue
                            logger.warning(f"Shodan enrichment error for {target_host}: {e}")
                            pass
                
                except Exception as e:
                    logger.error(f"Error scanning {target}: {e}")
                    console.print(f"[red]Error scanning {target}: {e}[/red]")
                    progress.update(task, advance=len(self.common_paths))
        
        # Run port scanning if enabled
        if self.options['port_scan_intensity']:
            console.print("\n[bold cyan]Running Port Scans...[/bold cyan]\n")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"Port scanning target 1 of {len(targets)}", total=len(targets))
                
                for target_index, target in enumerate(targets, 1):
                    # Update the description for this target
                    progress.update(task, description=f"Port scanning target {target_index} of {len(targets)}")
                    
                    try:
                        # Clean target for port scanning (get hostname/IP only)
                        target_host = target.replace("https://", "").replace("http://", "").split("/")[0]
                        
                        logger.info(f"Starting port scan on {target_host} with intensity {self.options['port_scan_intensity']}")
                        results = self.port_scanner.scan_host(
                            target_host,
                            intensity=self.options['port_scan_intensity']
                        )
                        
                        if results.get('success'):
                            port_count = len(results.get('open_ports', []))
                            logger.info(f"Port scan on {target_host} found {port_count} open ports")
                            self.port_scanner.display_results(results, show_scripts=True)
                            # Convert port scan results to web results format
                            port_web_results = self._port_results_to_web_format(results, target_host)
                            results_by_target[target]['port'] = port_web_results
                        else:
                            logger.warning(f"Port scan on {target_host} did not complete successfully")
                    
                    except Exception as e:
                        logger.error(f"Error port scanning {target_host}: {e}", exc_info=True)
                        console.print(f"[red]Error port scanning {target}: {e}[/red]")
                    
                    # Advance to the next target
                    progress.advance(task, 1)
        
        # Merge web and port results for each target in order
        all_results = []
        for target in targets:
            target_results = results_by_target.get(target, {})
            all_results.extend(target_results.get('web', []))
            all_results.extend(target_results.get('port', []))
        
        logger.info(f"Scan completed. Total results collected: {len(all_results)} (web + port)")
        
        # Output results
        self.output_results(all_results)
    
    def output_results(self, results: List[Dict]):
        """Output scan results"""
        logger.info(f"Outputting {len(results)} results in format: {self.options['output_format']}")
        
        if not results:
            logger.info("No results to output")
            console.print("\n[yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/yellow]")
            console.print("[yellow]No accessible endpoints found[/yellow]")
            console.print("[dim]This could mean:[/dim]")
            console.print("[dim]  • Targets are not reachable (network/firewall)[/dim]")
            console.print("[dim]  • Services don't match the wordlist paths[/dim]")
            console.print("[dim]  • Timeout is too short for target response[/dim]")
            console.print("\n[yellow]Try:[/yellow]")
            console.print("[dim]  • Verify targets are accessible manually[/dim]")
            console.print("[dim]  • Increase timeout (Advanced Options)[/dim]")
            console.print("[dim]  • Try different wordlist (e.g., larger list)[/dim]")
            console.print("[yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/yellow]\n")
            return
        
        console.print(f"\n[bold green]Found {len(results)} accessible endpoint(s)[/bold green]\n")
        
        if self.options['output_format'] == 'cli':
            self.output_cli(results)
        elif self.options['output_format'] == 'csv':
            self.output_csv(results)
        elif self.options['output_format'] == 'txt':
            self.output_txt(results)
    
    def output_cli(self, results: List[Dict]):
        """Output to console using prettytable"""
        # Build column headers
        headers = ["URL", "Final URL", "Service", "Confidence", "Score", "Type"]
        if self.options['use_shodan']:
            headers.append("Shodan Info")
        headers.append("DNS Info")
        
        table = PrettyTable(headers)
        table.align["URL"] = "l"
        table.align["Final URL"] = "l"
        if self.options['use_shodan']:
            table.align["Shodan Info"] = "l"
            table.max_width["Shodan Info"] = 50
        table.align["DNS Info"] = "l"
        table.max_width["DNS Info"] = 50
        table.max_width["URL"] = 40
        table.max_width["Final URL"] = 40
        
        for res in results:
            service = res.get("service") or "Unknown"
            confidence = res.get("confidence") or "N/A"
            score = str(res.get("fingerprint_score", "0"))
            
            # Determine Type field based on result type
            if res.get("looks_like_login"):
                result_type = "Login"
            elif res.get("is_port_scan"):
                result_type = "Open Port"
            else:
                result_type = "Page"
            
            initial_url = res.get("url", "")
            final_url = res.get("final_url", initial_url)
            
            # Show redirect indicator
            if res.get("is_redirect"):
                final_url_display = f"{final_url} ↳"
            else:
                final_url_display = final_url
            
            row = [
                initial_url,
                final_url_display,
                service,
                confidence,
                score,
                result_type
            ]
            
            # Add Shodan metadata if present
            if self.options['use_shodan']:
                shodan_info = []
                if res.get('shodan_org'):
                    shodan_info.append(f"Org: {res.get('shodan_org')}")
                if res.get('shodan_country'):
                    shodan_info.append(f"Country: {res.get('shodan_country')}")
                if res.get('shodan_isp'):
                    shodan_info.append(f"ISP: {res.get('shodan_isp')}")
                shodan_display = "\n".join(shodan_info) if shodan_info else "—"
                row.append(shodan_display)
            
            # Add DNS metadata if present
            dns_info = []
            if res.get('dns_info'):
                dns_data = res['dns_info']
                if dns_data.get('reverse_dns'):
                    dns_info.append(f"PTR: {dns_data['reverse_dns']}")
                if dns_data.get('mx_records'):
                    mx_list = ', '.join([m[1] for m in dns_data['mx_records'][:2]])
                    dns_info.append(f"MX: {mx_list}")
                if dns_data.get('ns_records'):
                    ns_list = ', '.join(dns_data['ns_records'][:2])
                    dns_info.append(f"NS: {ns_list}")
            
            dns_display = "\n".join(dns_info) if dns_info else "—"
            row.append(dns_display)
            
            table.add_row(row)
        
        console.print("\n[bold cyan]Scan Results[/bold cyan]")
        console.print(table)
    
    def output_csv(self, results: List[Dict]):
        """Output to CSV file"""
        try:
            logger.info(f"Writing CSV output to {self.options['output']} with {len(results)} results")
            with open(self.options['output'], 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Headers
                headers = [
                    'URL', 'FinalURL', 'Service', 'Confidence', 'Score', 'Type', 
                    'Title', 'Server', 'IsLogin', 'Redirected'
                ]
                
                # Add Shodan columns if enrichment was used
                if self.options['use_shodan']:
                    headers.extend(['ShodanOrg', 'ShodanCountry', 'ShodanPorts', 'ShodanVulns', 'ShodanHostnames', 'ShodanTags'])
                
                # Add DNS columns
                headers.extend(['ReverseDNS', 'MXRecords', 'NSRecords'])
                
                writer.writerow(headers)
                
                for res in results:
                    # Determine Type field based on result type
                    if res.get("looks_like_login"):
                        result_type = "Login"
                    elif res.get("is_port_scan"):
                        result_type = "Open Port"
                    else:
                        result_type = "Page"
                    
                    row = [
                        res.get("url", ""),
                        res.get("final_url", res.get("url", "")),
                        res.get("service", "Unknown"),
                        res.get("confidence", "N/A"),
                        res.get("fingerprint_score", "0"),
                        result_type,
                        res.get("title", ""),
                        res.get("headers", {}).get("Server", ""),
                        res.get("looks_like_login", False),
                        "Yes" if res.get("is_redirect") else "No"
                    ]
                    
                    # Add Shodan data if enrichment was used
                    if self.options['use_shodan']:
                        row.extend([
                            res.get("shodan_org", ""),
                            res.get("shodan_country", ""),
                            res.get("shodan_ports", ""),
                            res.get("shodan_vulns", ""),
                            res.get("shodan_hostnames", ""),
                            res.get("shodan_tags", "")
                        ])
                    
                    # Add DNS data if available
                    dns_reverse = ""
                    dns_mx = ""
                    dns_ns = ""
                    if res.get('dns_info'):
                        dns_data = res['dns_info']
                        dns_reverse = dns_data.get('reverse_dns', '')
                        if dns_data.get('mx_records'):
                            dns_mx = '; '.join([f"{m[1]}" for m in dns_data['mx_records'][:3]])
                        if dns_data.get('ns_records'):
                            dns_ns = '; '.join(dns_data['ns_records'][:3])
                    
                    row.extend([dns_reverse, dns_mx, dns_ns])
                    writer.writerow(row)
                
                logger.info(f"Successfully wrote {len(results)} rows to CSV file {self.options['output']}")
            
            console.print(f"[green]✓ Results saved to {self.options['output']}[/green]")
        except Exception as e:
            logger.error(f"Error writing CSV to {self.options['output']}: {e}", exc_info=True)
            console.print(f"[red]Error writing CSV: {e}[/red]")
    
    def output_txt(self, results: List[Dict]):
        """Output to text file with prettytable"""
        try:
            logger.info(f"Writing TXT output to {self.options['output']} with {len(results)} results")
            with open(self.options['output'], 'w', encoding='utf-8') as f:
                f.write("VoidSeeker Scan Results\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                if self.options['use_shodan']:
                    f.write("Enrichment: Shodan Intelligence Enabled\n")
                f.write("\n")
                
                # Build prettytable
                headers = ["URL", "Final URL", "Service", "Confidence", "Score", "Type"]
                if self.options['use_shodan']:
                    headers.extend(["Organization", "Country", "Ports", "Vulns"])
                
                table = PrettyTable(headers)
                table.align["URL"] = "l"
                table.align["Final URL"] = "l"
                
                for res in results:
                    service = res.get("service") or "Unknown"
                    confidence = res.get("confidence") or "N/A"
                    score = str(res.get("fingerprint_score", "0"))
                    
                    # Determine Type field based on result type
                    if res.get("looks_like_login"):
                        result_type = "Login"
                    elif res.get("is_port_scan"):
                        result_type = "Open Port"
                    else:
                        result_type = "Page"
                    
                    initial_url = res.get("url", "")
                    final_url = res.get("final_url", initial_url)
                    
                    row = [
                        initial_url,
                        final_url,
                        service,
                        confidence,
                        score,
                        result_type
                    ]
                    
                    if self.options['use_shodan']:
                        row.extend([
                            res.get('shodan_org', ''),
                            res.get('shodan_country', ''),
                            res.get('shodan_ports', ''),
                            res.get('shodan_vulns', '')
                        ])
                    
                    table.add_row(row)
                
                f.write(str(table))
                f.write("\n\n")
                
                # Write detailed information for each result
                f.write("\n" + "="*80 + "\n")
                f.write("DETAILED RESULTS\n")
                f.write("="*80 + "\n\n")
                
                for i, res in enumerate(results, 1):
                    f.write(f"[Result {i}]\n")
                    f.write(f"Initial URL: {res.get('url', '')}\n")
                    if res.get('is_redirect'):
                        f.write(f"Final URL: {res.get('final_url', res.get('url', ''))}\n")
                        if res.get('redirect_chain'):
                            f.write(f"Redirect Chain:\n")
                            for redirect in res.get('redirect_chain', []):
                                f.write(f"  {redirect['status']}: {redirect['from']} → {redirect['to']}\n")
                    f.write(f"Service: {res.get('service', 'Unknown')}\n")
                    f.write(f"Confidence: {res.get('confidence', 'N/A')}\n")
                    f.write(f"Score: {res.get('fingerprint_score', '0')}\n")
                    
                    # Determine Type field based on result type
                    if res.get('looks_like_login'):
                        result_type = 'Login Page'
                    elif res.get('is_port_scan'):
                        result_type = 'Open Port'
                    else:
                        result_type = 'Regular Page'
                    
                    f.write(f"Type: {result_type}\n")
                    if res.get('title'):
                        f.write(f"Title: {res.get('title')}\n")
                    if res.get('headers', {}).get('Server'):
                        f.write(f"Server: {res.get('headers', {}).get('Server')}\n")
                    
                    if self.options['use_shodan']:
                        if res.get('shodan_org'):
                            f.write(f"Shodan Organization: {res.get('shodan_org')}\n")
                        if res.get('shodan_country'):
                            f.write(f"Shodan Country: {res.get('shodan_country')}\n")
                        if res.get('shodan_isp'):
                            f.write(f"Shodan ISP: {res.get('shodan_isp')}\n")
                        if res.get('shodan_asn'):
                            f.write(f"Shodan ASN: {res.get('shodan_asn')}\n")
                        if res.get('shodan_ports'):
                            f.write(f"Shodan Ports: {res.get('shodan_ports')}\n")
                        if res.get('shodan_vulns'):
                            f.write(f"Shodan Vulnerabilities: {res.get('shodan_vulns')}\n")
                        if res.get('shodan_hostnames'):
                            f.write(f"Shodan Hostnames: {res.get('shodan_hostnames')}\n")
                        if res.get('shodan_tags'):
                            f.write(f"Shodan Tags: {res.get('shodan_tags')}\n")
                    
                    f.write("-" * 80 + "\n\n")
                
                logger.info(f"Successfully wrote {len(results)} detailed results to TXT file {self.options['output']}")
            
            console.print(f"[green]✓ Results saved to {self.options['output']}[/green]")
        except Exception as e:
            logger.error(f"Error writing TXT to {self.options['output']}: {e}", exc_info=True)
            console.print(f"[red]Error writing TXT: {e}[/red]")
    
    def _display_config_inline(self):
        """Display current configuration in a formatted box"""
        # Safely get target count, handling missing file
        try:
            targets_display = "Single target" if self.options['single_target'] else (
                f"{len(read_targets(self.options['targets']))} targets" 
                if self.options['targets'] and Path(self.options['targets']).exists() else "[red]Not set[/red]"
            )
        except Exception:
            targets_display = "[red]Not set[/red]"
        
        shodan_status = "[green]✓ Enabled[/green]" if self.options['use_shodan'] else "[red]✗ Disabled[/red]"
        port_scan_status = f"[green]✓ {self.options['port_scan_intensity']}[/green]" if self.options['port_scan_intensity'] else "[red]✗ Disabled[/red]"
        
        config_text = (
            f"Targets:        {targets_display}\n"
            f"Wordlist:       {os.path.basename(self.options['wordlist'])}\n"
            f"Output:         {self.options['output_format'].upper()} → {self.options['output'] or 'Console'}\n"
            f"Timeout:        {self.options['timeout']}s\n"
            f"Shodan:         {shodan_status}\n"
            f"Port Scanning:  {port_scan_status}"
        )
        
        console.print(Panel(config_text, title="[bold cyan]Current Configuration[/bold cyan]", border_style="cyan", expand=False, width=80))
    
    def main_menu(self):
        """Main interactive menu"""
        self.banner()
        
        while True:
            console.print("\n[bold cyan]═══════════════════════════════════[/bold cyan]")
            console.print("[bold cyan]VoidSeeker Interactive Menu[/bold cyan]")
            console.print("[bold cyan]═══════════════════════════════════[/bold cyan]\n")
            
            # Display current configuration inline
            self._display_config_inline()
            
            console.print("\n[cyan]Configuration:[/cyan]")
            console.print("  [cyan]1.[/cyan] Set targets         [dim]→ Choose target(s) to scan[/dim]")
            console.print("  [cyan]2.[/cyan] Set wordlist        [dim]→ Select paths to enumerate[/dim]")
            console.print("  [cyan]3.[/cyan] Set output          [dim]→ Choose output format & location[/dim]")
            console.print("  [cyan]4.[/cyan] Advanced options    [dim]→ Timeout & fingerprints database[/dim]")
            
            console.print("\n[cyan]Intelligence & Modules:[/cyan]")
            console.print("  [cyan]5.[/cyan] Modules             [dim]→ Shodan, port scanning, and more[/dim]")
            
            console.print("\n[cyan]Execution:[/cyan]")
            console.print("  [cyan]6.[/cyan] Run scan            [dim]→ Start full enumeration[/dim]")
            
            console.print("\n[cyan]Exit:[/cyan]")
            console.print("  [cyan]7.[/cyan] Exit                [dim]→ Quit VoidSeeker[/dim]\n")
            
            choice = Prompt.ask("[cyan]Select option[/cyan]", console=console)
            
            if choice == "1":
                self.set_targets()
            elif choice == "2":
                self.set_wordlist()
            elif choice == "3":
                self.set_output()
            elif choice == "4":
                self.set_advanced_options()
            elif choice == "5":
                self.set_modules()
            elif choice == "6":
                self.run_scan()
            elif choice == "7":
                console.print("[cyan]Exiting VoidSeeker[/cyan]")
                break
            else:
                console.print("[red]Invalid option[/red]")


def main():
    """Entry point"""
    menu = VoidSeekerMenu()
    try:
        menu.main_menu()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
