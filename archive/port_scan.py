import nmap  # pip install python-nmap

target_host = 'http://scanme.nmap.org/'
target_ports = ''
nmap_flags = '-sV -sC -O --script vuln'

def clean_url(url):
    """
    Remove leading http:// or https:// and trailing / from a URL.
    
    Args:
        url: URL string to clean
    
    Returns:
        str: Cleaned URL/hostname
    """
    cleaned = url.strip()
    
    # Remove leading http:// or https://
    if cleaned.startswith('https://'):
        cleaned = cleaned[8:]
    elif cleaned.startswith('http://'):
        cleaned = cleaned[7:]
    
    # Remove trailing /
    cleaned = cleaned.rstrip('/')
    
    return cleaned


def scan_host(host=None, port_range=None, flags=None):
    """
    Scan a host for open ports and services.
    
    Args:
        host: IP address or hostname to scan (default: uses target_host global)
        port_range: Port range to scan (default: uses target_ports global)
        flags: Nmap flags to use (default: uses nmap_flags global)
    
    Returns:
        dict: Scan results
    """
    # Use global variables if no arguments provided
    scan_target = host if host is not None else target_host
    scan_ports = port_range if port_range is not None else target_ports
    scan_flags = flags if flags is not None else nmap_flags
    
    # Clean the target URL/hostname
    scan_target = clean_url(scan_target)

    nm = nmap.PortScanner()
    
    try:
        # Scan without port specification if scan_ports is empty
        if scan_ports:
            nm.scan(scan_target, scan_ports, arguments=scan_flags)
        else:
            nm.scan(scan_target, arguments=scan_flags)
    except nmap.PortScannerError as e:
        # If OS detection fails due to lack of root privileges, retry without -O flag
        if 'requires root privileges' in str(e):
            print(f"Warning: {e}")
            print("Retrying scan without OS detection (-O flag)...")
            scan_flags_no_root = scan_flags.replace('-O', '').strip()
            if scan_ports:
                nm.scan(scan_target, scan_ports, arguments=scan_flags_no_root)
            else:
                nm.scan(scan_target, arguments=scan_flags_no_root)
        else:
            raise
    
    results = {
        'command': nm.command_line(),
        'scan_info': nm.scaninfo(),
        'hosts': []
    }
    
    for scanned_host in nm.all_hosts():
        host_info = {
            'host': scanned_host,
            'hostname': nm[scanned_host].hostname(),
            'state': nm[scanned_host].state(),
            'protocols': {}
        }
        
        for proto in nm[scanned_host].all_protocols():
            host_info['protocols'][proto] = {}
            lport = list(nm[scanned_host][proto].keys())
            lport.sort()
            
            for port in lport:
                host_info['protocols'][proto][port] = nm[scanned_host][proto][port]
        
        results['hosts'].append(host_info)
    
    return results

def print_scan_results(results):
    """
    Print scan results in a formatted way.
    
    Args:
        results: Dictionary of scan results from scan_host()
    """
    print(f"Command: {results['command']}")
    print(f"Scan Info: {results['scan_info']}")
    print()
    
    for host_info in results['hosts']:
        print('----------------------------------------------------')
        print(f"Host: {host_info['host']} ({host_info['hostname']})")
        print(f"State: {host_info['state']}")
        
        for proto, ports in host_info['protocols'].items():
            print('----------')
            print(f"Protocol: {proto}")
            
            for port, port_info in ports.items():
                print(f"\n  Port: {port}\tState: {port_info['state']}\tService: {port_info.get('name', 'unknown')}")
                
                # Print service version if available
                if 'product' in port_info:
                    version_info = port_info.get('product', '')
                    if 'version' in port_info:
                        version_info += f" {port_info['version']}"
                    if 'extrainfo' in port_info:
                        version_info += f" ({port_info['extrainfo']})"
                    print(f"    Version: {version_info}")
                
                # Print NSE script results (including vuln scripts)
                if 'script' in port_info:
                    print(f"    Script Results:")
                    for script_name, script_output in port_info['script'].items():
                        print(f"      [{script_name}]")
                        # Indent script output
                        for line in script_output.split('\n'):
                            print(f"        {line}")
                        print()

if __name__ == "__main__":
    # Example usage - uses global variables by default
    results = scan_host()
    print_scan_results(results)
