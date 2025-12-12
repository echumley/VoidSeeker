"""
VoidSeeker Core Scanning Engine

Provides the core functionality for:
- Loading fingerprint databases and wordlists
- Scanning URLs for accessible paths
- Service fingerprinting via multi-signal analysis
- Result deduplication and reporting
"""
import argparse
import sys
import csv
import json
import ssl
from typing import List, Dict, Optional, Tuple, Callable, Any
from urllib.parse import urljoin
from pathlib import Path
import requests
from urllib3.util.ssl_ import create_urllib3_context
import hashlib
import urllib3
import logging

from config.logging_config import get_logger

# Initialize logger
logger = get_logger(__name__)

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def normalize_base_url(raw: str) -> str:
    """
    Normalize and validate a target URL.
    
    Args:
        raw: Raw URL string (may be hostname or full URL)
    
    Returns:
        Normalized URL with protocol and trailing slash, or empty string if invalid
    
    Raises:
        None - returns empty string on invalid input
    """
    if not isinstance(raw, str):
        logger.warning(f"Invalid target type: {type(raw)}, expected str")
        return ""
    
    raw = raw.strip()
    if not raw:
        return ""
    
    # Add https:// if no protocol specified
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw
    
    # Ensure trailing slash
    if not raw.endswith("/"):
        raw += "/"
    
    logger.debug(f"Normalized URL: {raw}")
    return raw


def get_page_title(html: str) -> Optional[str]:
    """
    Extract page title from HTML content.
    
    Args:
        html: HTML content string
    
    Returns:
        Title text if found and non-empty, None otherwise
    """
    if not html or not isinstance(html, str):
        return None
    
    html_lower = html.lower()
    start = html_lower.find("<title")
    if start == -1:
        return None
    
    start = html_lower.find(">", start)
    if start == -1:
        return None
    
    end = html_lower.find("</title>", start)
    if end == -1:
        return None
    
    title = html[start + 1:end].strip()
    # Normalize whitespace
    return " ".join(title.split()) if title else None

def create_session() -> requests.Session:
    """
    Create a requests session with default headers and configuration.
    
    Returns:
        Configured requests.Session instance
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "VoidSeeker/1.0 (+https://github.com/void-seeker)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    })
    logger.debug("Created HTTP session with default headers")
    return session

def load_fingerprints(fingerprints_path: str, html_keywords_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load fingerprint database from JSON file and optional HTML keywords file.
    
    Args:
        fingerprints_path: Path to JSON fingerprints database
        html_keywords_path: Optional path to HTML keywords file (overrides database setting)
    
    Returns:
        Dictionary containing fingerprint data and loaded keywords
    
    Raises:
        FileNotFoundError: If fingerprints file doesn't exist
        json.JSONDecodeError: If fingerprints file is invalid JSON
    """
    if not fingerprints_path:
        raise ValueError("fingerprints_path cannot be empty")
    
    try:
        logger.debug(f"Loading fingerprints from {fingerprints_path}")
        with open(fingerprints_path, "r", encoding="utf-8") as f:
            fingerprints = json.load(f)
    except FileNotFoundError as e:
        logger.error(f"Fingerprints file not found: {fingerprints_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in fingerprints file: {e}")
        raise
    
    # Validate structure
    if not isinstance(fingerprints, dict):
        raise ValueError("Fingerprints file must contain a JSON object")
    
    if "services" not in fingerprints:
        logger.warning("Fingerprints database missing 'services' key")
        fingerprints["services"] = {}
    
    # Determine which keywords file to use (parameter takes precedence)
    keywords_file = html_keywords_path if html_keywords_path else fingerprints.get("html_keywords_file")
    
    # Load HTML keywords file if specified
    if keywords_file:
        try:
            logger.debug(f"Loading HTML keywords from {keywords_file}")
            with open(keywords_file, "r", encoding="utf-8") as f:
                html_keywords = [line.strip().lower() for line in f.readlines() if line.strip()]
            fingerprints["html_keywords"] = html_keywords
            logger.info(f"Loaded {len(html_keywords)} HTML keywords")
        except FileNotFoundError:
            logger.warning(f"HTML keywords file not found: {keywords_file}, continuing without keywords")
        except IOError as e:
            logger.warning(f"Failed to read HTML keywords file: {e}")
    
    service_count = len(fingerprints.get('services', {}))
    logger.info(f"Loaded {service_count} services from fingerprints database")
    return fingerprints


def extract_tls_cn(url: str) -> Optional[str]:
    """Extract CN from TLS certificate."""
    try:
        hostname = url.split("://")[1].split("/")[0].split(":")[0]
        context = create_urllib3_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        import socket
        conn = socket.create_connection((hostname, 443), timeout=5)
        ssock = context.wrap_socket(conn, server_hostname=hostname)
        cert = ssock.getpeercert()
        ssock.close()
        
        if cert and 'subject' in cert:
            for rdn in cert['subject']:
                for name, value in rdn:
                    if name == 'commonName':
                        return value
    except Exception:
        pass
    return None

def match_service_signals(url: str, response: requests.Response, fingerprints: Dict[str, Any], looks_like_login: bool = False) -> Dict[str, Any]:
    """
    Analyze response signals and match against fingerprint database.
    
    Args:
        url: Scanned URL
        response: requests.Response object (or compatible object with headers, text, status_code)
        fingerprints: Fingerprints database dictionary
        looks_like_login: Whether page appears to be a login form
    
    Returns:
        Dictionary mapping service_name -> {score, matched_signals, confidence, name}
    """
    service_scores = {}
    
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text[:4096] if response.status_code == 200 else ""
    body_lower = body.lower()
    title = get_page_title(body) if body else ""
    title_lower = title.lower() if title else ""
    
    # Extract path from URL
    url_lower = url.lower()
    
    for service_key, service_data in fingerprints.get("services", {}).items():
        score = 0
        matched_signals = {}
        
        signals = service_data.get("signals", {})
        weights = service_data.get("weights", {})
        
        # Check server header
        if "server_headers" in signals:
            for pattern in signals["server_headers"]:
                if pattern.lower() in headers.get("server", "").lower():
                    weight = weights.get("server_header", 7)
                    score += weight
                    matched_signals["server_header"] = headers.get("server", "")
                    break
        
        # Check HTML title patterns
        if "html_title_patterns" in signals and title:
            for pattern in signals["html_title_patterns"]:
                if pattern.lower() in title_lower:
                    weight = weights.get("html_title", 6)
                    score += weight
                    matched_signals["html_title"] = title
                    break
        
        # Check URL patterns
        if "url_patterns" in signals:
            for pattern in signals["url_patterns"]:
                if pattern.lower() in url_lower:
                    weight = weights.get("url_pattern", 3)
                    score += weight
                    matched_signals["url_pattern"] = pattern
                    break
        
        # Check page body for service names and patterns
        if "html_body_patterns" in signals:
            for pattern in signals["html_body_patterns"]:
                if pattern.lower() in body_lower:
                    weight = weights.get("html_body", 5)
                    score += weight
                    matched_signals["html_body"] = pattern
                    break
        
        # Check page body against general HTML keywords file
        if body_lower and "html_keywords" in fingerprints:
            html_keywords = fingerprints.get("html_keywords", [])
            matched_keywords_count = 0
            for keyword in html_keywords:
                # Check for keyword in various contexts: direct matches, within quotes, in filenames, etc.
                if (keyword in body_lower or 
                    f'"{keyword}' in body_lower or 
                    f"'{keyword}" in body_lower or
                    f'/{keyword}' in body_lower or
                    f'.{keyword}' in body_lower or
                    f'_{keyword}' in body_lower or
                    f'-{keyword}' in body_lower):
                    matched_keywords_count += 1
                    if matched_keywords_count == 1:
                        # Store the first matched keyword
                        matched_signals["html_keyword"] = keyword
            
            # Award points based on number of matched keywords
            if matched_keywords_count >= 3:
                # Multiple keywords matched = likely a real service
                weight = weights.get("html_keyword", 3)
                if weight > 0:
                    score += weight * min(matched_keywords_count // 2, 3)  # Scale up but cap at 3x weight
            elif matched_keywords_count == 1:
                # Single keyword match
                weight = weights.get("html_keyword", 3)
                if weight > 0:
                    score += weight
        
        # Check for X-Jenkins or other distinctive headers
        if "X-Jenkins" in response.headers:
            if service_key == "jenkins":
                score += weights.get("header_x_jenkins", 12)
                matched_signals["x_jenkins"] = response.headers["X-Jenkins"]
        
        # Check TLS CN
        if "tls_cn_patterns" in signals:
            tls_cn = extract_tls_cn(url)
            if tls_cn:
                for pattern in signals["tls_cn_patterns"]:
                    if pattern.lower() in tls_cn.lower():
                        weight = weights.get("tls_cn", 8)
                        score += weight
                        matched_signals["tls_cn"] = tls_cn
                        break
        
        # Check cookie patterns
        if "cookie_patterns" in signals:
            cookies = response.headers.get("set-cookie", "").lower()
            for pattern in signals["cookie_patterns"]:
                if pattern.lower() in cookies:
                    weight = weights.get("cookie_pattern", 5)
                    score += weight
                    matched_signals["cookie"] = pattern
                    break
        
        # Boost generic_login_portal if page looks like a login
        if service_key == "generic_login_portal" and looks_like_login:
            score += 5  # Bonus for detected login patterns (reduced to not override IMPI detection)
        
        if score > 0:
            service_scores[service_key] = {
                "name": service_data.get("name", service_key),
                "score": score,
                "signals": matched_signals,
                "confidence": get_confidence_level(score)
            }
    
    return service_scores

def get_confidence_level(score: int) -> str:
    """Map score to confidence level."""
    if score >= 21:
        return "HIGH"
    elif score >= 11:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    else:
        return "UNKNOWN"

def load_wordlist(wordlist_path: str) -> List[str]:
    """
    Load scanning paths from a wordlist file (one per line).
    
    Args:
        wordlist_path: Path to wordlist file
    
    Returns:
        List of non-empty paths
    
    Raises:
        FileNotFoundError: If wordlist file doesn't exist
        IOError: If file cannot be read
    """
    if not wordlist_path:
        raise ValueError("wordlist_path cannot be empty")
    
    try:
        logger.debug(f"Loading wordlist from {wordlist_path}")
        with open(wordlist_path, "r", encoding="utf-8") as f:
            paths = [line.strip() for line in f.readlines() if line.strip()]
        logger.info(f"Loaded {len(paths)} paths from wordlist")
        return paths
    except FileNotFoundError:
        logger.error(f"Wordlist file not found: {wordlist_path}")
        raise
    except IOError as e:
        logger.error(f"Failed to read wordlist file {wordlist_path}: {e}")
        raise
def scan_url(
    base_url: str,
    paths: List[str],
    timeout: int,
    session: requests.Session,
    fingerprints: Dict[str, Any],
    progress_callback: Optional[Callable[[int], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Scan a single base URL against a list of paths.
    
    Follows redirects and deduplicates results based on final landing page.
    
    Args:
        base_url: Target URL to scan
        paths: List of path segments to test
        timeout: Request timeout in seconds
        session: requests.Session instance
        fingerprints: Fingerprint database dictionary
        progress_callback: Optional callable to receive scan progress updates
    
    Returns:
        List of result dictionaries with fingerprinting information
    """
    if not base_url or not paths:
        logger.warning(f"Invalid scan parameters: base_url={base_url}, paths_count={len(paths) if paths else 0}")
        return []
    
    if timeout <= 0:
        raise ValueError(f"timeout must be positive, got {timeout}")
    
    logger.info(f"Starting scan of {base_url} with {len(paths)} paths")
    results: List[Dict[str, Any]] = []
    seen_final_urls: Dict[str, Dict[str, Any]] = {}  # Maps final URL to best result for that URL

    for path_index, path in enumerate(paths):
        full_url = urljoin(base_url, path)
        logger.debug(f"Testing path: {full_url}")
        final_url = full_url
        final_status = None
        final_headers = {}
        final_body = ""
        redirect_chain = []

        try:
            # Follow redirects manually to track the chain
            current_url = full_url
            for redirect_attempt in range(10):  # Max 10 redirects
                resp = session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=timeout,
                    verify=False,
                )
                
                final_status = resp.status_code
                final_headers = dict(resp.headers)
                
                # Check if this is a redirect
                if 300 <= resp.status_code < 400:
                    location = resp.headers.get("Location")
                    logger.debug(f"Redirect {resp.status_code} from {current_url} to {location}")
                    if location:
                        next_url = urljoin(current_url, location)
                        redirect_chain.append({
                            "from": current_url,
                            "to": next_url,
                            "status": resp.status_code
                        })
                        current_url = next_url
                        continue
                
                # Not a redirect, we've reached the final page
                final_url = current_url
                if resp.status_code == 200:
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "text" in content_type or "html" in content_type:
                        final_body = resp.text[:4096]
                break
        except requests.RequestException as e:
            logger.debug(f"Request error for {full_url}: {type(e).__name__} - {str(e)[:100]}")
            results.append({
                "base": base_url,
                "path": path,
                "url": full_url,
                "final_url": full_url,
                "status": "ERROR",
                "reason": str(e),
                "headers": {},
                "title": None,
                "looks_like_login": False,
                "is_redirect": False,
                "redirect_chain": [],
                "service": None,
                "confidence": None,
                "fingerprint_score": None,
            })
            if progress_callback:
                progress_callback(1)
            continue

        # Analyze the final page
        title = None
        looks_like_login = False
        service = None
        confidence = None
        fingerprint_score = None
        
        if final_status == 200 and final_body:
            title = get_page_title(final_body)
            text = ((title or "") + " " + final_body).lower()
            looks_like_login = any(
                kw in text for kw in ["login", "log in", "sign in", "password", "username", "account"]
            )
            logger.debug(f"Response 200 received for {final_url} - title: {title}, looks_like_login: {looks_like_login}")
            
            # Fingerprint the service
            # Create a temporary response-like object for fingerprinting
            class FakeScanResponse:
                def __init__(self, headers, text):
                    self.headers = headers
                    self.text = text
                    self.status_code = 200
            
            fake_resp = FakeScanResponse(final_headers, final_body)
            service_matches = match_service_signals(final_url, fake_resp, fingerprints, looks_like_login) # type: ignore
            if service_matches:
                # Get the best match
                best_match = max(service_matches.items(), key=lambda x: x[1]["score"])
                service = best_match[1]["name"]
                confidence = best_match[1]["confidence"]
                fingerprint_score = best_match[1]["score"]
                logger.info(f"Identified service: {service} ({confidence}) for {final_url}")
            else:
                logger.debug(f"No service fingerprint matched for {final_url}")
        elif final_status and final_status != 200:
            logger.debug(f"HTTP {final_status} received for {final_url} - path: {path}")
        
        # Build the result
        result_dict = {
            "base": base_url,
            "path": path,
            "url": full_url,
            "final_url": final_url,
            "status": final_status,
            "reason": getattr(resp, 'reason', 'Unknown') if final_status else 'Unknown',  # type: ignore
            "headers": final_headers,
            "title": title,
            "looks_like_login": looks_like_login,
            "is_redirect": len(redirect_chain) > 0,
            "redirect_chain": redirect_chain,
            "service": service,
            "confidence": confidence,
            "fingerprint_score": fingerprint_score,
        }
        
        # Deduplication: only keep one result per final URL
        # Prefer login-specific paths if multiple paths lead to the same place
        if final_url in seen_final_urls:
            existing = seen_final_urls[final_url]
            current_is_login_path = "login" in path.lower() or "auth" in path.lower()
            existing_is_login_path = "login" in existing["path"].lower() or "auth" in existing["path"].lower()
            
            # Keep current if it's a more specific login path
            if current_is_login_path and not existing_is_login_path:
                seen_final_urls[final_url] = result_dict
                logger.debug(f"Dedup: replaced {existing['path']} with {path} (more specific login path)")
            else:
                logger.debug(f"Dedup: skipping {path} (duplicate final URL with existing {existing['path']})")
        else:
            seen_final_urls[final_url] = result_dict
            logger.debug(f"Dedup: added {path} -> {final_url}")
        
        # Call progress callback if provided
        if progress_callback:
            progress_callback(1)

    # Add all deduplicated results
    results.extend(seen_final_urls.values())
    logger.info(f"Scan of {base_url} complete: {len(results)} accessible endpoint(s) found")
    return results

def fingerprint_sink(
    session: requests.Session,
    sink_url: str,
    timeout: int = 8,
) -> Optional[Dict[str, Any]]:
    """
    Fetch and analyze a sink URL endpoint.
    
    Does not follow redirects - analyzes the exact response received.
    
    Args:
        session: requests.Session instance
        sink_url: URL to analyze
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with analysis results, or None if request fails
    """
    if not sink_url or not isinstance(sink_url, str):
        logger.warning(f"Invalid sink URL: {sink_url}")
        return None
    
    try:
        r = session.get(
            sink_url,
            allow_redirects=False,
            timeout=timeout,
            verify=False,
        )
    except requests.RequestException as e:
        logger.warning(f"Failed to fingerprint sink {sink_url}: {type(e).__name__}")
        return None

    headers = dict(r.headers)
    content_type = headers.get("Content-Type", "").lower()
    body = r.text[:4096] if "text" in content_type else ""
    title = get_page_title(body) if body else None
    text = ((title or "") + " " + body).lower()

    looks_like_login = any(
        kw in text for kw in ["login", "log in", "sign in", "password", "username", "account"]
    )

    return {
        "status": r.status_code,
        "reason": r.reason,
        "headers": headers,
        "title": title,
        "looks_like_login": looks_like_login,
    }


def read_targets(file_path: str) -> List[str]:
    """
    Read and normalize target URLs from a file.
    
    Args:
        file_path: Path to file containing one target per line
    
    Returns:
        List of normalized target URLs (empty strings filtered out)
    
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    if not file_path:
        raise ValueError("file_path cannot be empty")
    
    try:
        logger.debug(f"Reading targets from {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [normalize_base_url(line) for line in f.readlines()]
        targets = [l for l in lines if l]  # Filter empty strings
        logger.debug(f"Read {len(targets)} valid target(s) from {file_path}")
        return targets
    except FileNotFoundError:
        logger.error(f"Targets file not found: {file_path}")
        raise
    except IOError as e:
        logger.error(f"Failed to read targets file {file_path}: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Deep web service enumeration and fingerprinting scanner."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to text file containing one base URL or hostname per line.",
    )
    parser.add_argument(
        "-w", "--wordlist",
        default="config/wordlists/common-subdirectories.txt",
        help="Path to wordlist file containing paths to scan (default: config/wordlists/common-subdirectories.txt)",
    )
    parser.add_argument(
        "-f", "--fingerprints",
        default="config/fingerprints.json",
        help="Path to fingerprints database file (default: config/fingerprints.json).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output file (CSV) for results.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="Request timeout in seconds (default: 8).",
    )
    args = parser.parse_args()

    targets = read_targets(args.input)
    if not targets:
        print("No valid targets found in input file.", file=sys.stderr)
        sys.exit(1)

    common_paths = load_wordlist(args.wordlist)
    if not common_paths:
        print("No paths found in wordlist file.", file=sys.stderr)
        sys.exit(1)

    fingerprints = load_fingerprints(args.fingerprints)

    print(f"[+] Loaded {len(targets)} targets from {args.input}")
    print(f"[+] Loaded {len(common_paths)} paths from {args.wordlist}")
    print(f"[+] Loaded fingerprints for {len(fingerprints.get('services', {}))} services")
    print("[+] Scanning and fingerprinting...\n")

    # Prepare CSV writer if needed
    csv_file = open(args.output, "w", newline="", encoding="utf-8") if args.output else None
    csv_writer = None
    if csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([
            "base",
            "path",
            "url",
            "status",
            "reason",
            "looks_like_login",
            "title",
            "service",
            "confidence",
            "fingerprint_score",
            "redirect_target",
            "is_redirect",
        ])

    session = create_session()

    for base in targets:
        print(f"=== Target: {base} ===")
        results = scan_url(base, common_paths, args.timeout, session, fingerprints)

        # Map of redirect target → list of request rows that redirected there
        sink_map: Dict[str, List[Dict]] = {}
        for r in results:
            if r.get("is_redirect") and r.get("redirect_target"):
                sink_map.setdefault(r["redirect_target"], []).append(r)

        # Detect generic "sinkholes" where multiple paths redirect to the same URL
        # (no longer requiring 'login' in the URL)
        sinkholes = {
            sink for sink, rows in sink_map.items()
            if len(rows) >= 2  # tweak threshold if you want
        }

        # Summarize sinkholes and fingerprint them
        for sink in sinkholes:
            alias_paths = [row["path"] for row in sink_map[sink]]
            print(f"  [*] Detected common sink: {sink}")
            print(f"      Aliases ({len(alias_paths)}): {', '.join(alias_paths[:5])}")
            if len(alias_paths) > 5:
                print(f"      ... and {len(alias_paths) - 5} more")

            fp = fingerprint_sink(session, sink, timeout=args.timeout)
            if fp:
                print(f"      Status: {fp['status']} {fp['reason']}")
                if fp["title"]:
                    print(f"      Title: {fp['title']}")
                if fp["looks_like_login"]:
                    print("      Heuristic: looks like a login / auth portal")
                # Show a couple of headers
                for h in ["Server", "X-Powered-By", "Set-Cookie"]:
                    if h in fp["headers"]:
                        print(f"      {h}: {fp['headers'][h]}")
            print()

        # Show only pages that resolve correctly (200 OK status)
        successful_pages = [res for res in results if res["status"] == 200 and not res.get("is_redirect", False)]
        
        if successful_pages:
            print(f"  [+] Found {len(successful_pages)} accessible page(s):")
            for res in successful_pages:
                url = res["url"]
                title = res.get("title") or ""
                looks_like_login = res.get("looks_like_login", False)
                service = res.get("service")
                confidence = res.get("confidence")
                score = res.get("fingerprint_score")
                
                print(f"- {url}")
                print(f"  Status: 200 OK")
                
                if title:
                    print(f"  Title: {title}")
                
                if service:
                    print(f"  Service: {service}")
                    print(f"  Confidence: {confidence}")
                    print(f"  Score: {score}")
                
                if looks_like_login:
                    print("  Type: Login/Auth page detected")
                
                # Show relevant headers
                for h in ["Server", "X-Powered-By", "Set-Cookie"]:
                    if h in res["headers"]:
                        print(f"  {h}: {res['headers'][h]}")
                print()
        else:
            print("  [!] No directly accessible admin/login pages found")

        # Only log successfully resolved pages (200 OK) to CSV if requested
        if csv_writer is not None:
            for res in results:
                if res["status"] == 200 and not res.get("is_redirect", False):
                    csv_writer.writerow([
                        res["base"],
                        res["path"],
                        res["url"],
                        res["status"],
                        res["reason"],
                        res.get("looks_like_login", False),
                        res.get("title", ""),
                        res.get("service", ""),
                        res.get("confidence", ""),
                        res.get("fingerprint_score", ""),
                        res.get("redirect_target", ""),
                        res.get("is_redirect", False),
                    ])

    if csv_file:
        csv_file.close()
        print(f"[+] Results written to {args.output}")

if __name__ == "__main__":
    # Disable SSL warnings for self-signed / mismatched certs during scanning
    requests.packages.urllib3.disable_warnings( # type: ignore
        requests.packages.urllib3.exceptions.InsecureRequestWarning # type: ignore
    )
    main()