# ip_x/cli.py

import argparse
import sys
import requests
import json
import dns.resolver
import dns.reversename # For reverse DNS lookups
import shodan
import censys.search
import socket # For basic port scanning
import ipaddress # For IP address validation
import re # For regex, useful for parsing headers
from urllib.parse import urlparse # For parsing URLs
from colorama import Fore, Style, init # For colored output

# Initialize Colorama for cross-platform compatibility and auto-reset
init(autoreset=True)

# --- Configuration ---
# Public DNS resolvers for diverse lookups
PUBLIC_DNS_RESOLVERS = [
    '8.8.8.8',  # Google
    '1.1.1.1',  # Cloudflare
    '9.9.9.9',  # Quad9
    '208.67.222.222', # OpenDNS
]

# Certificate Transparency Log endpoint
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# Common HTTP/S ports for active scanning
COMMON_WEB_PORTS = [80, 443, 8080, 8443]

# Known WAF/CDN signatures (headers, server banners, cookies etc.)
WAF_SIGNATURES = {
    'cloudflare': {
        'headers': ['Server: cloudflare', 'CF-RAY', 'cf-request-id', 'Cloudflare-CDN-ID', 'Accept-Encoding: gzip'],
        'cookies': ['__cfduid', '__cf_bm'],
        'html_keywords': ['cloudflare-nginx', 'DDoS protection by Cloudflare']
    },
    'incapsula': {
        'headers': ['X-CDN: Incapsula', 'X-Iinfo', 'Incapsula-debug', 'X-WAF-Proxy'],
        'cookies': ['incap_ses_', 'visid_incap_'],
        'html_keywords': ['Incapsula incident ID']
    },
    'sucuri': {
        'headers': ['X-Sucuri-ID', 'X-Sucuri-Cached', 'Server: Sucuri/Cloudproxy'],
        'html_keywords': ['Sucuri WebSite Firewall - Blocked']
    },
    'akamai': {
        'headers': ['X-Akamai-Transformed', 'Akamai-Request-ID', 'Server: AkamaiGHost'],
        'cookies': ['akamai_origin_cookie']
    },
    'amazon_cloudfront': {
        'headers': ['X-Amz-Cf-Id', 'X-Cache', 'Via: 1.1 cloudfront'],
        'html_keywords': ['CloudFront Request ID']
    },
    'google_cloud_cdn': {
        'headers': ['Via: 1.1 google', 'X-Goog-Fed-Proxy', 'Server: Google Frontend']
    },
    'azure_frontdoor': {
        'headers': ['X-Azure-Ref', 'X-Cache: CONFIG_MISS', 'x-fdid', 'x-ms-request-id']
    },
    'f5_bigip_asm': {
        'headers': ['X-Forwarded-For: ', 'X-Cnection: close'],
        'html_keywords': ['The requested URL was rejected. Please consult with your administrator.']
    },
    'wordfence': {
        'headers': ['X-Wordfence-Cache', 'X-WF-Internal-Error'],
        'html_keywords': ['WordPress Security by Wordfence']
    },
    'mod_security': {
        'headers': ['Server: Mod_Security', 'Server: Secure Entry Point'],
        'html_keywords': ['Mod_Security', 'WAF Blocked', 'attack detected']
    },
    'barracuda_waf': {
        'headers': ['X-Barracuda-Appreciation-Id', 'X-Powered-By-Barracuda']
    },
    'dotdefender': {
        'headers': ['X-dotDefender-denied']
    },
    'reblaze': {
        'headers': ['X-Reblaze-ID']
    },
    'netscaler': {
        'headers': ['X-Citrix-NSC', 'X-NS-Request-ID', 'Set-Cookie: NSC_'],
        'cookies': ['NSC_']
    },
    'palo_alto_networks_waf': {
        'headers': ['x-paloalto-waf']
    },
    'imperva_incapsula': {
        'headers': ['X-Imperva', 'X-Protect', 'Set-Cookie: incap_ses_']
    },
    'distil_networks': {
        'headers': ['X-Distil-CS']
    },
    'radware_appwall': {
        'headers': ['X-WAF-Perf']
    },
    'openresty_waf': {
        'headers': ['Server: openresty']
    },
    'cdn77': {
        'headers': ['Server: CDN77-Turbo', 'X-CDN77-Cache']
    },
    'fastly': {
        'headers': ['X-Served-By', 'X-Cache: HIT', 'Fastly-Request-ID']
    },
    'maxcdn': {
        'headers': ['X-Cdn: MaxCDN']
    }
}

# Subdomain Enumeration Sources - (Note: Many public APIs have rate limits or require API keys for extensive use.)
SUBDOMAIN_SOURCES = {
    'virustotal': "https://www.virustotal.com/api/v3/domains/{domain}/subdomains", # Requires VT API key
    'crtsh_subdomains': "https://crt.sh/?q=%25.{domain}&output=json", # Already used for IPs, but good for subdomains too
    'threatcrowd': "https://threatcrowd.org/searchLb.php?domain={domain}", # Basic, often rate-limited/unreliable
}


# --- Color Helper Function ---
def print_colored(message, color=Fore.WHITE, prefix_color=Fore.BLUE, prefix="[*]"):
    """Prints a message with custom colors."""
    print(f"{prefix_color}{prefix}{Style.RESET_ALL} {color}{message}{Style.RESET_ALL}")

# --- Helper Functions (Existing) ---

def is_valid_ip(ip_string):
    """Checks if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def get_dns_records(target_domain, record_type, verbose=False):
    """
    Retrieves DNS records for a given domain and record type.
    """
    records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = PUBLIC_DNS_RESOLVERS
        answers = resolver.resolve(target_domain, record_type)
        for rdata in answers:
            record_str = str(rdata)
            records.append(record_str)
            if verbose:
                print_colored(f"  [DNS-{record_type}] Found record: {record_str}", Fore.CYAN, prefix="  ")
    except dns.resolver.NoAnswer:
        if verbose: print_colored(f"  [DNS-{record_type}] No {record_type} records found for {target_domain}.", Fore.YELLOW, prefix="  ")
    except dns.resolver.NXDOMAIN:
        if verbose: print_colored(f"  [DNS-{record_type}] Domain {target_domain} does not exist.", Fore.RED, prefix="  ")
    except Exception as e:
        if verbose: print_colored(f"  [DNS-{record_type}] Error querying {record_type} records: {e}", Fore.RED, prefix="  ")
    return records

def get_crt_sh_data(target_domain, verbose=False):
    """
    Queries crt.sh for historical IPs and subdomains from Certificate Transparency logs.
    Returns (list of IPs, list of subdomains)
    """
    ips = set()
    subdomains = set()
    url = CRT_SH_URL.format(domain=target_domain)
    if verbose: print_colored(f"  [CRT.sh] Querying: {url}", Fore.LIGHTBLACK_EX, prefix="  ")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = json.loads(response.text)

        for entry in data:
            if 'ip_addresses' in entry:
                for ip_addr in entry['ip_addresses'].split(', '):
                    if is_valid_ip(ip_addr.strip()):
                        ips.add(ip_addr.strip())
                        if verbose: print_colored(f"  [CRT.sh] Found IP from entry: {ip_addr.strip()}", Fore.CYAN, prefix="  ")
            
            if 'common_name' in entry:
                cn = entry['common_name'].lower()
                if cn.endswith(f".{target_domain}") or cn == target_domain:
                    subdomains.add(cn)
                    if verbose: print_colored(f"  [CRT.sh] Found subdomain (CN): {cn}", Fore.CYAN, prefix="  ")
            if 'name_value' in entry:
                for name in entry['name_value'].split('\n'):
                    name = name.strip().lower()
                    if name.startswith('*.'):
                        name = name[2:]
                    if name.endswith(f".{target_domain}") or name == target_domain:
                        subdomains.add(name)
                        if verbose: print_colored(f"  [CRT.sh] Found subdomain (Name Value): {name}", Fore.CYAN, prefix="  ")

    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [CRT.sh] Error querying crt.sh: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [CRT.sh] Error decoding crt.sh JSON response: {e}", Fore.RED, prefix="  ")
    except Exception as e:
        if verbose: print_colored(f"  [CRT.sh] An unexpected error occurred with crt.sh: {e}", Fore.RED, prefix="  ")
    
    if target_domain in subdomains:
        subdomains.remove(target_domain)

    return list(ips), list(subdomains)


def detect_github_pages(target_domain, verbose=False):
    """
    Detects if the target domain or its subdomains are hosted on GitHub Pages.
    """
    github_presence = False
    github_ips = set()

    if verbose: print_colored(f"  [GitHub Detector] Checking for GitHub Pages via CNAME records for {target_domain}...", Fore.LIGHTBLACK_EX, prefix="  ")

    cname_records = get_dns_records(target_domain, 'CNAME', verbose)
    for cname in cname_records:
        if 'github.io' in cname:
            github_presence = True
            if verbose: print_colored(f"  [GitHub Detector] Found CNAME pointing to GitHub Pages: {cname}", Fore.GREEN, prefix="  ")
            github_io_ips = get_dns_records(cname, 'A', verbose)
            github_ips.update(github_io_ips)

    return github_presence, list(github_ips)

def query_shodan_for_domain(target_domain, shodan_api_key, verbose=False):
    """
    Queries Shodan for historical IP information related to the target domain.
    """
    ips = set()
    if not shodan_api_key:
        if verbose: print_colored("  [Shodan] Shodan API key not provided. Skipping Shodan query.", Fore.YELLOW, prefix="  ")
        return []

    try:
        api = shodan.Shodan(shodan_api_key)
        if verbose: print_colored(f"  [Shodan] Querying Shodan for domain: {target_domain}", Fore.LIGHTBLACK_EX, prefix="  ")

        results = api.search(f"hostname:{target_domain}")

        for result in results['matches']:
            ip_str = result['ip_str']
            if is_valid_ip(ip_str):
                ips.add(ip_str)
                if verbose:
                    print_colored(f"  [Shodan] Found IP: {ip_str} (Port: {result.get('port')}, Org: {result.get('org')})", Fore.CYAN, prefix="  ")

    except shodan.APIError as e:
        if "No information available for that search query" in str(e):
            if verbose: print_colored(f"  [Shodan] No results found for {target_domain} on Shodan.", Fore.YELLOW, prefix="  ")
        elif "Invalid API key" in str(e):
            print_colored(f"  [Shodan] Error: Invalid Shodan API key.", Fore.RED, prefix="  ")
        else:
            print_colored(f"  [Shodan] Shodan API Error: {e}", Fore.RED, prefix="  ")
    except Exception as e:
        print_colored(f"  [Shodan] An unexpected error occurred while querying Shodan: {e}", Fore.RED, prefix="  ")
    return list(ips)

def query_censys_for_domain(target_domain, censys_api_id, censys_api_secret, verbose=False):
    """
    Queries Censys for historical IP information related to the target domain.
    """
    ips = set()
    if not censys_api_id or not censys_api_secret:
        if verbose: print_colored("  [Censys] Censys API ID or Secret not provided. Skipping Censys query.", Fore.YELLOW, prefix="  ")
        return []

    try:
        c = censys.search.CensysSearch(api_id=censys_api_id, api_secret=censys_api_secret)

        if verbose: print_colored(f"  [Censys] Querying Censys for hosts related to domain: {target_domain}", Fore.LIGHTBLACK_EX, prefix="  ")

        query = f"services.dns.names: {target_domain} OR p443.certificates.leaf.subject.common_name: {target_domain} OR p443.certificates.leaf.subject_alt_names: {target_domain}"

        for result in c.v2.hosts.search(query, fields=['ip'], per_page=50, pages=-1):
            ip_addr = result['ip']
            if is_valid_ip(ip_addr):
                ips.add(ip_addr)
                if verbose: print_colored(f"  [Censys] Found IP: {ip_addr}", Fore.CYAN, prefix="  ")

    except censys.base.CensysException as e:
        if "Authentication failed" in str(e):
            print_colored(f"  [Censys] Error: Censys Authentication failed. Check your API ID and Secret.", Fore.RED, prefix="  ")
        elif "No results found" in str(e) or "query returned no results" in str(e):
             if verbose: print_colored(f"  [Censys] No results found for {target_domain} on Censys.", Fore.YELLOW, prefix="  ")
        else:
            print_colored(f"  [Censys] Censys API Error: {e}", Fore.RED, prefix="  ")
    except Exception as e:
        print_colored(f"  [Censys] An unexpected error occurred while querying Censys: {e}", Fore.RED, prefix="  ")
    return list(ips)

def extract_ips_from_email_header(raw_email_headers, verbose=False):
    """
    Parses raw email headers (typically 'Received:' lines) to extract IP addresses.
    """
    ips = set()
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_pattern_v6 = r'\b(?:[0-9a-fA-F:]{2,})?\[?([0-9a-fA-F:]+)\]?(?:[0-9a-fA-F:]{2,})?\b'
    
    lines = raw_email_headers.splitlines()
    for line in lines:
        if line.lower().startswith('received:'):
            found_ipv4s = re.findall(ip_pattern, line)
            for ip_addr in found_ipv4s:
                if is_valid_ip(ip_addr) and not (ip_addr.startswith(('10.', '172.16.', '192.168.')) or ip_addr == '127.0.0.1'):
                    ips.add(ip_addr)
                    if verbose: print_colored(f"  [Email Header] Found public IPv4 in '{line.strip()[:60]}...': {ip_addr}", Fore.CYAN, prefix="  ")
            
            found_ipv6s = re.findall(ip_pattern_v6, line)
            for potential_ip in found_ipv6s:
                if is_valid_ip(potential_ip):
                    ips.add(potential_ip)
                    if verbose: print_colored(f"  [Email Header] Found public IPv6 in '{line.strip()[:60]}...': {potential_ip}", Fore.CYAN, prefix="  ")
    
    return list(ips)

def perform_reverse_dns(ip_address, verbose=False):
    """
    Performs a reverse DNS lookup on an IP address to find associated hostnames.
    """
    hostnames = set()
    if not is_valid_ip(ip_address):
        if verbose: print_colored(f"  [Reverse DNS] Skipping invalid IP for reverse lookup: {ip_address}", Fore.YELLOW, prefix="  ")
        return []

    try:
        addr = dns.reversename.from_address(ip_address)
        resolver = dns.resolver.Resolver()
        resolver.nameservers = PUBLIC_DNS_RESOLVERS
        answers = resolver.resolve(addr, "PTR")
        for rdata in answers:
            hostname = str(rdata).rstrip('.')
            hostnames.add(hostname)
            if verbose: print_colored(f"  [Reverse DNS] PTR record for {ip_address}: {hostname}", Fore.CYAN, prefix="  ")
    except dns.resolver.NXDOMAIN:
        if verbose: print_colored(f"  [Reverse DNS] No PTR record (NXDOMAIN) for {ip_address}.", Fore.YELLOW, prefix="  ")
    except dns.resolver.NoAnswer:
        if verbose: print_colored(f"  [Reverse DNS] No PTR answer for {ip_address}.", Fore.YELLOW, prefix="  ")
    except Exception as e:
        if verbose: print_colored(f"  [Reverse DNS] Error performing reverse DNS for {ip_address}: {e}", Fore.RED, prefix="  ")
    return list(hostnames)


# --- Subdomain Discovery Function ---
def find_subdomains_from_sources(target_domain, api_keys, verbose=False):
    """
    Queries various online sources for subdomains of the target domain.
    """
    found_subdomains = set()
    
    # 1. crt.sh
    if verbose: print_colored(f"\n  [Subdomain] Extracting subdomains from crt.sh data...", Fore.LIGHTBLACK_EX, prefix="  ")
    _, crt_subdomains = get_crt_sh_data(target_domain, verbose)
    found_subdomains.update(crt_subdomains)

    # 2. VirusTotal (requires API key)
    if 'virustotal_api_key' in api_keys and api_keys['virustotal_api_key']:
        vt_url = SUBDOMAIN_SOURCES['virustotal'].format(domain=target_domain)
        headers = {'x-apikey': api_keys['virustotal_api_key']}
        if verbose: print_colored(f"  [Subdomain-VT] Querying VirusTotal for subdomains: {vt_url}", Fore.LIGHTBLACK_EX, prefix="  ")
        try:
            response = requests.get(vt_url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            if 'data' in data:
                for entry in data['data']:
                    if 'id' in entry and entry['type'] == 'subdomain':
                        subdomain_name = entry['id'].lower()
                        if subdomain_name.endswith(f".{target_domain}"):
                            found_subdomains.add(subdomain_name)
                            if verbose: print_colored(f"    [Subdomain-VT] Found: {subdomain_name}", Fore.CYAN, prefix="    ")
        except requests.exceptions.RequestException as e:
            if verbose: print_colored(f"  [Subdomain-VT] Error querying VirusTotal: {e}", Fore.RED, prefix="  ")
        except json.JSONDecodeError as e:
            if verbose: print_colored(f"  [Subdomain-VT] Error decoding VirusTotal JSON: {e}", Fore.RED, prefix="  ")
    elif verbose:
        print_colored("  [Subdomain-VT] VirusTotal API key not provided or empty. Skipping.", Fore.YELLOW, prefix="  ")

    # 3. ThreatCrowd (often unreliable/rate-limited for automation, but can be a source)
    if verbose: print_colored(f"  [Subdomain-TC] Querying ThreatCrowd for subdomains...", Fore.LIGHTBLACK_EX, prefix="  ")
    tc_url = SUBDOMAIN_SOURCES['threatcrowd'].format(domain=target_domain)
    try:
        response = requests.get(tc_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if 'subdomains' in data:
            for sd in data['subdomains']:
                subdomain_name = sd.lower().strip()
                if subdomain_name.endswith(f".{target_domain}"):
                    found_subdomains.add(subdomain_name)
                    if verbose: print_colored(f"    [Subdomain-TC] Found: {subdomain_name}", Fore.CYAN, prefix="    ")
    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [Subdomain-TC] Error querying ThreatCrowd: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [Subdomain-TC] Error decoding ThreatCrowd JSON: {e}", Fore.RED, prefix="  ")

    return sorted(list(found_subdomains))


# --- Active Mode and WAF Detection Functions ---

def detect_waf(response_headers, response_body, verbose=False):
    """
    Analyzes HTTP response headers and body to detect WAFs.
    Returns a list of detected WAFs.
    """
    detected_wafs = []
    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    response_body_lower = response_body.lower() if response_body else ""

    if verbose: print_colored("  [WAF Detector] Analyzing headers and body for WAF signatures...", Fore.MAGENTA, prefix="  ")

    for waf_name, signatures in WAF_SIGNATURES.items():
        # Check headers
        if 'headers' in signatures:
            for header_sig in signatures['headers']:
                if ': ' in header_sig:
                    key, value = header_sig.split(': ', 1)
                    if key.lower() in headers_lower and value.lower() in headers_lower[key.lower()]:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            if verbose: print_colored(f"    [WAF] Detected {waf_name} via header: '{header_sig}'", Fore.RED, prefix="    ")
                            break
                else:
                    if header_sig.lower() in headers_lower:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            if verbose: print_colored(f"    [WAF] Detected {waf_name} via header key presence: '{header_sig}'", Fore.RED, prefix="    ")
                            break

        # Check cookies
        if 'cookies' in signatures:
            set_cookie_header = headers_lower.get('set-cookie', '')
            for cookie_sig in signatures['cookies']:
                if cookie_sig.lower() in set_cookie_header:
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
                        if verbose: print_colored(f"    [WAF] Detected {waf_name} via cookie: '{cookie_sig}'", Fore.RED, prefix="    ")
                        break

        # Check HTML keywords in body (for blocking pages)
        if 'html_keywords' in signatures:
            for keyword in signatures['html_keywords']:
                if keyword.lower() in response_body_lower:
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
                        if verbose: print_colored(f"    [WAF] Detected {waf_name} via HTML keyword: '{keyword[:40]}...'", Fore.RED, prefix="    ")
                        break
    return sorted(list(set(detected_wafs)))

def check_port(ip, port, timeout=1):
    """
    Checks if a specific port is open on an IP address.
    Returns True if open, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except (socket.error, OverflowError):
        return False

def perform_active_scan(target_domain, potential_ips, verbose=False):
    """
    Performs active IP discovery and WAF detection by directly interacting with targets.
    """
    found_origin_ips = set()
    detected_wafs = set()
    print_colored("\n--- Starting Active Scan ---", Fore.BLUE, prefix="")

    if not potential_ips:
        if verbose: print_colored("[Active] No potential IPs from passive scan. Resolving target domain's current DNS.", Fore.YELLOW)
        current_a_records = get_dns_records(target_domain, 'A', verbose)
        potential_ips.extend(current_a_records)
        current_aaaa_records = get_dns_records(target_domain, 'AAAA', verbose)
        potential_ips.extend(current_aaaa_records)

    if not potential_ips:
        print_colored("[Active] No IPs to actively scan.", Fore.YELLOW)
        return [], []

    potential_ips = list(set(ip for ip in potential_ips if is_valid_ip(ip)))

    for ip in potential_ips:
        if not is_valid_ip(ip): continue

        print_colored(f"\n[*] Probing potential origin IP: {ip}", Fore.LIGHTBLUE_EX)

        open_ports = []
        for port in COMMON_WEB_PORTS:
            if verbose: print_colored(f"  [Active] Checking port {port} on {ip}...", Fore.LIGHTBLACK_EX, prefix="  ")
            if check_port(ip, port):
                open_ports.append(port)
                if verbose: print_colored(f"    [SUCCESS] Port {port} is open.", Fore.GREEN, prefix="    ")
            else:
                if verbose: print_colored(f"    [INFO] Port {port} is closed or filtered.", Fore.YELLOW, prefix="    ")

        if open_ports:
            print_colored(f"  [Active] Open web ports found on {ip}: {', '.join(map(str, open_ports))}", Fore.GREEN, prefix="  ")
        else:
            if verbose: print_colored(f"  [Active] No common web ports found open on {ip}.", Fore.YELLOW, prefix="  ")


        headers = {
            'Host': target_domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 IP.X-Scanner/0.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        schemes = ['https', 'http']

        for scheme in schemes:
            if open_ports and ((scheme == 'https' and 443 not in open_ports) and (scheme == 'http' and 80 not in open_ports)):
                if verbose: print_colored(f"  [Active] Skipping {scheme} to {ip} as common web ports were checked and not open.", Fore.YELLOW, prefix="  ")
                continue

            url = f"{scheme}://{ip}/"
            try:
                if verbose: print_colored(f"  [Active] Attempting direct {scheme} connection to {ip} with Host: {target_domain}", Fore.LIGHTBLACK_EX, prefix="  ")
                response = requests.get(url, headers=headers, timeout=7, allow_redirects=True, verify=False)

                content_match = target_domain in response.text or \
                                f"https://{target_domain}" in response.text or \
                                f"http://{target_domain}" in response.text
                status_ok = 200 <= response.status_code < 300

                if (content_match and status_ok) or response.status_code == 200:
                    print_colored(f"  [SUCCESS] Direct connection to {ip} ({scheme}) returned content for {target_domain} (Status: {response.status_code}).", Fore.GREEN, prefix="  ")
                    found_origin_ips.add(ip)
                else:
                    if verbose: print_colored(f"  [INFO] Direct connection to {ip} ({scheme}) did not return expected content. Status: {response.status_code}", Fore.YELLOW, prefix="  ")
                
                current_detected_wafs = detect_waf(response.headers, response.text, verbose)
                if current_detected_wafs:
                    # Print WAFs found on this specific IP with a distinct color (e.g., bright red for alert)
                    print_colored(f"    {Fore.RED}!!! WAF(s) Detected on {ip} ({scheme}): {', '.join(current_detected_wafs)} !!!{Style.RESET_ALL}", Fore.RED, prefix="    ")
                    detected_wafs.update(current_detected_wafs)
                elif verbose:
                    print_colored(f"    [WAF] No obvious WAF detected on {ip} ({scheme}).", Fore.LIGHTBLACK_EX, prefix="    ")

            except requests.exceptions.Timeout:
                if verbose: print_colored(f"  [Active] Timeout connecting to {ip} ({scheme}).", Fore.RED, prefix="  ")
            except requests.exceptions.TooManyRedirects:
                if verbose: print_colored(f"  [Active] Too many redirects from {ip} ({scheme}).", Fore.RED, prefix="  ")
            except requests.exceptions.ConnectionError:
                if verbose: print_colored(f"  [Active] Connection error to {ip} ({scheme}).", Fore.RED, prefix="  ")
            except requests.exceptions.RequestException as e:
                if verbose: print_colored(f"  [Active] An HTTP request error occurred to {ip} ({scheme}): {e}", Fore.RED, prefix="  ")
            except Exception as e:
                if verbose: print_colored(f"  [Active] An unexpected error during active scan on {ip} ({scheme}): {e}", Fore.RED, prefix="  ")

    print_colored("\n--- Active Scan Complete ---", Fore.BLUE, prefix="")
    return list(found_origin_ips), list(detected_wafs)

# --- Passive Scan Function (Includes all passive collection methods) ---
def passive_scan(target, verbose=False, api_keys=None):
    """
    Performs passive IP collection techniques.
    """
    found_ips = set()
    found_hostnames = set()
    found_subdomains = set()

    print_colored("\n--- Starting Passive Scan ---", Fore.BLUE, prefix="")

    print_colored(f"\n[*] Collecting A records for {target}...", Fore.WHITE)
    a_records = get_dns_records(target, 'A', verbose)
    found_ips.update(a_records)

    print_colored(f"\n[*] Collecting AAAA records for {target}...", Fore.WHITE)
    aaaa_records = get_dns_records(target, 'AAAA', verbose)
    found_ips.update(aaaa_records)

    print_colored(f"\n[*] Querying Certificate Transparency logs (crt.sh) for {target}...", Fore.WHITE)
    crt_sh_ips, crt_sh_subdomains = get_crt_sh_data(target, verbose)
    found_ips.update(crt_sh_ips)
    found_subdomains.update(crt_sh_subdomains)

    print_colored(f"\n[*] Detecting GitHub Pages presence for {target}...", Fore.WHITE)
    is_github_pages, github_page_ips = detect_github_pages(target, verbose)
    if is_github_pages:
        print_colored(f"  [SUCCESS] {target} appears to be hosted on GitHub Pages!", Fore.GREEN, prefix="  ")
        if github_page_ips:
            print_colored("  [INFO] IPs associated with GitHub Pages CNAME:", Fore.CYAN, prefix="  ")
            for ip in github_page_ips:
                print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
                found_ips.add(ip)
    else:
        print_colored(f"  [INFO] {target} does not appear to be directly hosted on GitHub Pages via CNAME.", Fore.YELLOW, prefix="  ")

    print_colored(f"\n[*] Querying Shodan for historical data related to {target}...", Fore.WHITE)
    shodan_api_key = api_keys.get('shodan_api_key') if api_keys else None
    shodan_ips = query_shodan_for_domain(target, shodan_api_key, verbose)
    if shodan_ips:
        print_colored(f"  [SUCCESS] Shodan found {len(shodan_ips)} potential IP(s).", Fore.GREEN, prefix="  ")
        for ip in shodan_ips:
            print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
            found_ips.add(ip)
    else:
        print_colored("  [INFO] Shodan did not return additional IPs or API key was missing/invalid.", Fore.YELLOW, prefix="  ")

    print_colored(f"\n[*] Querying Censys for historical data related to {target}...", Fore.WHITE)
    censys_api_id = api_keys.get('censys_api_id') if api_keys else None
    censys_api_secret = api_keys.get('censys_api_secret') if api_keys else None
    censys_ips = query_censys_for_domain(target, censys_api_id, censys_api_secret, verbose)
    if censys_ips:
        print_colored(f"  [SUCCESS] Censys found {len(censys_ips)} potential IP(s).", Fore.GREEN, prefix="  ")
        for ip in censys_ips:
            print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
            found_ips.add(ip)
    else:
        print_colored("  [INFO] Censys did not return additional IPs or API keys were missing/invalid.", Fore.YELLOW, prefix="  ")

    # --- New Passive Additions ---

    print_colored(f"\n[*] Enumerating subdomains from various sources for {target}...", Fore.WHITE)
    discovered_subdomains = find_subdomains_from_sources(target, api_keys, verbose)
    found_subdomains.update(discovered_subdomains)
    if found_subdomains:
        print_colored(f"  [SUCCESS] Subdomain enumeration found {len(found_subdomains)} subdomain(s).", Fore.GREEN, prefix="  ")
        for subdomain in found_subdomains:
            print_colored(f"    - {subdomain}", Fore.CYAN, prefix="    ")
            # Resolve IPs for discovered subdomains
            sub_a_records = get_dns_records(subdomain, 'A', verbose)
            found_ips.update(sub_a_records)
            sub_aaaa_records = get_dns_records(subdomain, 'AAAA', verbose)
            found_ips.update(sub_aaaa_records)
            if sub_a_records or sub_aaaa_records:
                if verbose: print_colored(f"      [Subdomain DNS] Resolved IPs for {subdomain}: {list(set(sub_a_records + sub_aaaa_records))}", Fore.LIGHTCYAN_EX, prefix="      ")
    else:
        print_colored("  [INFO] No additional subdomains found.", Fore.YELLOW, prefix="  ")


    print_colored(f"\n[*] Performing Reverse DNS lookups on collected IPs...", Fore.WHITE)
    current_found_ips_list = list(found_ips)
    for ip in current_found_ips_list:
        resolved_hostnames = perform_reverse_dns(ip, verbose)
        found_hostnames.update(resolved_hostnames)

    if found_hostnames:
        print_colored(f"  [INFO] Reverse DNS found {len(found_hostnames)} associated hostname(s):", Fore.CYAN, prefix="  ")
        for hostname in found_hostnames:
            print_colored(f"    - {hostname}", Fore.LIGHTCYAN_EX, prefix="    ")
    else:
        print_colored("  [INFO] No additional hostnames from reverse DNS.", Fore.YELLOW, prefix="  ")

    print_colored("\n--- Passive Scan Complete ---", Fore.BLUE, prefix="")
    return list(found_ips)


# --- Main function: orchestrates the scan ---

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}IP.X - An origin IP finder behind WAF and CDN, with WAF detection capabilities.{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "target",
        help="The target domain (e.g., example.com)."
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable active mode (performs direct connections, port scans, etc.)."
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Enable passive mode (collects data from public sources like DNS history, CT logs)."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output for detailed information during the scan."
    )
    parser.add_argument(
        "--output",
        type=str,
        metavar="FILE",
        help="Save the scan results to the specified file."
    )
    parser.add_argument(
        "--api_keys",
        type=str,
        metavar="FILE",
        help="Path to a file containing API keys (e.g., Shodan, Censys, VirusTotal) in JSON format.\n"
             "Example JSON content:\n"
             "{\n"
             "  \"shodan_api_key\": \"YOUR_SHODAN_API_KEY\",\n"
             "  \"censys_api_id\": \"YOUR_CENSYS_API_ID\",\n"
             "  \"censys_api_secret\": \"YOUR_CENSYS_API_SECRET\",\n"
             "  \"virustotal_api_key\": \"YOUR_VIRUSTOTAL_API_KEY\"\n"
             "}"
    )

    args = parser.parse_args()

    if not args.active and not args.passive:
        print_colored("Error: You must enable either --active or --passive mode (or both).", Fore.RED, prefix="[ERROR]")
        parser.print_help()
        sys.exit(1)

    api_keys = {}
    if args.api_keys:
        try:
            with open(args.api_keys, 'r') as f:
                api_keys = json.load(f)
            if args.verbose:
                print_colored(f"[*] Successfully loaded API keys from {args.api_keys}", Fore.GREEN)
        except FileNotFoundError:
            print_colored(f"Error: API keys file '{args.api_keys}' not found.", Fore.RED, prefix="[ERROR]")
            sys.exit(1)
        except json.JSONDecodeError:
            print_colored(f"Error: Invalid JSON format in API keys file '{args.api_keys}'.", Fore.RED, prefix="[ERROR]")
            sys.exit(1)

    print_colored(f"\n{Fore.LIGHTMAGENTA_EX}IP.X Scan Initiated for: {args.target}{Style.RESET_ALL}", Fore.WHITE, prefix="")
    print_colored(f"Active Mode: {Fore.GREEN if args.active else Fore.RED}{'Enabled' if args.active else 'Disabled'}", Fore.WHITE, prefix="  ")
    print_colored(f"Passive Mode: {Fore.GREEN if args.passive else Fore.RED}{'Enabled' if args.passive else 'Disabled'}", Fore.WHITE, prefix="  ")
    print_colored(f"Verbose Output: {Fore.GREEN if args.verbose else Fore.RED}{'Enabled' if args.verbose else 'Disabled'}", Fore.WHITE, prefix="  ")
    print_colored(f"Output File: {Fore.CYAN}{args.output if args.output else 'None'}", Fore.WHITE, prefix="  ")
    print_colored(f"API Keys File: {Fore.CYAN}{args.api_keys if args.api_keys else 'None'}", Fore.WHITE, prefix="  ")

    all_found_ips = set()
    detected_wafs_overall = set()

    if args.passive:
        passive_ips = passive_scan(args.target, args.verbose, api_keys)
        all_found_ips.update(passive_ips)
        print_colored(f"\nPassive scan found {len(passive_ips)} potential IP(s).", Fore.MAGENTA)
        for ip in passive_ips:
            print_colored(f"  - {ip}", Fore.CYAN, prefix="  ")

    if args.active:
        active_mode_found_ips, active_mode_detected_wafs = perform_active_scan(args.target, list(all_found_ips), args.verbose)
        all_found_ips.update(active_mode_found_ips)
        detected_wafs_overall.update(active_mode_detected_wafs)


    print_colored("\n--- Scan Complete ---", Fore.BLUE, prefix="")
    if all_found_ips:
        print_colored(f"\nTotal unique potential origin IP(s) found: {len(all_found_ips)}", Fore.LIGHTGREEN_EX)
        for ip in sorted(list(all_found_ips)):
            print_colored(f"  {Fore.GREEN}--> {ip}", Fore.GREEN, prefix="")
    else:
        print_colored("No potential origin IPs found.", Fore.YELLOW)

    if detected_wafs_overall:
        print_colored(f"\n{Fore.RED}!!! Detected WAF(s): {', '.join(sorted(list(detected_wafs_overall)))} !!!{Style.RESET_ALL}", Fore.RED, prefix="")
    else:
        print_colored("\nNo WAFs detected.", Fore.GREEN)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(f"IP.X Scan Results for: {args.target}\n")
                f.write(f"Active Mode: {'Enabled' if args.active else 'Disabled'}\n")
                f.write(f"Passive Mode: {'Enabled' if args.passive else 'Disabled'}\n")
                f.write(f"Verbose Output: {'Enabled' if args.verbose else 'Disabled'}\n")
                f.write("\n--- Potential Origin IPs ---\n")
                if all_found_ips:
                    for ip in sorted(list(all_found_ips)):
                        f.write(f"- {ip}\n")
                else:
                    f.write("No potential origin IPs found.\n")
                f.write("\n--- WAF Detection ---\n")
                if detected_wafs_overall:
                    f.write(f"Detected WAF(s): {', '.join(sorted(list(detected_wafs_overall)))}\n")
                else:
                    f.write("No WAFs detected.\n")
            print_colored(f"\nResults saved to: {args.output}", Fore.GREEN)
        except IOError as e:
            print_colored(f"Error: Could not write to output file '{args.output}': {e}", Fore.RED, prefix="[ERROR]")


if __name__ == "__main__":
    main()
