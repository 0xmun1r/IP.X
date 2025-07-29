# ip_x/cli.py

import argparse
import sys
import requests
import json
import dns.resolver
import dns.reversename # For reverse DNS lookups
import shodan
# Censys imports removed as per request
import socket # For basic port scanning
import ipaddress # For IP address validation
import re # For regex, useful for parsing headers
import os # For os.getcwd() to find api_keys.json automatically
from urllib.parse import urlparse # For parsing URLs
from colorama import Fore, Style, Back, init # For colored output
import urllib3 # To disable InsecureRequestWarning
import hashlib # For general hashing (though mmh3 is preferred for favicon)

# Try to import mmh3 for Shodan favicon hash. If not available, we'll note it.
try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

# Disable InsecureRequestWarning for direct IP connections (verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# API Base URLs for new integrations
SECURITYTRAILS_BASE_URL = "https://api.securitytrails.com/v1"
URLSCAN_IO_SEARCH_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}" # For passive historical lookups
IPINFO_API_URL = "https://ipinfo.io/{}/json" # For ASN and IP range lookup
WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx?url={}/&output=json&fl=original,urlkey,timestamp,statuscode,digest,length,mime_type,ip,redirect&filter=statuscode:200|301|302"
VIEWDNS_REVERSE_IP_URL = "https://api.viewdns.info/reverseip/?host={ip}&apikey={api_key}&output=json" # For Reverse IP lookup

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

SUBDOMAIN_SOURCES = {
    'virustotal': "https://www.virustotal.com/api/v3/domains/{domain}/subdomains", # Requires VT API key
    'crtsh_subdomains': "https://crt.sh/?q=%25.{domain}&output=json", # Already used for IPs, but good for subdomains too
    'threatcrowd': "https://threatcrowd.org/searchLb.php?domain={domain}", # Basic, often rate-limited/unreliable
}

# Common subdomains for brute-forcing (can be expanded from external wordlists)
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'dev', 'test', 'blog', 'api', 'admin', 'portal', 'webmail',
    'autodiscover', 'cpanel', 'vpn', 'docs', 'ns1', 'ns2', 'cloud', 'app', 'cdn',
    'secure', 'stage', 'beta', 'demo', 'status', 'forum', 'shop', 'store', 'media',
    'assets', 'files', 'support', 'wiki', 'crm', 'erp', 'hr', 'intranet', 'extranet',
    'jira', 'confluence', 'jenkins', 'gitlab', 'github', 'sso', 'login', 'register',
    'dashboard', 'control', 'manage', 'remote', 'gateway', 'proxy', 'monitor', 'metrics',
    'db', 'sql', 'mysql', 'postgres', 'redis', 'mongo', 'es', 'elastic', 'kafka',
    'uat', 'prod', 'staging', 'qa', 'live', 'development', 'acceptance', 'test',
    'backup', 'archive', 'old', 'new', 'vps', 'server', 'client', 'partner',
    'public', 'private', 'external', 'internal', 'service', 'services', 'data',
    'reports', 'graphs', 'stats', 'sys', 'system', 'logs', 'audit', 'monitor', 'nagios',
    'zabbix', 'grafana', 'kibana', 'splunk', 'rancher', 'kubernetes', 'kube',
    'prometheus', 'alertmanager', 'vault', 'consul', 'nomad', 'nexus', 'artifactory',
    'registry', 'harbor', 'docker', 'swarm', 'ci', 'cd', 'build', 'monitor',
    'download', 'downloads', 'dl', 'cdn', 'static', 'images', 'img', 'video', 'videos',
    'audio', 'voice', 'stream', 'streaming', 'cast', 'player', 'play', 'go', 'get',
    'join', 'meet', 'chat', 'talk', 'connect', 'community', 'groups', 'members',
    'news', 'events', 'calendar', 'directory', 'list', 'status', 'help', 'faq',
    'kb', 'knowledge', 'docs', 'manual', 'guide', 'tutorial', 'training', 'learn',
    'academy', 'university', 'campus', 'student', 'faculty', 'alumni', 'careers',
    'jobs', 'recruit', 'apply', 'candidates', 'onboarding', 'hris', 'pay', 'payroll',
    'expense', 'travel', 'crm', 'sales', 'marketing', 'support', 'tickets', 'helpdesk',
    'knowledgebase', 'supportcenter', 'adminpanel', 'controlpanel', 'webadmin',
    'management', 'central', 'securelogin', 'my', 'portal', 'extranet', 'intranet'
]


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
        # DNS queries can sometimes be slow; setting a timeout can prevent hangs
        resolver.timeout = 5
        resolver.lifetime = 5
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
    except dns.exception.Timeout:
        if verbose: print_colored(f"  [DNS-{record_type}] DNS query timed out for {target_domain}.", Fore.RED, prefix="  ")
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

def query_shodan_by_favicon(favicon_hash, shodan_api_key, verbose=False):
    """
    Queries Shodan for hosts with a matching favicon hash.
    """
    ips = set()
    if not shodan_api_key:
        if verbose: print_colored("  [Shodan-Favicon] Shodan API key not provided. Skipping Favicon query.", Fore.YELLOW, prefix="  ")
        return []

    if not HAS_MMH3:
        if verbose: print_colored("  [Shodan-Favicon] mmh3 library not found. Cannot perform Shodan favicon query.", Fore.YELLOW, prefix="  ")
        return []

    try:
        api = shodan.Shodan(shodan_api_key)
        query = f'http.favicon.hash:{favicon_hash}'
        if verbose: print_colored(f"  [Shodan-Favicon] Querying Shodan for favicon hash: {favicon_hash}", Fore.LIGHTBLACK_EX, prefix="  ")

        results = api.search(query)

        for result in results['matches']:
            ip_str = result['ip_str']
            if is_valid_ip(ip_str):
                ips.add(ip_str)
                if verbose:
                    print_colored(f"  [Shodan-Favicon] Found IP: {ip_str} (Favicon Match)", Fore.CYAN, prefix="  ")

    except shodan.APIError as e:
        if "No information available for that search query" in str(e):
            if verbose: print_colored(f"  [Shodan-Favicon] No results found for favicon hash {favicon_hash} on Shodan.", Fore.YELLOW, prefix="  ")
        elif "Invalid API key" in str(e):
            print_colored(f"  [Shodan-Favicon] Error: Invalid Shodan API key for Favicon query.", Fore.RED, prefix="  ")
        else:
            print_colored(f"  [Shodan-Favicon] Shodan API Error (Favicon): {e}", Fore.RED, prefix="  ")
    except Exception as e:
        print_colored(f"  [Shodan-Favicon] An unexpected error occurred while querying Shodan (Favicon): {e}", Fore.RED, prefix="  ")
    return list(ips)

def get_favicon_hash(target_domain, verbose=False):
    """
    Fetches the favicon of a domain and calculates its MurmurHash3 hash.
    Returns the hash as a string, or None if not found/error.
    """
    if not HAS_MMH3:
        if verbose: print_colored("  [Favicon] mmh3 library not found. Cannot calculate Shodan-compatible favicon hash. Please install with 'pip install mmh3'.", Fore.YELLOW, prefix="  ")
        return None

    favicon_url = f"http://{target_domain}/favicon.ico"
    try:
        if verbose: print_colored(f"  [Favicon] Attempting to fetch favicon from: {favicon_url}", Fore.LIGHTBLACK_EX, prefix="  ")
        response = requests.get(favicon_url, timeout=5, verify=False)
        response.raise_for_status()

        if response.status_code == 200 and 'image' in response.headers.get('Content-Type', ''):
            favicon_hash = mmh3.hash(response.content) # Use mmh3
            if verbose: print_colored(f"  [Favicon] Found and hashed favicon: {favicon_hash}", Fore.CYAN, prefix="  ")
            return str(favicon_hash) # mmh3 returns int, convert to string
        else:
            if verbose: print_colored(f"  [Favicon] Favicon not found at {favicon_url} or not an image (Status: {response.status_code}).", Fore.YELLOW, prefix="  ")
            return None
    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [Favicon] Error fetching favicon: {e}", Fore.RED, prefix="  ")
        return None
    except Exception as e:
        if verbose: print_colored(f"  [Favicon] An unexpected error occurred with favicon: {e}", Fore.RED, prefix="  ")
    return None


def query_securitytrails(target_domain, securitytrails_api_key, verbose=False):
    """
    Queries SecurityTrails for historical DNS, subdomains, and associated IPs.
    Returns (list of IPs, list of subdomains)
    """
    ips = set()
    subdomains = set()

    if not securitytrails_api_key:
        if verbose: print_colored("  [SecurityTrails] API key not provided. Skipping SecurityTrails query.", Fore.YELLOW, prefix="  ")
        return [], []

    headers = {
        "APIKEY": securitytrails_api_key,
        "Accept": "application/json"
    }

    if verbose: print_colored(f"  [SecurityTrails] Querying for subdomains and historical DNS for {target_domain}...", Fore.LIGHTBLACK_EX, prefix="  ")

    # --- Get Subdomains ---
    subdomain_url = f"{SECURITYTRAILS_BASE_URL}/domain/{target_domain}/subdomains"
    try:
        response = requests.get(subdomain_url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        if 'subdomains' in data:
            for sd in data['subdomains']:
                full_subdomain = f"{sd}.{target_domain}".lower()
                subdomains.add(full_subdomain)
                if verbose: print_colored(f"    [SecurityTrails] Found subdomain: {full_subdomain}", Fore.CYAN, prefix="    ")
    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [SecurityTrails] Error querying subdomains: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [SecurityTrails] Error decoding subdomain JSON: {e}", Fore.RED, prefix="  ")

    # --- Get Historical DNS (A records) ---
    history_url = f"{SECURITYTRAILS_BASE_URL}/history/{target_domain}/dns/a"
    try:
        response = requests.get(history_url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        if 'records' in data:
            for record_entry in data['records']:
                for ip_record in record_entry.get('values', []):
                    ip_addr = ip_record.get('ip')
                    if ip_addr and is_valid_ip(ip_addr):
                        ips.add(ip_addr)
                        if verbose: print_colored(f"    [SecurityTrails] Found historical IP: {ip_addr}", Fore.CYAN, prefix="    ")
    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [SecurityTrails] Error querying historical DNS: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [SecurityTrails] Error decoding historical DNS JSON: {e}", Fore.RED, prefix="  ")

    return list(ips), list(subdomains)

def query_urlscan_io(target_domain, verbose=False):
    """
    Queries URLScan.io for passive IP and WAF detection from historical scans.
    Returns (list of IPs, list of detected WAFs from headers)
    """
    ips = set()
    wafs_from_urlscan = set()

    if verbose: print_colored(f"  [URLScan.io] Querying URLScan.io for historical scans of {target_domain}...", Fore.LIGHTBLACK_EX, prefix="  ")

    url = URLSCAN_IO_SEARCH_URL.format(domain=target_domain)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = json.loads(response.text)

        if 'results' in data:
            for result in data['results']:
                if 'page' in result and 'url' in result['page'] and target_domain in result['page']['url']:
                    # Extract IP
                    if 'ip' in result['page'] and is_valid_ip(result['page']['ip']):
                        ips.add(result['page']['ip'])
                        if verbose: print_colored(f"    [URLScan.io] Found IP: {result['page']['ip']}", Fore.CYAN, prefix="    ")
                    
                    # Extract and check headers (simplified for initial integration)
                    if 'dom' in result and 'server' in result['dom']:
                        simplified_headers = {'Server': result['dom']['server']}
                        current_detected_wafs = detect_waf(simplified_headers, "", verbose=False) # Don't be verbose here to avoid double-printing
                        wafs_from_urlscan.update(current_detected_wafs)


    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [URLScan.io] Error querying URLScan.io: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [URLScan.io] Error decoding URLScan.io JSON: {e}", Fore.RED, prefix="  ")
    except Exception as e:
        if verbose: print_colored(f"  [URLScan.io] An unexpected error occurred with URLScan.io: {e}", Fore.RED, prefix="  ")

    return list(ips), list(wafs_from_urlscan)

def get_asn_ips(ip_address, ipinfo_api_key=None, verbose=False):
    """
    Queries ipinfo.io for ASN and associated IP ranges.
    Returns a list of IPs from the ASN.
    """
    ips_from_asn = set()
    if not is_valid_ip(ip_address):
        if verbose: print_colored(f"  [ASN] Skipping invalid IP for ASN lookup: {ip_address}", Fore.YELLOW, prefix="  ")
        return []
    
    headers = {}
    if ipinfo_api_key:
        headers["Authorization"] = f"Bearer {ipinfo_api_key}"

    try:
        # Get ASN for the given IP
        ip_details_url = IPINFO_API_URL.format(ip_address)
        if verbose: print_colored(f"  [ASN] Querying ipinfo.io for IP details: {ip_details_url}", Fore.LIGHTBLACK_EX, prefix="  ")
        response = requests.get(ip_details_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        if 'asn' in data and data['asn']:
            asn_id = data['asn']
            if verbose: print_colored(f"    [ASN] Found ASN for {ip_address}: {asn_id}", Fore.CYAN, prefix="    ")

            # Query for all prefixes (IP ranges) associated with this ASN
            asn_details_url = IPINFO_API_URL.format(asn_id)
            if verbose: print_colored(f"  [ASN] Querying ipinfo.io for ASN prefixes: {asn_details_url}", Fore.LIGHTBLACK_EX, prefix="  ")
            response = requests.get(asn_details_url, headers=headers, timeout=10)
            response.raise_for_status()
            asn_data = response.json()

            if 'prefixes' in asn_data:
                for prefix_entry in asn_data['prefixes']:
                    cidr = prefix_entry.get('cidr')
                    if cidr:
                        try:
                            network = ipaddress.ip_network(cidr, strict=False)
                            # Add the network address itself
                            ips_from_asn.add(str(network.network_address))
                            # For larger networks, add a few more for variety without being too aggressive
                            if network.num_addresses > 1 and network.num_addresses < 256: # Limit enumeration for smaller networks
                                for i, host in enumerate(network.hosts()):
                                    if i >= 3: break # Add first 3 hosts
                                    ips_from_asn.add(str(host))
                            
                            if verbose: print_colored(f"      [ASN] Found prefix: {cidr}", Fore.CYAN, prefix="      ")
                        except ValueError:
                            if verbose: print_colored(f"      [ASN] Invalid CIDR format: {cidr}", Fore.YELLOW, prefix="      ")
            elif verbose:
                print_colored(f"    [ASN] No prefixes found for ASN {asn_id}.", Fore.YELLOW, prefix="    ")
        elif verbose:
            print_colored(f"    [ASN] No ASN found for IP {ip_address}.", Fore.YELLOW, prefix="    ")

    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [ASN] Error querying ipinfo.io: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [ASN] Error decoding ipinfo.io JSON response: {e}", Fore.RED, prefix="  ")
    except Exception as e:
        if verbose: print_colored(f"  [ASN] An unexpected error occurred with ASN lookup: {e}", Fore.RED, prefix="  ")
    
    return list(ips_from_asn)

def query_wayback_machine(target_domain, verbose=False):
    """
    Queries Wayback Machine (Archive.org) for historical IPs.
    Returns a list of IPs.
    """
    ips = set()
    url = WAYBACK_CDX_URL.format(target_domain)
    if verbose: print_colored(f"  [Wayback] Querying Wayback Machine: {url}", Fore.LIGHTBLACK_EX, prefix="  ")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        # The CDX API returns a list of lists (CSV-like JSON)
        data = json.loads(response.text)

        # The first element is typically headers, skip it
        if data and len(data) > 1:
            headers = data[0]
            ip_index = headers.index('ip') if 'ip' in headers else -1

            for entry in data[1:]: # Iterate from the second element (actual data)
                if ip_index != -1 and len(entry) > ip_index:
                    ip_addr = entry[ip_index]
                    if ip_addr and is_valid_ip(ip_addr):
                        ips.add(ip_addr)
                        if verbose: print_colored(f"    [Wayback] Found historical IP: {ip_addr}", Fore.CYAN, prefix="    ")

    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [Wayback] Error querying Wayback Machine: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [Wayback] Error decoding Wayback Machine JSON response: {e}", Fore.RED, prefix="  ")
    except Exception as e:
        if verbose: print_colored(f"  [Wayback] An unexpected error occurred with Wayback Machine: {e}", Fore.RED, prefix="  ")
    
    return list(ips)

def query_reverse_ip_viewdns(ip_address, viewdns_api_key, verbose=False):
    """
    Queries ViewDNS.info for other domains hosted on the same IP.
    Returns a list of domains.
    """
    domains = set()
    if not viewdns_api_key:
        if verbose: print_colored("  [ReverseIP] ViewDNS.info API key not provided. Skipping Reverse IP lookup.", Fore.YELLOW, prefix="  ")
        return []

    url = VIEWDNS_REVERSE_IP_URL.format(ip=ip_address, api_key=viewdns_api_key)
    if verbose: print_colored(f"  [ReverseIP] Querying ViewDNS.info for reverse IP: {ip_address}...", Fore.LIGHTBLACK_EX, prefix="  ")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = json.loads(response.text)

        if 'response' in data and 'domains' in data['response']:
            for entry in data['response']['domains']:
                domain_name = entry.get('name')
                if domain_name:
                    domains.add(domain_name)
                    if verbose: print_colored(f"    [ReverseIP] Found domain on {ip_address}: {domain_name}", Fore.CYAN, prefix="    ")
        elif 'response' in data and 'error' in data['response']:
            if verbose: print_colored(f"  [ReverseIP] Error from ViewDNS.info for {ip_address}: {data['response']['error']}", Fore.RED, prefix="  ")
        else:
            if verbose: print_colored(f"  [ReverseIP] No domains found for {ip_address} via ViewDNS.info.", Fore.YELLOW, prefix="  ")

    except requests.exceptions.RequestException as e:
        if verbose: print_colored(f"  [ReverseIP] Error querying ViewDNS.info: {e}", Fore.RED, prefix="  ")
    except json.JSONDecodeError as e:
        if verbose: print_colored(f"  [ReverseIP] Error decoding ViewDNS.info JSON: {e}", Fore.RED, prefix="  ")
    except Exception as e:
        if verbose: print_colored(f"  [ReverseIP] An unexpected error occurred with Reverse IP: {e}", Fore.RED, prefix="  ")
    return list(domains)


def bruteforce_subdomains(target_domain, verbose=False):
    """
    Performs basic subdomain brute-forcing using a common wordlist.
    """
    found_subdomains = set()
    if verbose: print_colored(f"\n  [Subdomain Brute-Force] Starting brute-force for {target_domain}...", Fore.LIGHTBLACK_EX, prefix="  ")

    for subdomain_prefix in COMMON_SUBDOMAINS:
        test_subdomain = f"{subdomain_prefix}.{target_domain}"
        # Skip verbose DNS messages for each brute-force attempt, unless overall verbose is on
        a_records = get_dns_records(test_subdomain, 'A', verbose=False)
        aaaa_records = get_dns_records(test_subdomain, 'AAAA', verbose=False)

        if a_records or aaaa_records:
            found_subdomains.add(test_subdomain)
            if verbose: print_colored(f"      [Subdomain Brute-Force] Found: {test_subdomain} -> IPs: {list(set(a_records + aaaa_records))}", Fore.CYAN, prefix="      ")
    
    if verbose and not found_subdomains:
        print_colored("  [Subdomain Brute-Force] No new subdomains found via brute-force with common list.", Fore.YELLOW, prefix="  ")

    return list(found_subdomains)


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
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(addr, "PTR")
        for rdata in answers:
            hostname = str(rdata).rstrip('.')
            hostnames.add(hostname)
            if verbose: print_colored(f"  [Reverse DNS] PTR record for {ip_address}: {hostname}", Fore.CYAN, prefix="  ")
    except dns.resolver.NXDOMAIN:
        if verbose: print_colored(f"  [Reverse DNS] No PTR record (NXDOMAIN) for {ip_address}.", Fore.YELLOW, prefix="  ")
    except dns.resolver.NoAnswer:
        if verbose: print_colored(f"  [Reverse DNS] No PTR answer for {ip_address}.", Fore.YELLOW, prefix="  ")
    except dns.exception.Timeout:
        if verbose: print_colored(f"  [Reverse DNS] Reverse DNS query timed out for {ip_address}.", Fore.RED, prefix="  ")
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
            data = json.loads(response.text)
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
    
    # 4. SecurityTrails for subdomains (added via its function call)
    securitytrails_api_key = api_keys.get('securitytrails_api_key') if api_keys else None
    if securitytrails_api_key:
        _, st_subdomains = query_securitytrails(target_domain, securitytrails_api_key, verbose)
        found_subdomains.update(st_subdomains)
    elif verbose:
        print_colored("  [Subdomain-ST] SecurityTrails API key not provided or empty. Skipping subdomain query.", Fore.YELLOW, prefix="  ")
    
    # 5. Subdomain Brute-Force (using COMMON_SUBDOMAINS list)
    brute_force_subdomains = bruteforce_subdomains(target_domain, verbose)
    found_subdomains.update(brute_force_subdomains)

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
                # Suppress InsecureRequestWarning for self-signed certs or cert mismatches during direct IP connection
                with requests.Session() as s:
                    s.verify = False # Do not verify SSL certs for direct IP connections
                    response = s.get(url, headers=headers, timeout=7, allow_redirects=True)


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
                    print_colored(f"    {Fore.LIGHTRED_EX}{Style.BRIGHT}!!! WAF(s) Detected on {ip} ({scheme}): {', '.join(current_detected_wafs)} !!!{Style.RESET_ALL}", Fore.LIGHTRED_RED, prefix="    ")
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
    detected_wafs_passive = set() # To collect WAFs found during passive (e.g., from URLScan.io)

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
    
    # Censys section removed from here

    # --- NEW: SecurityTrails Integration ---
    print_colored(f"\n[*] Querying SecurityTrails for historical data related to {target}...", Fore.WHITE)
    securitytrails_api_key = api_keys.get('securitytrails_api_key') if api_keys else None
    st_ips, st_subdomains = query_securitytrails(target, securitytrails_api_key, verbose)
    if st_ips:
        print_colored(f"  [SUCCESS] SecurityTrails found {len(st_ips)} potential IP(s).", Fore.GREEN, prefix="  ")
        for ip in st_ips:
            print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
            found_ips.add(ip)
    if st_subdomains:
        print_colored(f"  [SUCCESS] SecurityTrails found {len(st_subdomains)} subdomain(s).", Fore.GREEN, prefix="  ")
        found_subdomains.update(st_subdomains) # Add to general subdomains list
    else:
        print_colored("  [INFO] SecurityTrails did not return additional IPs/subdomains or API key was missing/invalid.", Fore.YELLOW, prefix="  ")

    # --- NEW: URLScan.io Integration (Passive) ---
    print_colored(f"\n[*] Querying URLScan.io for passive IP data...", Fore.WHITE)
    urlscan_ips, urlscan_wafs = query_urlscan_io(target, verbose)
    if urlscan_ips:
        print_colored(f"  [SUCCESS] URLScan.io found {len(urlscan_ips)} potential IP(s).", Fore.GREEN, prefix="  ")
        for ip in urlscan_ips:
            print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
            found_ips.add(ip)
    else:
        print_colored("  [INFO] URLScan.io did not return additional IPs.", Fore.YELLOW, prefix="  ")
    if urlscan_wafs:
        print_colored(f"  [SUCCESS] URLScan.io found {len(urlscan_wafs)} WAF(s) signatures.", Fore.MAGENTA, prefix="  ")
        detected_wafs_passive.update(urlscan_wafs)

    # --- NEW: Wayback Machine Integration ---
    print_colored(f"\n[*] Querying Wayback Machine for historical IPs...", Fore.WHITE)
    wayback_ips = query_wayback_machine(target, verbose)
    if wayback_ips:
        print_colored(f"  [SUCCESS] Wayback Machine found {len(wayback_ips)} potential IP(s).", Fore.GREEN, prefix="  ")
        for ip in wayback_ips:
            print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
            found_ips.add(ip)
    else:
        print_colored("  [INFO] Wayback Machine did not return additional IPs.", Fore.YELLOW, prefix="  ")

    # --- NEW: Favicon Hashing with Shodan ---
    shodan_api_key = api_keys.get('shodan_api_key') if api_keys else None
    if shodan_api_key:
        favicon_hash_val = get_favicon_hash(target, verbose)
        if favicon_hash_val:
            print_colored(f"\n[*] Querying Shodan for IPs with matching favicon hash...", Fore.WHITE)
            shodan_favicon_ips = query_shodan_by_favicon(favicon_hash_val, shodan_api_key, verbose)
            if shodan_favicon_ips:
                print_colored(f"  [SUCCESS] Shodan (Favicon) found {len(shodan_favicon_ips)} potential IP(s).", Fore.GREEN, prefix="  ")
                for ip in shodan_favicon_ips:
                    print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
                    found_ips.add(ip)
            else:
                print_colored("  [INFO] Shodan (Favicon) did not return additional IPs.", Fore.YELLOW, prefix="  ")
    elif verbose:
        print_colored("  [Favicon] Shodan API key not provided. Skipping Favicon lookup.", Fore.YELLOW, prefix="  ")


    # --- Subdomain Enumeration (now includes SecurityTrails & Brute-Force) ---
    print_colored(f"\n[*] Enumerating subdomains from various sources for {target}...", Fore.WHITE)
    # find_subdomains_from_sources now calls SecurityTrails and Brute-Force internally
    discovered_subdomains = find_subdomains_from_sources(target, api_keys, verbose)
    found_subdomains.update(discovered_subdomains) 
    if found_subdomains:
        print_colored(f"  [SUCCESS] Subdomain enumeration found {len(found_subdomains)} subdomain(s).", Fore.GREEN, prefix="  ")
        # Resolve IPs for discovered subdomains
        for subdomain in found_subdomains:
            # We already resolve IPs for each subdomain in bruteforce_subdomains,
            # but this loop ensures all found subdomains from all sources get their IPs resolved.
            # Avoid re-printing if already verbose in the specific function.
            if verbose: print_colored(f"    - {subdomain}", Fore.CYAN, prefix="    ")
            sub_a_records = get_dns_records(subdomain, 'A', verbose)
            found_ips.update(sub_a_records)
            sub_aaaa_records = get_dns_records(subdomain, 'AAAA', verbose)
            found_ips.update(sub_aaaa_records)
            if (sub_a_records or sub_aaaa_records) and verbose:
                print_colored(f"      [Subdomain DNS] Resolved IPs for {subdomain}: {list(set(sub_a_records + sub_aaaa_records))}", Fore.LIGHTCYAN_EX, prefix="      ")
    else:
        print_colored("  [INFO] No additional subdomains found.", Fore.YELLOW, prefix="  ")
    
    # --- NEW: ASN IP Lookup (after initial IP collection) ---
    ipinfo_api_key = api_keys.get('ipinfo_api_key') if api_keys else None
    if ipinfo_api_key:
        print_colored(f"\n[*] Performing ASN lookups on collected IPs...", Fore.WHITE)
        initial_ips_for_asn_check = list(found_ips) # Take a snapshot of IPs found so far
        asn_found_ips = set()
        for ip in initial_ips_for_asn_check:
            new_ips = get_asn_ips(ip, ipinfo_api_key, verbose)
            asn_found_ips.update(new_ips)
        
        if asn_found_ips:
            print_colored(f"  [SUCCESS] ASN lookup found {len(asn_found_ips)} additional potential IP(s).", Fore.GREEN, prefix="  ")
            for ip in asn_found_ips:
                print_colored(f"    - {ip}", Fore.CYAN, prefix="    ")
                found_ips.add(ip)
        else:
            print_colored("  [INFO] ASN lookup did not return additional IPs.", Fore.YELLOW, prefix="  ")
    elif verbose:
        print_colored("  [ASN] IPinfo.io API key not provided. Skipping ASN lookup.", Fore.YELLOW, prefix="  ")

    # --- NEW: Reverse IP Lookup (after all IPs are collected) ---
    viewdns_api_key = api_keys.get('viewdns_api_key') if api_keys else None
    if viewdns_api_key:
        print_colored(f"\n[*] Performing Reverse IP lookups on collected IPs...", Fore.WHITE)
        all_current_ips = list(found_ips) # Snapshot current IPs for reverse lookup
        reverse_ip_found_domains = set()
        for ip in all_current_ips:
            # For each IP found, try to find other domains on it
            new_domains = query_reverse_ip_viewdns(ip, viewdns_api_key, verbose)
            if new_domains:
                reverse_ip_found_domains.update(new_domains)
                # For each new domain found, resolve its IPs as well
                for new_domain in new_domains:
                    if verbose: print_colored(f"    [ReverseIP] Resolving IPs for new domain {new_domain}...", Fore.LIGHTBLACK_EX, prefix="    ")
                    new_domain_a = get_dns_records(new_domain, 'A', verbose=False)
                    new_domain_aaaa = get_dns_records(new_domain, 'AAAA', verbose=False)
                    found_ips.update(new_domain_a)
                    found_ips.update(new_domain_aaaa)
                    if (new_domain_a or new_domain_aaaa) and verbose:
                        print_colored(f"      [ReverseIP DNS] Resolved IPs for {new_domain}: {list(set(new_domain_a + new_domain_aaaa))}", Fore.LIGHTCYAN_EX, prefix="      ")
        if reverse_ip_found_domains:
            print_colored(f"  [SUCCESS] Reverse IP lookup found {len(reverse_ip_found_domains)} additional domains.", Fore.GREEN, prefix="  ")
            # The IPs from these domains are already added to found_ips
        else:
            print_colored("  [INFO] Reverse IP lookup did not return additional domains.", Fore.YELLOW, prefix="  ")
    elif verbose:
        print_colored("  [ReverseIP] ViewDNS.info API key not provided. Skipping Reverse IP lookup.", Fore.YELLOW, prefix="  ")


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
    return list(found_ips), list(detected_wafs_passive) # Return both IPs and passive WAFs


# --- Main function: orchestrates the scan ---

def main():
    # ASCII Art Banner (UPDATED with Version 0.0.1 and Developer 0xmun1r)
    banner = f"""
{Fore.LIGHTCYAN_EX}{Style.BRIGHT}
       ___   ___      __  __
      |_ _| | _ \     \ \/ /
       | |  |  _/  _   >  < 
      |___| |_|   (_) /_/\_\
                       
{Style.RESET_ALL}
{Fore.WHITE}{Style.BRIGHT}        The ORIGIN IP Finder{Style.RESET_ALL}
{Fore.MAGENTA}{Style.BRIGHT}        Version: 0.0.1{Style.RESET_ALL}
{Fore.YELLOW}{Style.BRIGHT}        Developer: 0xmun1r{Style.RESET_ALL}
{Fore.CYAN}{Style.BRIGHT}
===========================================================
     {Fore.GREEN}WEB APPLICATION ORIGIN IP & FIREWALL DETECTOR{Style.RESET_ALL}{Fore.CYAN}{Style.BRIGHT}
===========================================================
{Style.RESET_ALL}
    """
    print(banner) # Moved to the very beginning of main()

    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}IP.X - An origin IP finder behind WAF and CDN, with WAF detection capabilities.{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True # Ensure help is always available
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
        help="Save only potential IPs to the specified file."
    )
    parser.add_argument(
        "--api_keys",
        type=str,
        metavar="FILE",
        default="api_keys.json", # Automatically looks for api_keys.json in CWD
        help="Path to a file containing API keys (e.g., Shodan, VirusTotal, SecurityTrails, IPinfo.io, ViewDNS.info) in JSON format.\n"
             "Defaults to 'api_keys.json' in the current directory if not specified."
    )

    args = parser.parse_args()

    if not args.active and not args.passive:
        print_colored("Error: You must enable either --active or --passive mode (or both).", Fore.RED, prefix="[ERROR]")
        parser.print_help()
        sys.exit(1)

    # --- API Keys Auto-Loading Logic ---
    api_keys = {}
    api_keys_path = args.api_keys # This will be 'api_keys.json' by default if not specified
    
    # Construct full path if it's not absolute
    if not os.path.isabs(api_keys_path):
        api_keys_path = os.path.join(os.getcwd(), api_keys_path)

    if os.path.exists(api_keys_path): # Only attempt to load if file exists
        try:
            with open(api_keys_path, 'r') as f:
                api_keys = json.load(f)
            if args.verbose:
                print_colored(f"[*] Successfully loaded API keys from {api_keys_path}", Fore.GREEN)
        except json.JSONDecodeError:
            print_colored(f"Error: Invalid JSON format in API keys file '{api_keys_path}'. API-dependent features will be skipped.", Fore.RED, prefix="[ERROR]")
        except Exception as e:
            print_colored(f"Error loading API keys from '{api_keys_path}': {e}. API-dependent features will be skipped.", Fore.RED, prefix="[ERROR]")
    else:
        if args.verbose:
            print_colored(f"API keys file '{api_keys_path}' not found. API-dependent features will be skipped.", Fore.YELLOW)


    print_colored(f"\n{Fore.LIGHTMAGENTA_EX}IP.X Scan Initiated for: {args.target}{Style.RESET_ALL}", Fore.WHITE, prefix="")
    print_colored(f"Active Mode: {Fore.GREEN if args.active else Fore.RED}{'Enabled' if args.active else 'Disabled'}", Fore.WHITE, prefix="  ")
    print_colored(f"Passive Mode: {Fore.GREEN if args.passive else Fore.RED}{'Enabled' if args.passive else 'Disabled'}", Fore.WHITE, prefix="  ")
    print_colored(f"Verbose Output: {Fore.GREEN if args.verbose else Fore.RED}{'Enabled' if args.verbose else 'Disabled'}", Fore.WHITE, prefix="  ")
    print_colored(f"Output File: {Fore.CYAN}{args.output if args.output else 'None'}", Fore.WHITE, prefix="  ")
    print_colored(f"API Keys File: {Fore.CYAN}{api_keys_path if api_keys else 'Not loaded'}", Fore.WHITE, prefix="  ")


    all_found_ips = set()
    detected_wafs_overall = set()

    if args.passive:
        passive_ips, passive_wafs = passive_scan(args.target, args.verbose, api_keys)
        all_found_ips.update(passive_ips)
        detected_wafs_overall.update(passive_wafs) # Add WAFs found during passive scan
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
        # Enhanced WAF summary output
        waf_list_str = ', '.join(sorted(list(detected_wafs_overall)))
        print_colored(f"\n{Fore.RED}{Style.BRIGHT}" + "="*50 + Style.RESET_ALL, Fore.RED, prefix="")
        print_colored(f"{Fore.RED}{Style.BRIGHT}!!! FINAL WAF DETECTION SUMMARY !!!{Style.RESET_ALL}", Fore.RED, prefix="", prefix_color="")
        print_colored(f"{Fore.WHITE}{Back.RED}{Style.BRIGHT} Detected WAF(s): {waf_list_str} {Style.RESET_ALL}", Fore.RED, prefix="", prefix_color="")
        print_colored(f"{Fore.RED}{Style.BRIGHT}" + "="*50 + Style.RESET_ALL, Fore.RED, prefix="")
    else:
        print_colored("\nNo WAFs detected.", Fore.GREEN)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                # Only write IPs to the file
                if all_found_ips:
                    for ip in sorted(list(all_found_ips)):
                        f.write(f"{ip}\n")
                else:
                    f.write("No potential origin IPs found.\n")
            print_colored(f"\nResults (IPs only) saved to: {args.output}", Fore.GREEN)
        except IOError as e:
            print_colored(f"Error: Could not write to output file '{args.output}': {e}", Fore.RED, prefix="[ERROR]")


if __name__ == "__main__":
    main()
