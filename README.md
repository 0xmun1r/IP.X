<p align="center">
  <img src="https://github.com/0xmun1r/IP.X/blob/main/image.png" width="300" height="200">
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=700&size=22&pause=1000&center=true&width=435&lines=🛡️+IP.X+-+The+Digital+Vanguard;🌐+Uncover+Origin+IP+Behind+WAF%2FCDN;🧠+OSINT+%2B+Active+Recon+Powered+Tool" alt="Typing SVG" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Recon-Tool-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active-orange?style=for-the-badge">
</p>

---

## 🧠 What is IP.X?

**IP.X** (The Digital Vanguard) is a Python-powered cyber reconnaissance tool crafted to **uncover origin IPs hidden behind WAF/CDN**. It uses both:

- 🎯 **Passive techniques** (e.g., DNS records, `crt.sh`, Shodan, Censys)
- ⚔️ **Active techniques** (e.g., Host header injection, DNS brute force)

> Whether you're doing OSINT or ethical hacking, IP.X gives you an edge.

---

# IP.X: The Advanced IP Finder & WAF Detector

## ⚙️ Features

IP.X employs a multi-faceted approach to IP discovery and WAF detection, including:

**Passive Reconnaissance:**
* **DNS Records:** Fetches A, AAAA, CNAME records.
* **Certificate Transparency Logs (crt.sh):** Discovers historical IPs and subdomains from public certificate data.
* **GitHub Pages Detection:** Identifies if a domain or subdomain is hosted on GitHub Pages.
* **Shodan:** Queries historical IP information and open ports/services associated with the target domain.
* **Favicon Hashing (with Shodan):** Calculates the favicon hash and searches Shodan for other IPs/domains sharing the same hash, revealing related infrastructure.
* **VirusTotal:** Gathers subdomains via VirusTotal's API.
* **ThreatCrowd:** Collects additional subdomains from ThreatCrowd data.
* **SecurityTrails:** Utilizes SecurityTrails for historical DNS records and extensive subdomain enumeration.
* **URLScan.io:** Queries public scan results for historical IPs and server headers.
* **Wayback Machine (Archive.org):** Retrieves historical IP addresses associated with the domain.
* **ASN IP Range Expansion (via IPinfo.io):** Discovers full IP ranges belonging to the target's Autonomous System Number.
* **Reverse IP Lookup (via ViewDNS.info):** Finds other domains hosted on the same IP address, revealing shared hosting.
* **Subdomain Brute-Forcing:** Actively probes for common subdomains using an internal wordlist.
* **Reverse DNS Lookups:** Translates discovered IP addresses back to hostnames.
* **Email Header Analysis:** Can extract public IPs from raw email headers (if provided).

**Active Reconnaissance:**
* **Port Scanning:** Checks common web ports (80, 443, 8080, 8443) on potential origin IPs.
* **Direct HTTP/S Probing:** Attempts direct connections to potential origin IPs, bypassing CDNs/WAFs using `Host` headers.
* **WAF/CDN Detection:** Analyzes HTTP response headers and body for signatures of known WAFs and CDNs.

## Prerequisites

Before you begin, ensure you have the following installed on your Linux system:

* `git`: For cloning the repository.
* `python3`: Python 3.8+ is recommended.
* `python3-pip`: The package installer for Python 3.

**For Debian/Kali Linux:**
```bash
sudo apt update -y
sudo apt install git python3-pip -y
```
---

## `/// 🚀 DEPLOYMENT PROTOCOL //`

### `[+] Installation (No VirtualEnv)`

```bash
git clone https://github.com/0xmun1r/IP.X.git
cd IP.X
python3 -m pip install --user -r requirements.txt
```
```
Add Your API Keys (Optional, but for full power):
```
---
In the current folder (/home/m0n1r/Downloads/IP.X), create a file named api_keys.json.

Open this file with a text editor (like nano api_keys.json or gedit api_keys.json).

Paste your keys inside, replacing the placeholder text:
```
{
  "shodan_api_key": "YOUR_SHODAN_API_KEY",
  "virustotal_api_key": "YOUR_VIRUTOTAL_API_KEY",
  "securitytrails_api_key": "YOUR_SECURITYTRAILS_API_KEY",
  "ipinfo_api_key": "YOUR_IPINFO_API_KEY",
  "viewdns_api_key": "YOUR_VIEWDNS_API_KEY"
}
```
---

📂 Usage
Basic scan with both active and passive modes, verbose output
```
IP.X example.com --active --passive --verbose
```
Example: Using a specific API keys file
```
IP.X example.com --active --passive --api_keys /path/to/your/api_keys.json
```
Example: Saving results to a file
```
IP.X example.com --passive --output found_ips.txt
```
Example: Only passive reconnaissance
```
IP.X example.com --passive
```
Example: Only active reconnaissance (will try to resolve IPs first)
```
IP.X example.com --active
```
Show help message (banner will also be displayed)
```
IP.X --help
```
# 🧪 Scan Examples
```
🔍 Passive :  IP.X --target example.com --passive
⚔️ Active  :  IP.X --target example.com --active --output out.txt
👻 Silent  :  IP.X --target example.com --active --silent
💡 Pro Tip  : Combine --active + --output for max power 🔥
```
 
**`v1.0 // Code-Name: DIGITAL_VANGUARD`**
`_ The Architect: 0xmun1d _`

---

## `/// SYSTEM STATUS ///`

*(**Note:** Replace `your-username` in the badge links with your actual GitHub username. You may need to set up GitHub Actions for the Build Status badge to work.)*

-----

## `/// CORE INTEL //`


[ 💾 The Mission: Unveiling the Origin ]---


IP.X stands as a **pinnacle Python-driven intelligence framework**, meticulously engineered for the discerning digital investigator. Its prime directive: to **uncover the true origin IP address** of any target domain, even when it's fortified behind the intricate defenses of Web Application Firewalls (WAFs) and Content Delivery Networks (CDNs). More than just an IP retriever, IP.X actively **identifies and classifies the digital guardians** (WAFs) attempting to shield the truth.

--- For those who seek deeper insights, beyond the obvious.`

-----

## `/// THE ENGINE //`

IP.X operates with a calculated fusion of clandestine information gathering and assertive network probing, leveraging a vast network of data sources to construct a comprehensive threat landscape.

### `[ 01 ] -- PASSIVE OPERATIONS: DIGITAL FOOTPRINTING --`

```
┌──────────────────────────────────────────────────────────────┐
│ >_ Gathering intelligence without direct engagement.         │
└──────────────────────────────────────────────────────────────┘
```

  * `🖧 DNS Record Forensics`: Dives into current and historical A (IPv4) and AAAA (IPv6) records, unearthing critical infrastructure footprints.
  * `📜 Certificate Transparency Logs (crt.sh)`: Scours public SSL/TLS certificate databases, revealing dormant IPs and previously unknown subdomains from past and present certificates.
  * `🐙 GitHub Pages Fingerprinting`: Identifies custom domains routing to GitHub Pages, a common misconfiguration exposure.
  * `🔍 Shodan Nexus Query`: Hooks into Shodan's vast database to pull historical IP data, open ports, and organizational footprints.
  * `📊 Censys Protocol Interrogation`: Interrogates Censys for comprehensive internet-wide scan data, correlating IPs with certificate and DNS metadata.
  * `🔄 Reverse DNS Chain`: Traces IPs back to associated hostnames via PTR records, often unveiling interconnected infrastructure.
  * `🌲 Subdomain Swarm Enumeration`: Leverages multiple OSINT sources (crt.sh, VirusTotal, ThreatCrowd) to uncover a broad spectrum of subdomains, and then resolves their corresponding IPs.
  * `📧 Email Header Forensics (Utility)`: Includes a module to extract potential origin IPs embedded within raw email `Received:` headers – a deep dive into communication metadata.

### `[ 02 ] -- ACTIVE ENGAGEMENTS: PROBING THE VEIL --`

```
┌──────────────────────────────────────────────────────────────┐
│ >_ Calculated interaction to validate and expose hidden hosts.│
└──────────────────────────────────────────────────────────────┘
```

  * `🔌 Port Illumination`: Conducts lightweight scans on standard web ports (80, 443, 8080, 8443) on identified potential IPs, seeking open doors.
  * `🎭 Host Header Forgery`: Executes direct HTTP/S requests to suspected origin IPs, strategically altering the `Host` header to trick misconfigured servers into revealing their true content, bypassing front-end defenses.

### `[ 03 ] -- WAF DECRYPTION PROTOCOL: SHIELD BREAKER --`

```
┌──────────────────────────────────────────────────────────────┐
│ >_ Identifying and categorizing the protective layers.       │
└──────────────────────────────────────────────────────────────┘
```

IP.X systematically analyzes HTTP response headers, cookies, and even subtle HTML cues against an extensive database of known WAF and CDN signatures. Detected WAFs are **`FLAGGED WITH HIGH VISUAL PROMINENCE`**, providing immediate clarity on the target's defensive strategy.

-----

## `/// TACTICAL EXECUTION //`

Once deployed, `IP.X` is ready for command. API keys from `api_keys.json` will be automatically detected if found in your current working directory.

**`Command Syntax:`**

```bash
IP.X <target_domain> [--active] [--passive] [--verbose] [--output <filename.txt>]
```

**`Argument Modifiers:`**

  * `<target_domain>`: The primary target for your digital incursion (e.g., `securehost.com`). `[MANDATORY]`
  * `--active`: Engage active probing protocols (direct connections, port scans).
  * `--passive`: Initiate silent intelligence gathering (OSINT, historical data).
  * `--verbose`: Unveil detailed operational logs during the scan for granular analysis.
  * `--output <filename.txt>`: Direct the discovered potential IPs into a dedicated log file for post-operation review.

**`Strategic Engagement Scenarios:`**

1.  **`Full Spectrum Dominance (Recommended):`**

    ```bash
    IP.X target.com --passive --active --verbose --output comprehensive_ips.txt
    ```

    `>> For an exhaustive deep-dive, leaving no digital shadow unexamined.`

2.  **`Ghost Protocol (Passive Stealth):`**

    ```bash
    IP.X covert.net --passive --verbose --output stealth_intel.txt
    ```

    `>> Extract critical intelligence from public archives, maintaining a low profile.`

3.  **`Direct Breach Assessment (Active Probe):`**

    ```bash
    IP.X highvalue.org --active --verbose
    ```

    `>> Focused penetration testing on a known vulnerability point or suspected origin.`

4.  **`Rapid Threat Appraisal (Quick Overview):`**

    ```bash
    IP.X swiftscan.xyz --active --passive
    ```

    `>> For swift insights into potential IPs and immediate WAF identification.`

5.  **`Accessing the Manual:`**

    ```bash
    IP.X --help
    ```

    `>> Consult the operational manual for all available parameters.`





## `/// DIGITAL WISDOM //`

> "The difference between a curious mind and a powerful one is action."
> `— Unknown Architect`

-----

```
```
IP.X - The Digital Vanguard
👨‍💻 Author
0xmun1r
---
---

## 🧠 Stay Ahead with HackExploit Weekly

🎯 **Hack | Learn | Dominate**  
Join 0xmun1r’s free newsletter crafted for ethical hackers, recon nerds & bug bounty hunters.

👉 [Subscribe now on Substack](https://hackexploit.substack.com)

💥 What you'll get every week:
- 🕵️‍♂️ Real-world Recon + OSINT Tactics
- ⚔️ Bug Bounty Automation Tips
- 🧠 Deep Dives into Tools like IP.X
- 🧪 Zero-day Research & Practical Exploits

[![Subscribe Now](https://img.shields.io/badge/Subscribe--Now-HackExploit_Weekly-orange?style=for-the-badge&logo=substack)](https://hackexploit.substack.com)

> Powered by **HackExploit.S** | Curated by `0xmun1r` | Always Free 🚀

---

## 🌐 Connect with me

[![GitHub](https://img.shields.io/badge/GitHub-0×mun1r-181717?style=for-the-badge&logo=github)](https://github.com/0xmun1r)
[![Facebook](https://img.shields.io/badge/Facebook-Page-blue?style=for-the-badge&logo=facebook)](https://facebook.com/0xmun1r)
[![Telegram](https://img.shields.io/badge/Telegram-Channel-2CA5E0?style=for-the-badge&logo=telegram)](https://t.me/telegr_mun1r)
[![YouTube](https://img.shields.io/badge/YouTube-Channel-FF0000?style=for-the-badge&logo=youtube)](https://youtube.com/@0xmun1r?si=BQwwz7HA2YfqKvaF)

📜 License
This project is licensed under the MIT License.

<p align="center"><b><i>✨ Scan Deep. Reveal All. Be the Digital Vanguard. ✨</i></b></p> ```
