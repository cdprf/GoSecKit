# GoSecKit - Handy Go Toolkits for Security Professionals

A curated collection of powerful Go-based tools for security testing, reconnaissance, and analysis.

## Table of Contents

- [Installation & Updates](#installation--updates)
- [Tool Management](#tool-management)
- [Reconnaissance](#reconnaissance)
  - [DNS & Subdomain Enumeration](#dns--subdomain-enumeration)
  - [IP & ASN Analysis](#ip--asn-analysis)
  - [Content Discovery](#content-discovery)
  - [OSINT](#osint)
  - [Asset Discovery](#asset-discovery)
- [Scanning](#scanning)
  - [Port Scanning](#port-scanning)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Web Scanning](#web-scanning)
- [Web Analysis & Fuzzing](#web-analysis--fuzzing)
  - [General Fuzzing](#general-fuzzing)
  - [CRLFuzz](#crlfuzz)
  - [XSS](#xss)
- [Exploitation](#exploitation)
- [Proxy Tools](#proxy-tools)
- [Utilities](#utilities)

---

## Installation & Updates

Ensure you have Go installed and properly configured in your system's environment.

<details>
  <summary><strong>Linux (apt)</strong></summary>

  ```bash
  # Install Git and Go
  sudo apt update && sudo apt install git golang -y

  # Optional: Update Go to the latest version
  git clone https://github.com/udhos/update-golang
  cd update-golang && sudo ./update-golang.sh
  cd .. && rm -rf update-golang
  ```
</details>

<details>
  <summary><strong>Windows (Chocolatey / Scoop / Winget)</strong></summary>

  Using **Chocolatey**:
  ```powershell
  choco install git golang
  ```

  Using **Scoop**:
  ```powershell
  scoop install git go
  ```

  Using **Winget**:
  ```powershell
  winget install git GoLang.Go
  ```
</details>

<details>
  <summary><strong>Update Nuclei Templates</strong></summary>

  ```bash
  nuclei -update-templates
  ```
</details>


---

## Bulk Installation Scripts

For convenience, you can use the following scripts to install all the tools listed in this document at once.

<details>
  <summary><strong>Bash (Linux/macOS)</strong></summary>

  ```bash
  # Make the script executable
  chmod +x install_all.sh

  # Run the script
  ./install_all.sh
  ```
</details>

<details>
  <summary><strong>PowerShell (Windows)</strong></summary>

  ```powershell
  # Run the script
  ./install_all.ps1
  ```
</details>

---

## Tool Management

<details>
  <summary><strong>PDTM - ProjectDiscovery Tool Manager</strong></summary>

  ```bash
  # Install pdtm
  go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

  # Install all tools to a specific path
  pdtm -ia -ip C:\Portables\Security
  ```
</details>

---

## Reconnaissance

### DNS & Subdomain Enumeration

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Get subdomains for a single domain
  chaos -d uber.com

  # Get subdomains for a list of domains
  chaos -dL domains.txt

  # Get subdomains and save the output to a file
  chaos -d uber.com -o uber_subdomains.txt
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Find subdomains for a single domain
  subfinder -d example.com

  # Find subdomains for a list of domains
  subfinder -dL domains.txt

  # Find subdomains and save the output to a file
  subfinder -d example.com -o subdomains.txt
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Resolve a list of subdomains
  shuffledns -d example.com -list subdomains.txt -r resolvers.txt -mode resolve

  # Bruteforce subdomains using a wordlist
  shuffledns -d example.com -w wordlist.txt -r resolvers.txt -mode bruteforce

  # Use subfinder and shuffledns together
  subfinder -d example.com | shuffledns -d example.com -r resolvers.txt -mode resolve
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/boy-hack/ksubdomain/cmd/ksubdomain@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Enumerate subdomains for a single domain
  ksubdomain enum -d example.com

  # Verify a list of subdomains from a file
  ksubdomain verify -f subdomains.txt

  # Enumerate subdomains from stdin
  echo "example.com" | ksubdomain enum --stdin
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/d3mondev/puredns/v2@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Resolve a list of domains from a file
  puredns resolve domains.txt

  # Bruteforce subdomains using a wordlist
  puredns bruteforce wordlist.txt example.com

  # Resolve domains from stdin
  cat domains.txt | puredns resolve
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/OWASP/Amass/cmd/amass@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Discover domains related to an organization
  amass intel -d owasp.org -whois

  # Perform a passive enumeration
  amass enum -passive -d owasp.org

  # Perform an active enumeration with brute-forcing
  amass enum -active -d owasp.org -brute -w wordlist.txt
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Generate permutations from a list of subdomains
  chaos -d tesla.com | alterx

  # Enrich the wordlist with known subdomains to generate more targeted permutations
  chaos -d tesla.com | alterx -enrich

  # Use a custom pattern for generating permutations
  chaos -d tesla.com | alterx -enrich -p '{{word}}-{{suffix}}'
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>

### IP & ASN Analysis

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Get ASN information for a specific ASN
  asnmap -a AS14421

  # Get ASN information for a specific IP address
  asnmap -i 93.184.216.34

  # Get ASN information for a specific domain
  asnmap -d example.com
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Get the A records for a domain
  echo "example.com" | dnsx -a

  # Filter out wildcard subdomains
  dnsx -l subdomains.txt -wd example.com -o output.txt

  # Use a custom resolver
  chaos -d hackerone.com | dnsx -r 1.1.1.1
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Expand a CIDR to a list of IPs
  mapcidr -cidr 173.0.84.0/24

  # Slice a CIDR into smaller subnets
  mapcidr -cidr 173.0.84.0/24 -sbc 10

  # Aggregate a list of IPs into a CIDR
  mapcidr -il ips.txt -aggregate
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/ip2location/ip2convert/ip2convert@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Convert IP2Location DB1 IPv6 CSV into MMDB format (GeoLite2-Country)
  ip2convert csv2mmdb -t country -i IPV6-COUNTRY.CSV -o IP2LOCATION-LITE-DB1.MMDB

  # Convert IP2Location DB9 IPv6 CSV into MMDB format (GeoLite2-City)
  ip2convert csv2mmdb -t city -i IPV6-COUNTRY-REGION-CITY-LATITUDE-LONGITUDE-ZIPCODE.CSV -o IP2LOCATION-LITE-DB9.MMDB

  # Convert IP2Location DB15 IPv6 CSV into MMDB format (GeoLite2-ASN)
  ip2convert csv2mmdb -t asn -i IPV6-ASN.CSV -o IP2LOCATION-LITE-DB15.MMDB
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/zu1k/nali@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Query a single IP address
  nali 1.2.3.4

  # Query multiple IP addresses
  nali 1.2.3.4 4.3.2.1

  # Use with other tools
  dig bing.com +short | nali
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>

### Content Discovery

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/lc/gau/v2/cmd/gau@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Fetch all known URLs for a domain
  gau example.com

  # Fetch URLs for subdomains as well
  gau --subs example.com

  # Use with other tools to find XSS vulnerabilities
  gau example.com | gf xss
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/tomnomnom/assetfinder@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Find all assets for a domain
  assetfinder example.com

  # Find subdomains only
  assetfinder --subs-only example.com

  # Use with other tools to check for live hosts
  assetfinder --subs-only example.com | httprobe
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/dwisiswant0/galer@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # List all available patterns
  gfx -l

  # Print the grep command of a pattern
  gfx -d aws*

  # Save a new pattern
  gfx --save pattern-name '-Hnri' 'search-pattern'
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Fetch URLs from a single URL
  galer -u "http://domain.tld"

  # Fetch URLs from a list of URLs
  galer -u urls.txt

  # Fetch URLs from stdin
  cat urls.txt | galer
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/ariary/JSextractor@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Gather all JavaScript from a URL
  curl https://example.com | jse

  # Gather JavaScript from a specific source (e.g., script tags)
  curl https://example.com | jse -ds

  # Launch the Terminal User Interface (TUI)
  curl https://example.com | jse -tui
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/tomnomnom/waybackurls@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Fetch all known URLs for a domain
  waybackurls example.com

  # Fetch URLs for a list of domains
  cat domains.txt | waybackurls

  # Use with other tools to check for live hosts
  waybackurls example.com | httprobe
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/jaeles-project/gospider@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Crawl a single site
  gospider -s "https://example.com"

  # Crawl a list of sites
  gospider -S sites.txt

  # Crawl a site using a proxy
  gospider -s "https://example.com" -p "http://127.0.0.1:8080"
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Find all URLs for a domain
  urlfinder -d example.com

  # Find URLs matching a specific pattern
  urlfinder -d example.com -m "shop"

  # Output results in JSONL format
  urlfinder -d example.com -j
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/lc/subjs@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Basic fuzzing
  ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ

  # Fuzzing with a specific wordlist and extensions
  ffuf -w /usr/share/wordlists/dirb/common.txt -e .php,.html -u https://example.com/FUZZ

  # Fuzzing with a custom header
  ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ -H "User-Agent: MyFuzzer"
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Fetch javascript files from a list of URLs
  cat urls.txt | subjs

  # Fetch javascript files from a file
  subjs -i urls.txt

  # Use with other tools to get javascript files from subdomains
  cat hosts.txt | gau | subjs
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>

### OSINT

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install github.com/edoardottt/favirecon/cmd/favirecon@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Identify a single domain
  favirecon -u https://www.github.com

  # Identify a list of domains
  favirecon -l targets.txt

  # Identify a CIDR range
  favirecon -u 192.168.1.0/24 -cidr
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install github.com/edoardottt/csprecon/cmd/csprecon@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Discover new domains from a single domain
  csprecon -u https://www.github.com

  # Discover new domains from a list of domains
  csprecon -l targets.txt

  # Discover new domains from a CIDR range
  csprecon -u 192.168.1.0/24 -cidr
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Hunt for secrets in a list of URLs
  cat urls.txt | cariddi -s

  # Hunt for juicy endpoints in a list of URLs
  cat urls.txt | cariddi -e

  # Hunt for juicy files in a list of URLs
  cat urls.txt | cariddi -ext 2
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install github.com/utkusen/urlhunter@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Search for a keyword
  urlhunter -k "example.com"

  # Search for a list of keywords
  urlhunter -k keywords.txt

  # Search for a specific date
  urlhunter -d 2023-10-26
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install github.com/dwisiswant0/go-dork@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Perform a simple dork query
  go-dork -q "inurl:'...'"

  # Use a different search engine (e.g., Bing)
  go-dork -e bing -q ".php?id="

  # Scrape multiple pages of results
  go-dork -q "intext:'jira'" -p 5
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>

### Asset Discovery

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/zhzyker/dismap/cmd/dismap@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a network segment
  dismap -i 192.168.1.1/24

  # Scan a single URL
  dismap -u https://example.com

  # Scan a network segment with custom ports
  dismap -i 192.168.1.1/24 -p 1-65535
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Perform a simple query using the default engine (shodan)
  uncover -q "grafana"

  # Use a specific engine (e.g., fofa)
  uncover -e fofa -q "app=\\"Apache-Tomcat\\""

  # Use the awesome search queries to find exposed assets
  uncover -asq "jira"
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install github.com/hideckies/aut0rec0n@latest
  ```
</details>

---

## Scanning

### Port Scanning

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single host
  naabu -host example.com

  # Scan a list of hosts
  naabu -list hosts.txt

  # Scan the top 100 ports
  naabu -host example.com -top-ports 100
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/liamg/furious@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single host
  furious 192.168.1.4

  # Scan a whole CIDR
  furious 192.168.1.0/24

  # Scan a mixture of IPs, hostnames and CIDRs
  furious -s connect 8.8.8.8 192.168.1.1/24 google.com
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/shadow1ng/fscan@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single host
  fscan -h 192.168.1.1

  # Scan a range of hosts
  fscan -h 192.168.1.1-255

  # Scan with a specific module (e.g., ssh)
  fscan -h 192.168.1.1 -m ssh
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/s0md3v/smap/cmd/smap@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Basic scan with a dictionary
  dirstalk scan http://example.com/ --dictionary mydictionary.txt

  # Scan with custom HTTP methods
  dirstalk scan http://example.com/ --dictionary mydictionary.txt --http-methods GET,POST

  # Scan with a SOCKS5 proxy
  dirstalk scan http://example.com/ --dictionary mydictionary.txt --socks5 127.0.0.1:9150
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single host
  smap 127.0.0.1

  # Scan a list of hosts
  smap -iL targets.txt

  # Scan specific ports
  smap -p 21-30,80,443 -iL targets.txt
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/hktalent/scan4all@2.6.9
  ```
</details>

### Vulnerability Scanning

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single target
  nuclei -u https://example.com

  # Scan a list of targets
  nuclei -l targets.txt

  # Use with other tools to scan subdomains for exposures
  subfinder -d example.com | httpx | nuclei -t http/exposures/
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/openrisk@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # NOTE: This tool requires an OpenAI API key to be set as an environment variable.
  # export OPENAI_API_KEY=<YOUR_API_KEY>

  # Generate a risk score from a nuclei text output file
  openrisk -f nuclei_scan_result.txt

  # Generate a risk score from a nuclei JSONL output file
  openrisk -f nuclei_scan_result.jsonl

  # Generate a risk score from a nuclei markdown output file
  openrisk -f nuclei_scan_result.md
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/michenriksen/aquatone@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Run a basic scan on a list of hosts
  cat hosts.txt | aquatone

  # Scan with a specific set of ports
  cat hosts.txt | aquatone -ports 80,443,3000,3001

  # Use with amass for DNS enumeration
  amass enum -d example.com | aquatone
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/veo/vscan@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single host
  vscan -host example.com

  # Scan a list of hosts
  vscan -l hosts.txt

  # Scan the top 1000 ports
  vscan -host example.com -tp top-1000
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/lcvvvv/kscan@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single target
  kscan -t example.com

  # Scan a list of targets
  kscan -f targets.txt

  # Scan using a fofa query
  kscan --fofa "app=\\"Apache-Tomcat\\""
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/zan8in/afrog/v2/cmd/afrog@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single target
  afrog -t https://example.com

  # Scan a list of targets
  afrog -T targets.txt

  # Search for PoCs and scan the results
  afrog -s weblogic,jboss
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a container image
  trivy image YOUR_IMAGE

  # Scan a filesystem
  trivy fs /path/to/your_project

  # Filter by severity
  trivy image --severity CRITICAL YOUR_IMAGE
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>

### Web Scanning

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Crawl a single URL
  katana -u https://example.com

  # Crawl a list of URLs
  katana -list urls.txt

  # Use headless mode to crawl pages that require JavaScript
  katana -u https://example.com -headless
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Probe a single URL
  httpx -u https://example.com

  # Probe a list of URLs
  httpx -l urls.txt

  # Take a screenshot of a URL
  httpx -u https://example.com -screenshot
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/EdgeSecurityTeam/EHole/cmd/EHole@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single URL
  EHole -u https://example.com

  # Scan a list of URLs
  EHole -l urls.txt

  # Use the fingerprinting feature
  EHole -f "app=\\"Apache-Tomcat\\""
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/bitquark/shortscan/cmd/shortscan@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Scan a single URL
  shortscan http://example.org/

  # Scan a list of URLs from a file
  shortscan @urls.txt

  # Check if a site is vulnerable without enumerating files
  shortscan --isvuln http://example.org/
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  ```
</details>

---

## Web Analysis & Fuzzing

### General Fuzzing

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/kitabisa/teler@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Analyze logs from stdin
  tail -f /var/log/nginx/access.log | teler

  # Analyze logs from a file
  teler -i /var/log/nginx/access.log

  # Use a custom configuration file
  teler -i /var/log/nginx/access.log -c /path/to/config.yaml
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/dwisiswant0/unew@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```bash
  # Append URLs, skipping duplicates
  cat urls.txt | unew

  # Combine parameters from duplicate URLs
  cat urls.txt | unew -combine

  # Skip specific paths
  cat urls.txt | unew -skip-path ".(jpg|png|gif)"
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/Damian89/yataf@latest
  ```
</details>
<details>
  <summary>Usage Examples</summary>

  ```go
  // Basic implementation
  import "github.com/teler-sh/teler-waf"

  func main() {
      // ...
      teler := teler.New()
      http.Handle("/", teler.Handler(http.HandlerFunc(myHandler)))
      // ...
  }

  // Custom configuration
  import "github.com/teler-sh/teler-waf"

  func main() {
      // ...
      teler := teler.New(teler.Options{
          Excludes: []string{
              "/api/v1/users",
          },
      })
      http.Handle("/", teler.Handler(http.HandlerFunc(myHandler)))
      // ...
  }

  // Using with a specific framework (e.g., Gin)
  import (
      "github.com/gin-gonic/gin"
      "github.com/teler-sh/teler-waf"
  )

  func main() {
      // ...
      teler := teler.New()
      r := gin.Default()
      r.Use(teler.Gin())
      // ...
  }
  ```
</details>
<details>
  <summary>Installation Commands</summary>
  go install -v github.com/kitabisa/teler-waf@latest
  go install -v github.com/ffuf/ffuf@latest
  go install -v github.com/stefanoj3/dirstalk/cmd/dirstalk@latest
  go install -v github.com/dwisiswant0/gfx@latest
  go install -v github.com/hideckies/fuzzagotchi@latest
  ```
</details>

### CRLFuzz

<details>
  <summary>Installation and Usage</summary>

  ```bash
  # Install
  go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

  # Usage
  crlfuzz fuzz --url https://example.com/
  crlfuzz fuzz --url https://example.com/ --payload wordlist.txt --concurrency 10
  crlfuzz fuzz --url https://example.com/ --delay 500ms
  ```
</details>

### XSS

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install github.com/KathanP19/Gxss@latest
  go install github.com/hahwul/dalfox/v2@latest
  ```
</details>

---

## Exploitation

<details>
  <summary>Installation Commands</summary>

  ```bash
  # Denial of Service (DoS) Testing / Load Tester
  go install github.com/tsenart/vegeta@latest

  # Interaction Capture
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  ```
</details>

---

## Proxy Tools

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/kitabisa/mubeng@latest
  go install -v github.com/dstotijn/hetty@latest
  ```
</details>


---

## Utilities

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/notify/cmd/notify@latest
  go install -v github.com/tomnomnom/anew@latest
  go install -v github.com/spf13/viper@latest
  go install -v github.com/eth0izzle/shhgit@latest
  go install -v github.com/gohugoio/hugo@latest
  go install -v github.com/charmbracelet/glow@latest
  go install -v github.com/dhn/udon@latest
  go install -v github.com/tomnomnom/unfurl@latest
  go install -v github.com/projectdiscovery/aix/cmd/aix@latest
  go install -v github.com/mmM1ku/Mscan@latest
  ```
</details>