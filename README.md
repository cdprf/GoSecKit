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
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  go install -v github.com/boy-hack/ksubdomain/cmd/ksubdomain@latest
  go install -v github.com/d3mondev/puredns/v2@latest
  go install -v github.com/OWASP/Amass/cmd/amass@latest
  go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
  ```
</details>

### IP & ASN Analysis

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
  go install -v github.com/ip2location/ip2convert/ip2convert@latest
  go install -v github.com/zu1k/nali@latest
  ```
</details>

### Content Discovery

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/lc/gau/v2/cmd/gau@latest
  go install -v github.com/tomnomnom/assetfinder@latest
  go install -v github.com/dwisiswant0/galer@latest
  go install -v github.com/ariary/JSextractor@latest
  go install -v github.com/tomnomnom/waybackurls@latest
  go install -v github.com/jaeles-project/gospider@latest
  go install -v github.com/pingc0y/URLFinder@latest
  go install -v github.com/lc/subjs@latest
  ```
</details>

### OSINT

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install github.com/edoardottt/favirecon/cmd/favirecon@latest
  go install github.com/edoardottt/csprecon/cmd/csprecon@latest
  go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
  go install github.com/utkusen/urlhunter@latest
  go install github.com/dwisiswant0/go-dork@latest
  ```
</details>

### Asset Discovery

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/zhzyker/dismap/cmd/dismap@latest
  go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
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
  go install -v github.com/liamg/furious@latest
  go install -v github.com/shadow1ng/fscan@latest
  go install -v github.com/s0md3v/smap/cmd/smap@latest
  go install -v github.com/hktalent/scan4all@2.6.9
  ```
</details>

### Vulnerability Scanning

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  go install -v github.com/projectdiscovery/openrisk@latest
  go install -v github.com/michenriksen/aquatone@latest
  go install -v github.com/veo/vscan@latest
  go install -v github.com/lcvvvv/kscan@latest
  go install -v github.com/zan8in/afrog/v2/cmd/afrog@latest
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  ```
</details>

### Web Scanning

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/EdgeSecurityTeam/EHole/cmd/EHole@latest
  go install -v github.com/bitquark/shortscan/cmd/shortscan@latest
  ```
</details>

---

## Web Analysis & Fuzzing

### General Fuzzing

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/kitabisa/teler@latest
  go install -v github.com/dwisiswant0/unew@latest
  go install -v github.com/Damian89/yataf@latest
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