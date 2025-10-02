# GoSecKit - Handy Go Toolkits for Security Professionals

A curated collection of powerful Go-based tools for security testing, reconnaissance, and analysis.

## Table of Contents

- [Installation & Updates](#installation--updates)
- [Reconnaissance](#reconnaissance)
  - [DNS Enumeration](#dns-enumeration)
  - [IP & ASN Analysis](#ip--asn-analysis)
  - [Content Discovery](#content-discovery)
- [Scanning](#scanning)
  - [Port Scanning](#port-scanning)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Web Scanning](#web-scanning)
- [Web Analysis & Fuzzing](#web-analysis--fuzzing)
- [Exploitation](#exploitation)
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

---

## Reconnaissance

### DNS Enumeration

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  go install -v github.com/boy-hack/ksubdomain/cmd/ksubdomain@latest
  go install -v github.com/d3mondev/puredns/v2@latest
  go install -v github.com/OWASP/Amass/cmd/amass@latest
  ```
</details>

### IP & ASN Analysis

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
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
  ```
</details>

### Vulnerability Scanning

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  go install -v github.com/projectdiscovery/openrisk@latest
  go install -v github.com/michenriksen/aquatone@latest
  go install -v github.com/hack2fun/Gscan/releases/download/v1.0/Gscan_windows_amd64.zip
  ```
</details>

### Web Scanning

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```
</details>

---

## Web Analysis & Fuzzing

<details>
  <summary>Installation Commands</summary>

  ```bash
  go install -v github.com/kitabisa/teler@latest
  go install -v github.com/dwisiswant0/unew@latest
  go install -v github.com/Damian89/yataf@latest
  go install -v github.com/kitabisa/teler-waf@latest
  ```
</details>

---

## Exploitation

<details>
  <summary>Installation Commands</summary>

  ```bash
  # Denial of Service (DoS) Testing
  go install github.com/tsenart/vegeta@latest

  # Interaction Capture
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
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
  go install github.com/gohugoio/hugo@latest
  go install github.com/zu1k/nali@latestna
  go install github.com/mmM1ku/Mscan
  ```
</details>