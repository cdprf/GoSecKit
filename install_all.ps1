# GoSecKit - Installation Script for PowerShell
# This script installs all the Go-based security tools listed in the README.md

Write-Host "Installing GoSecKit Tools..."

# Tool Management
Write-Host "Installing Tool Management..."
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

# Reconnaissance
Write-Host "Installing Reconnaissance Tools..."
# DNS & Subdomain Enumeration
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/boy-hack/ksubdomain/cmd/ksubdomain@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/OWASP/Amass/cmd/amass@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest

# IP & ASN Analysis
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/ip2location/ip2convert/ip2convert@latest
go install -v github.com/zu1k/nali@latest

# Content Discovery
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/dwisiswant0/galer@latest
go install -v github.com/ariary/JSextractor@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/pingc0y/URLFinder@latest
go install -v github.com/lc/subjs@latest

# OSINT
go install github.com/edoardottt/favirecon/cmd/favirecon@latest
go install github.com/edoardottt/csprecon/cmd/csprecon@latest
go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
go install github.com/utkusen/urlhunter@latest
go install github.com/dwisiswant0/go-dork@latest

# Asset Discovery
go install -v github.com/zhzyker/dismap/cmd/dismap@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
go install github.com/hideckies/aut0rec0n@latest

# Scanning
Write-Host "Installing Scanning Tools..."
# Port Scanning
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/liamg/furious@latest
go install -v github.com/shadow1ng/fscan@latest
go install -v github.com/s0md3v/smap/cmd/smap@latest
go install -v github.com/hktalent/scan4all@2.6.9

# Vulnerability Scanning
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/openrisk@latest
go install -v github.com/michenriksen/aquatone@latest
go install -v github.com/veo/vscan@latest
go install -v github.com/lcvvvv/kscan@latest
go install -v github.com/zan8in/afrog/v2/cmd/afrog@latest
# Note: The trivy installation command is for bash. For PowerShell, please refer to the trivy documentation for installation instructions.

# Web Scanning
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/EdgeSecurityTeam/EHole/cmd/EHole@latest
go install -v github.com/bitquark/shortscan/cmd/shortscan@latest

# Web Analysis & Fuzzing
Write-Host "Installing Web Analysis & Fuzzing Tools..."
# General Fuzzing
go install -v github.com/kitabisa/teler@latest
go install -v github.com/dwisiswant0/unew@latest
go install -v github.com/Damian89/yataf@latest
go install -v github.com/kitabisa/teler-waf@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/stefanoj3/dirstalk/cmd/dirstalk@latest
go install -v github.com/dwisiswant0/gfx@latest
go install -v github.com/hideckies/fuzzagotchi@latest

# CRLFuzz
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# XSS
go install github.com/KathanP19/Gxss@latest
go install github.com/hahwul/dalfox/v2@latest

# Exploitation
Write-Host "Installing Exploitation Tools..."
go install github.com/tsenart/vegeta@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Proxy Tools
Write-Host "Installing Proxy Tools..."
go install -v github.com/kitabisa/mubeng@latest
go install -v github.com/dstotijn/hetty@latest

# Utilities
Write-Host "Installing Utilities..."
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

Write-Host "All tools installed successfully!"