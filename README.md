# VulnForge
 
**Vulnerability & Exploit Intelligence Tool | Nebula Forge Detection Suite v2**
 
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-lightgrey?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Part of Nebula Forge](https://img.shields.io/badge/Nebula%20Forge-Detection%20Suite%20v2-58a6ff?style=flat-square)](https://github.com/Rootless-Ghost/Nebula-Forge)
 
VulnForge aggregates exploit intelligence from ExploitDB, NVD, and Metasploit, maps findings to MITRE ATT&CK techniques, and feeds results directly into the Nebula Forge purple team pipeline — generating hunt playbooks, LogNorm-ready exports, and AtomicLoop simulation triggers from a single search.
 
---
 
## Overview
 
VulnForge closes the gap between vulnerability discovery and detection engineering. Search for a CVE or keyword, get back exploit data mapped to ATT&CK techniques, then push that context downstream — straight into HuntForge for playbook generation or AtomicLoop for simulation.
 
**Pipeline position:**
 
```
VulnForge → HuntForge (hunt playbook) → AtomicLoop (simulation) → Wazuh (detection)
```
 
---
 
## Features
 
- **Multi-source search** — ExploitDB, NVD (NIST API v2), and Metasploit in parallel
- **CVE → ATT&CK mapping** — CVE/CWE → CAPEC → ATT&CK technique chaining via `mitreattack-python`
- **LogNorm export** — ECS-lite NDJSON compatible with the LogNorm normalization pipeline
- **HuntForge integration** — Send technique IDs directly to HuntForge for auto-generated hunt playbooks
- **AtomicLoop trigger** — Push ATT&CK technique IDs to AtomicLoop for simulation execution
- **CVSS scoring** — Color-coded severity (Critical / High / Medium / Low)
- **Dark UI** — Nebula Forge dark theme, consistent with the full suite
---

## Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/automated-exploit-finder.git
cd automated-exploit-finder
```

2. Install the required dependencies:
```
pip install requests beautifulsoup4 colorama tqdm
```

3. Make the script executable:
```
chmod +x exploit_finder.py
```

## Usage

### Basic Usage

```
python exploit_finder.py --keyword "apache 2.4" --type "rce" --output results.json
```

### Search by CVE ID

```
python exploit_finder.py --cve "CVE-2021-44228" --output log4shell_exploits.json
```

### Search for Specific Platform Exploits

```
python exploit_finder.py --keyword "wordpress" --platform "php" --output wordpress_exploits.csv --format csv
```

### Search Only Specific Sources

```
python exploit_finder.py --keyword "windows" --exploitdb --metasploit
```

### Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--keyword` | `-k` | Keyword to search for (e.g., "apache 2.4") |
| `--cve` | `-c` | Specific CVE ID to search for (e.g., "CVE-2021-44228") |
| `--type` | `-t` | Type of exploit to search for (e.g., "rce", "sqli", "xss") |
| `--platform` | `-p` | Platform to search for (e.g., "windows", "linux", "php") |
| `--output` | `-o` | Output file name |
| `--format` | `-f` | Output format (json or csv, default: json) |
| `--exploitdb` | | Search only ExploitDB |
| `--nvd` | | Search only NVD |
| `--metasploit` | | Search only Metasploit |

## Example Output

```
[*] Starting comprehensive search across all databases...
[*] Search criteria: keyword='apache', type='rce', platform='None', cve='None'
[*] Searching ExploitDB...
[+] Found 15 exploits on ExploitDB
[*] Searching NVD Database...
[+] Found 23 vulnerabilities in NVD
[*] Searching Metasploit Framework...
[+] Found 7 exploits in Metasploit
[+] Search complete. Found 45 total results

=== Results Summary ===
[*] ExploitDB: 15 results
[*] NVD: 23 results
[*] Metasploit: 7 results
[+] Results exported to exploit_finder_results_20250324_120835.json

=== Sample Results (showing first 5) ===

Result #1 from ExploitDB
  ID: 51095
  Title: Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
  Date: 2022-04-08
  URL: https://www.exploit-db.com/exploits/51095

Result #2 from ExploitDB
  ID: 50572
  Title: Apache 2.4.49 - Path Traversal
  Date: 2021-10-05
  URL: https://www.exploit-db.com/exploits/50572

...
```

## Responsible Usage

This tool is intended for legitimate security testing and research purposes only. Always ensure you have proper authorization before testing for vulnerabilities on any system. Unauthorized testing may violate laws and regulations.

## Acknowledgments

- ExploitDB for maintaining a comprehensive exploit database
- National Vulnerability Database (NVD) for providing CVE information
- Metasploit Framework for providing a powerful exploitation framework

## Disclaimer

The authors of this tool are not responsible for any misuse or damage caused by this program. Use at your own risk.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.


<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

</div>

