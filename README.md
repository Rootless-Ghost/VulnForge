[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/)

# Automated Exploit Finder

A Python tool for junior penetration testers to search for exploits across multiple vulnerability databases, including ExploitDB, National Vulnerability Database (NVD), and Metasploit Framework.

## Features

- Search for exploits by keywords, CVE IDs, exploit types, and platforms
- Query multiple sources in parallel using multi-threading
- Export results in JSON or CSV format
- Color-coded terminal output for better readability
- Integration with Metasploit Framework (if installed)

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

