# SubNaut - Powerful Subdomain Enumeration Tool

![Bash Script](https://img.shields.io/badge/bash-script-blue) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

SubNaut is an advanced Bash script that performs extensive subdomain enumeration using multiple tools and techniques, with optional active probing of discovered subdomains.

<img width="1115" height="628" alt="image" src="https://github.com/user-attachments/assets/1c5074c1-9e58-4550-a30a-cab75a8cff6c" />

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Examples](#examples)
6. [Contributing](#contributing)
7. [License](#license)
8. [Author](#author)

---

## Features

- Supports multiple popular subdomain discovery tools:
  - subfinder
  - assetfinder
  - knock
  - findomain
  - subenum
  - VirusTotal API integration
- Accepts single domain or a list of domains from a file
- Allows selection or exclusion of specific tools for enumeration
- Combines and deduplicates results using `anew`
- Optionally probes subdomains for active HTTP services using `httpx`
- Outputs results to customizable files
- Supports silent mode and color disabling
- Provides helpful flags for assistance, version info, and tool listing

---

## Requirements

Make sure the following tools are installed and accessible in your system `PATH`:

- `subfinder`
- `assetfinder`
- `knock`
- `findomain`
- `subenum`
- `httpx`
- `jq`
- `curl`

---

## Installation

1. Install all dependencies above.
2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/subnaut.git
   cd subnaut
   ```
3. Make the script executable:
   ```bash
   chmod +x subnaut.sh
   ```
4. Add to PATH:
   ```bash
   sudo ln -s $(pwd)/subnaut.sh /usr/local/bin/subnaut
   ```

---

## Usage

```bash
./subnaut.sh [flags]
```
### Input Flags:
- `-d, --domain <domain>` : Target domain for enumeration
- `-D, --domains <file>` : File containing list of domains
- `--api <API key>` : VirusTotal API key (optional)
### Filtering Flags:
- `-t, --tools [tool1,tool2,...]` : Specify which tools to use (default: all)
- `-f, --filter [tool1,tool2,...]` : Exclude specific tools from enumeration
### Output Flags:
- `-o, --output <file>` : Output file name (default: subdomains.txt)
- `--no-httpx` : Skip active probing with httpx
### Debug & Help Flags:
- `-h, --help` : Show help message and exit
- `-v, --version` : Show version information
- `-ls, --list-sources` : List all supported subdomain sources
- `-s, --silent` : Silent mode - only outputs subdomains without extra logs
- `-nc, --no-color` : Disable colored output
  
---

## Examples
- Run enumeration on a single domain with VirusTotal API key:
```bash
./subnaut.sh -d example.com --api YOUR_VIRUSTOTAL_API_KEY -o results.txt
```

- Run enumeration on multiple domains from a file, using only `subfinder` and `findomain`, and skip httpx probing:
```bash
./subnaut.sh -D domains.txt -t subfinder,findomain --no-httpx -s
```

---

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests for improvements or bug fixes.

---

## License
This project is licensed under the [MIT License](https://github.com/barakota15/DETS-Correction-System/blob/main/LICENSE). See the `LICENSE` file for details.

---

## Author
SubNaut by Barakota15 — version 1.1
