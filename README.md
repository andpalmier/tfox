# tfox - ThreatFox CLI Client

A command-line tool for interacting with the [ThreatFox API](https://threatfox.abuse.ch/api/).

> **Part of the abuse.ch CLI toolkit** - This project is part of a collection of CLI tools for interacting with [abuse.ch](https://abuse.ch) services:
> - [urlhs](https://github.com/andpalmier/urlhs) - URLhaus (malware URL database)
> - [tfox](https://github.com/andpalmier/tfox) - ThreatFox (IOC database)
> - [yrfy](https://github.com/andpalmier/yrfy) - YARAify (YARA scanning)
> - [mbzr](https://github.com/andpalmier/mbzr) - MalwareBazaar (malware samples)

[![Go Report Card](https://goreportcard.com/badge/github.com/andpalmier/tfox)](https://goreportcard.com/report/github.com/andpalmier/tfox)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Features

- ✅ Uses only Go standard libraries
- 📝 JSON output for easy parsing
- ⚡️ Built-in rate limiting (10 req/s)
- 🐳 Docker, Podman, and Apple container support

## Installation

### Using Homebrew

```bash
brew install andpalmier/tap/tfox
```

### Using Go

```bash
go install github.com/andpalmier/tfox@latest
```

### Using Container (Docker/Podman)

```bash
# Pull pre-built image
docker pull ghcr.io/andpalmier/tfox:latest

# Or build locally
docker build -t tfox .
```

### From Source

```bash
git clone https://github.com/andpalmier/tfox.git
cd tfox
make build
```

## Quick Start

1. **Get your API key** from [abuse.ch Authentication Portal](https://auth.abuse.ch/)

2. **Set your API key**:

```bash
export ABUSECH_API_KEY="your_api_key_here"
```

3. **Query recent IOCs**:

```bash
tfox recent -days 3
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `recent` | Query recent IOCs (max 7 days) |
| `query` | Query by IOC ID, tag, malware, or label |
| `search` | Search IOCs by term or file hash |
| `list` | List malware families, types, or tags |
| `version` | Show version information |

### Query Recent IOCs

```bash
# IOCs from last 3 days
tfox recent -days 3

# IOCs from last 7 days
tfox recent -days 7
```

### Query by Criteria

```bash
# By IOC ID
tfox query -id 41

# By tag
tfox query -tag Emotet -limit 10

# By malware family
tfox query -malware "Cobalt Strike" -limit 10

# Identify malware label
tfox query -label warzone -platform win
```

### Search IOCs

```bash
# Search by IOC value
tfox search -ioc 94.103.84.81

# Exact match
tfox search -ioc evil.com -exact

# Search by file hash
tfox search -hash 2151c4b970eff0071948dbbc19066aa4
```

### List Data

```bash
tfox list -malware    # Malware families
tfox list -types      # IOC/threat types
tfox list -tags       # Known tags
```

### Container Usage

```bash
# Run with Docker
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/tfox recent -days 3

# Run with Podman
podman run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/tfox recent -days 3

# Run with Apple container
container run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/tfox recent -days 3
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ABUSECH_API_KEY` | Your abuse.ch API key (required) |

## License

This project is licensed under the AGPLv3 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [ThreatFox](https://threatfox.abuse.ch) by abuse.ch
- [abuse.ch](https://abuse.ch) for their work in fighting malware
