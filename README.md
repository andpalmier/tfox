# tfox - ThreatFox CLI client

A command-line client for the [ThreatFox API](https://threatfox.abuse.ch/api/). It looks up indicators of compromise by value, hash, tag or malware family, and shares new ones.

> Part of the abuse.ch CLI toolkit, a set of clients for [abuse.ch](https://abuse.ch) services:
> - [urlhs](https://github.com/andpalmier/urlhs) for URLhaus, the malware URL database
> - [tfox](https://github.com/andpalmier/tfox) for ThreatFox, the IOC database
> - [yrfy](https://github.com/andpalmier/yrfy) for YARAify, YARA scanning
> - [mbzr](https://github.com/andpalmier/mbzr) for MalwareBazaar, malware samples

[![Go Report Card](https://goreportcard.com/badge/github.com/andpalmier/tfox)](https://goreportcard.com/report/github.com/andpalmier/tfox)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Features

- Built on the Go standard library, with no third party dependencies
- Prints JSON, so you can pipe it into jq or anything else
- Rate limits itself to 10 requests per second
- Runs under Docker, Podman, and Apple container

## Installation

### Homebrew

```bash
brew install --cask andpalmier/tap/tfox
```

Homebrew casks are macOS only. On Linux, use `go install` or a pre-built binary.

### Go

```bash
go install github.com/andpalmier/tfox@latest
```

### Container

```bash
# Pull the pre-built image
docker pull ghcr.io/andpalmier/tfox:latest

# Or build it yourself
docker build -t tfox .
```

### From source

```bash
git clone https://github.com/andpalmier/tfox.git
cd tfox
make build
```

## Quick start

Get an API key from the [abuse.ch Authentication Portal](https://auth.abuse.ch/), export it, then query something:

```bash
export ABUSECH_API_KEY="your_api_key_here"
tfox recent -days 3
```

Every command reads the key from `ABUSECH_API_KEY`. When a query fails, tfox prints the explanation ThreatFox itself returned, so you get "The IOC id you have provided is unknown" rather than a bare status code.

ThreatFox expires indicators after six months. Anything older is still visible in the web interface but no longer served by the API.

## Usage

### Global flags

These go before the command name.

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Print what the client is doing |
| `-t`, `--timeout` | Timeout per request, as a duration such as `45s` or `2m` (default `30s`) |
| `-V`, `--version` | Print version information |
| `-h`, `--help` | Print help |

### Commands

| Command | Description |
|---------|-------------|
| `recent` | List recent IOCs, up to seven days back |
| `query` | Look up by IOC id, tag, malware family, or malware label |
| `search` | Search by IOC value or file hash |
| `submit` | Share indicators of compromise |
| `list` | List malware families, IOC and threat types, or tags |
| `version` | Print version information |

### Recent IOCs

```bash
# The last three days
tfox recent -days 3

# The most the API allows
tfox recent -days 7
```

### Looking things up

```bash
# By the ThreatFox database id
tfox query -id 1901292

# By tag
tfox query -tag Emotet -limit 10

# By malware family
tfox query -malware "Cobalt Strike" -limit 10

# Resolve a malware name to its Malpedia label
tfox query -label warzone -platform win
```

### Searching

```bash
# By IOC value, matching substrings
tfox search -ioc suspicious.com

# Only exact matches
tfox search -ioc evil.com -exact

# By file hash, MD5 or SHA256
tfox search -hash <md5_or_sha256_hash>
```

### Reference data

Use these to find the values `submit` expects.

```bash
tfox list -malware    # malware families
tfox list -types      # IOC and threat types
tfox list -tags       # known tags
```

### Sharing IOCs

Submit only confirmed, vetted indicators. Repeated policy violations can get your account banned from contributing.

```bash
tfox submit -threat_type botnet_cc -ioc_type domain \
  -malware win.zloader \
  -ioc evil.example \
  -ioc worse.example \
  -confidence 75 \
  -reference https://example.org/report \
  -tags TA505 \
  -comment "seen in a Zloader campaign"
```

`-ioc` can be repeated to send several indicators in one submission. Take `-threat_type` and `-ioc_type` from `tfox list -types`, and `-malware` from `tfox list -malware`. Confidence runs from 0 to 100 and the API defaults it to 50. Add `-compromised` when the asset belongs to a victim rather than the attacker, and `-anonymous` to submit without attribution.

### Running in a container

```bash
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/tfox recent -days 3

podman run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/tfox recent -days 3

container run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/tfox recent -days 3
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `ABUSECH_API_KEY` | Your abuse.ch API key. Required. |

## License

Licensed under the AGPLv3. See [LICENSE](LICENSE) for the full text.

## Acknowledgments

- [ThreatFox](https://threatfox.abuse.ch) by abuse.ch
- [abuse.ch](https://abuse.ch) for their work against malware
