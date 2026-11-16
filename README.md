# tfox

CLI for the [ThreatFox API](https://threatfox.abuse.ch/api/). Look up indicators of compromise, submit new ones, and download bulk exports.

[![CI](https://github.com/andpalmier/tfox/actions/workflows/ci.yml/badge.svg)](https://github.com/andpalmier/tfox/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Install

```bash
brew install --cask andpalmier/tap/tfox
go install github.com/andpalmier/tfox@latest
docker pull ghcr.io/andpalmier/tfox:latest
```

Homebrew works on macOS only. On Linux, use Go or a release binary.

## Quick start

```bash
export ABUSECH_API_KEY="your_api_key_here"
tfox recent -days 3
```

Every command needs `ABUSECH_API_KEY`. tfox prints API errors as received.

## Commands

- `recent`: list recent indicators, up to seven days back.
- `query`: look up by IOC id, tag, malware family, or malware label.
- `search`: search by IOC value or file hash.
- `submit`: share indicators of compromise.
- `list`: list malware families, IOC types, threat types, or tags.
- `export`: download a bulk export.
- `version`: print version information.

## Examples

```bash
tfox recent -days 7
tfox query -tag Emotet -limit 10
tfox query -malware "Cobalt Strike" -limit 10
tfox search -ioc evil.com -exact
tfox list -types
tfox list -malware
tfox submit -threat_type botnet_cc -ioc_type domain -malware win.zloader -ioc evil.example -confidence 75 -reference https://example.org/report -tags TA505
tfox -t 5m export -file full.json.zip -out /tmp/threatfox.json.zip
```

## Notes

- ThreatFox expires indicators after six months.
- Submit only confirmed indicators. Repeated violations can ban your account.
- `-ioc` can be repeated in one submission.
- Use `tfox list -types` and `tfox list -malware` to find valid submit values.
- Exports rebuild every five minutes. Large exports need a longer `-t` timeout.

## Container

```bash
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/tfox recent -days 3
docker run --rm -e ABUSECH_API_KEY="your_key" -v "$PWD":/data ghcr.io/andpalmier/tfox export -file recent.csv -out /data/recent.csv
```

## License

AGPLv3. See [LICENSE](LICENSE).
