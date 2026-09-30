# 🦅 SecretHawk

Fast, extensible secret scanning for source trees and Git repositories.

> Find exposed credentials before they become incidents.

## Features
- Regex-based secret detection
- Recursive filesystem scanning
- Git-aware directory handling
- Secret redaction in findings
- JSON and terminal output
- Severity and confidence scoring
- CI-friendly `--fail-on-secret` mode

## Quick start
```bash
go run ./cmd/secrethawk scan .
go run ./cmd/secrethawk scan . --format json
go run ./cmd/secrethawk scan . --fail-on-secret
```

## Roadmap
- Git history scanning
- SARIF output
- Configurable detector packs
- Baselines and allowlists
- Parallel scanning and incremental cache
- Detector fuzzing and benchmarks

## Security
Use SecretHawk only on repositories and systems you are authorized to inspect. Detected credentials are not contacted or validated by default.

## License
Apache-2.0