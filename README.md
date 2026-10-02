# 🦅 SecretHawk

**Sponsorship & inquiries:** **hunterkritik@gmail.com**

Fast, extensible secret scanning for source trees and Git repositories.

> Find exposed credentials before they become incidents.

[![CI](https://github.com/hacrrrrrrr/SecretHawk/actions/workflows/ci.yml/badge.svg)](https://github.com/hacrrrrrrr/SecretHawk/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

---

## Overview

SecretHawk is a defensive secret-scanning toolkit designed to help developers and security teams identify accidentally exposed credentials in source code and repositories.

It is designed around a simple principle:

**detect early, redact safely, and make findings useful.**

SecretHawk does not contact external services or attempt to validate discovered credentials by default.

## Highlights

- 🔎 Recursive source-tree scanning
- 🔐 Provider-specific secret detectors
- 🧬 Entropy-analysis primitives
- 🧹 Finding deduplication
- 🎭 Redacted findings
- 📊 Severity and confidence metadata
- 📄 Terminal and JSON output
- 🛡️ SARIF output with locations
- 🚦 CI-friendly failure mode
- 🧪 Unit tests, fuzz tests and benchmarks
- 📦 Public Go API
- 🧩 Extensible architecture

## Installation

### From source

Requirements:

- Go 1.23+
- Git (required for `secrethawk git`)

Clone and build:

```bash
git clone https://github.com/hacrrrrrrr/SecretHawk.git
cd SecretHawk
go build -o secrethawk ./cmd/secrethawk
```

Install into your Go binary directory:

```bash
go install github.com/hacrrrrrrr/SecretHawk/cmd/secrethawk@latest
```

### Roadmap features

```bash
secrethawk scan . --config .secrethawk.json --baseline .secrethawk-baseline.json --fail-on-secret
secrethawk scan . --update-baseline --baseline .secrethawk-baseline.json
```

Then verify:

```bash
secrethawk version
secrethawk --help
```

### Download a release

When release binaries are published, download the archive for your operating system and architecture from the project's **Releases** page, extract it, and place the `secrethawk` binary somewhere on your `PATH`.

## Usage

### Scan a directory

```bash
secrethawk scan .
```

Scan a specific source tree:

```bash
secrethawk scan ./src
```

### JSON output

```bash
secrethawk scan . --format json
```

### SARIF output

```bash
secrethawk scan . --format sarif > results.sarif
```

### CI failure mode

```bash
secrethawk scan . --fail-on-secret
```

The command exits with status `1` when findings are detected.

### Scan a local Git repository

```bash
secrethawk git ./my-repository
```

### Scan a public or authorized remote Git repository

```bash
secrethawk git https://github.com/owner/repository.git
```

SecretHawk uses the local Git executable to clone the repository into a temporary directory. The temporary checkout is removed after scanning.

### Scan Git history

```bash
secrethawk git ./my-repository --history
```

History scanning examines commit diffs for supported secret patterns and reports redacted findings.

### Remote private repositories

SecretHawk does not ask for or transmit GitHub credentials. Configure your normal Git credential helper or SSH authentication first, then run the Git command normally.

Only scan repositories you are authorized to access.

### Command help

```bash
secrethawk --help
secrethawk scan --help
secrethawk git --help
```


## Example finding

SecretHawk intentionally avoids printing complete credential material:

```text
[HIGH] aws-access-key (96%) config/app.env:42 AKIA••••••••••••EF
```

The exact secret value is not exposed in normal output.

## Project structure

```text
SecretHawk/
├── cmd/                 # CLI applications
├── internal/
│   ├── detector/        # Detection logic
│   ├── model/           # Finding models
│   ├── output/          # Output renderers
│   └── scanner/         # Scanning and analysis engine
├── pkg/                 # Public Go API
├── assets/              # Static/bundled assets
├── docs/                # Architecture and project documentation
├── examples/             # Safe usage examples
├── proto/               # Future API/service definitions
├── scripts/             # Build/test helpers
├── .github/workflows/   # Continuous integration
├── Makefile
└── go.mod
```

## Detection architecture

```text
Source / Repository
       │
       ▼
 File discovery
       │
       ▼
 Normalization
       │
       ▼
 Detector engine
 ┌─────┴──────────┐
 │ Regex          │
 │ Entropy        │
 │ Provider rules │
 └─────┬──────────┘
       ▼
 Deduplication
       │
       ▼
 Severity / confidence
       │
       ├── Terminal
       ├── JSON
       └── SARIF
```

## Development

Run tests:

```bash
make test
```

Run static analysis:

```bash
make vet
```

Run everything used by the local test helper:

```bash
./scripts/test.sh
```

Build an optimized binary:

```bash
./scripts/build.sh
```

## Security model

SecretHawk is intended for systems and repositories you are authorized to inspect.

By design:

- detected values are redacted in normal output;
- credentials are not transmitted to third-party services;
- credential validation is disabled by default;
- examples use synthetic values;
- security reports should avoid including live credentials.

See **[SECURITY.md](SECURITY.md)** for reporting and responsible-disclosure guidance.

## Roadmap

### Current release: v0.4.0

### Current

- [x] Recursive filesystem scanning
- [x] Regex detectors
- [x] Secret redaction
- [x] JSON output
- [x] Entropy primitives
- [x] Deduplication
- [x] SARIF foundation
- [x] Fuzz/benchmark coverage

### v0.4 completed

- [x] Git history scanning
- [x] Baselines and allowlists
- [x] .gitignore-aware traversal
- [x] Parallel worker pool
- [x] JSON config file
- [x] Detector packs
- [x] Incremental scanning cache
- [x] Improved false-positive suppression
- [x] CI integration with SARIF upload
- [x] Large-repository benchmark suite
- [x] Expanded SARIF rules and source locations

## Sponsorship & collaboration

SecretHawk is an independent security tooling project.

For **sponsorship, collaboration, research inquiries, or project-related questions**:

**hunterkritik@gmail.com**

Please do not send real credentials or other sensitive secrets in email.

## License

SecretHawk is released under the **Apache License 2.0**.

See [LICENSE](LICENSE) for details.
