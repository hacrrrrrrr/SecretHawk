# 🦅 SecretHawk

Fast, extensible secret scanning for source trees and Git repositories.

> Find exposed credentials before they become incidents.

## Features

- Regex-based secret detection
- Recursive filesystem scanning
- Git-aware directory handling
- Secret redaction
- JSON and terminal output
- Severity and confidence scoring
- Go API under `pkg/`
- CI-friendly `--fail-on-secret`

## Project layout

```
cmd/          CLI
internal/     scanner implementation
pkg/          public Go API
assets/       bundled/static assets
docs/         architecture and security documentation
examples/     safe usage examples
proto/        future service/API definitions
scripts/      build and test helpers
```

## Quick start

```bash
go run ./cmd/secrethawk scan .
go run ./cmd/secrethawk scan . --format json
go run ./cmd/secrethawk scan . --fail-on-secret
```

Build with:

```bash
make build
```

Test with:

```bash
make test
make vet
```

## Roadmap

- Git history scanning
- Entropy-assisted detection
- SARIF output
- Configurable detector packs
- Baselines and allowlists
- Parallel scanning and incremental cache
- Fuzzing and benchmarks
- Optional service/API layer

## Security

Use SecretHawk only on repositories and systems you are authorized to inspect. Detected credentials are not contacted or validated by default.

See [docs/threat-model.md](docs/threat-model.md).

## License

Apache-2.0
