# SecretHawk Architecture

SecretHawk uses a deterministic, local-first scanning pipeline:

```
source / repository
       |
       +--> .gitignore filtering
       |
       +--> incremental cache lookup
       |
       v
parallel file workers
       |
       +--> provider regex rules
       +--> detector packs
       +--> entropy analysis
       |
       v
confidence + placeholder suppression
       |
       +--> baseline suppression
       |
       v
deduplication
       |
       +--> text
       +--> JSON
       +--> SARIF
```

## Components

- **CLI** — command parsing, configuration, baseline/cache controls and CI exit codes.
- **Scanner** — file discovery, worker pool, size limits, cache integration and deterministic result ordering.
- **Git integration** — local/remote checkout plus commit-diff history scanning.
- **Detector registry** — built-in provider rules plus JSON detector packs.
- **Baseline** — stable fingerprints for intentionally accepted findings.
- **Cache** — file metadata and finding reuse for unchanged files.
- **Output** — redacted terminal/JSON output and SARIF 2.1.0 rule/location metadata.
- **Public API** — small Go API for embedding scans in other applications.

All detection is local by default. SecretHawk does not validate credentials against their providers.
