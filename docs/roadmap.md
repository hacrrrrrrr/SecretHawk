# Roadmap

## v0.2 — shipped
- [x] Detector registry
- [x] Entropy analysis
- [x] Deduplication
- [x] SARIF output
- [x] Fuzz tests and benchmarks

## v0.3 — shipped
- [x] Git history scanning
- [x] Baselines and allowlists
- [x] Parallel worker pool
- [x] .gitignore-aware traversal
- [x] JSON configuration

## v0.4 — shipped
- [x] Detector packs
- [x] Incremental scanning cache
- [x] Better false-positive suppression
- [x] CI integration with SARIF upload
- [x] Large-repository benchmark suite
- [x] Expanded SARIF rule metadata and source locations

## Security invariant

SecretHawk intentionally keeps credential validation disabled by default. It never sends detected values to third-party services as part of normal scanning.

## Operational roadmap

Future work can focus on remote cache backends, richer GitHub/GitLab/Bitbucket annotations, signed detector packs, and additional language-aware parsers without changing the core scanning contract.
