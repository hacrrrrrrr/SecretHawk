# Configuration

SecretHawk accepts a JSON configuration file through `--config`. If omitted, `.secrethawk.json` in the current working directory is used when present.

Example:

```json
{
  "workers": 4,
  "max_file_size": 10485760,
  "confidence_threshold": 70,
  "ignore_paths": ["**/.cache/**", "**/coverage/**"],
  "ignore_extensions": [".lock"],
  "detector_packs": ["examples/detector-pack.json"],
  "disabled_detectors": ["generic-secret"],
  "entropy_threshold": 4.2,
  "cache_file": ".secrethawk-cache.json",
  "baseline_file": ".secrethawk-baseline.json"
}
```

## Fields

- `workers`: number of concurrent file workers. Zero uses CPU count.
- `max_file_size`: maximum file size in bytes.
- `confidence_threshold`: suppress findings below this confidence.
- `ignore_paths`: path patterns to skip.
- `ignore_extensions`: extensions to skip.
- `detector_packs`: JSON detector-pack files.
- `disabled_detectors`: built-in or pack detector names to disable.
- `entropy_threshold`: Shannon entropy threshold for secret-like assignments.
- `cache_file`: incremental scan cache location.
- `baseline_file`: known-finding suppression file.

## Baselines

Generate a baseline from the current result set:

```bash
secrethawk scan . --update-baseline --baseline .secrethawk-baseline.json
```

Then future scans suppress matching fingerprints:

```bash
secrethawk scan . --baseline .secrethawk-baseline.json --fail-on-secret
```

Baselines should be reviewed and committed deliberately. They contain detector/path metadata and fingerprints, not full secret values.

## Cache

The incremental cache stores file metadata and findings locally. Disable it with `--no-cache`. Cache files should normally remain outside source control.

Configuration files and baselines should never contain real production credentials. Use synthetic test values in examples.
