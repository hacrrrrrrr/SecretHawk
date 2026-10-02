# Detector Development

A detector should:

- have a stable name;
- return a severity and confidence;
- minimize false positives;
- redact sensitive material in output;
- include focused tests;
- never contact the detected service as part of normal scanning.

## Built-in rules

Provider rules live in `internal/detector/detector.go`. Placeholder suppression avoids common synthetic values such as `example`, `changeme`, `dummy` and `placeholder`.

## Detector packs

External packs are JSON files:

```json
{
  "name": "my-provider",
  "rules": [
    {
      "name": "my-token",
      "pattern": "\\bMY_[A-Z0-9]{24}\\b",
      "severity": "HIGH",
      "confidence": 92
    }
  ]
}
```

Load a pack through configuration:

```json
{
  "detector_packs": ["./detectors/my-provider.json"]
}
```

Pack regular expressions are compiled before scanning. Invalid packs fail closed rather than silently disabling detection.

## False-positive controls

Use confidence thresholds, disabled detectors, placeholder suppression, ignore paths/extensions, and baselines for known findings. Baselines suppress fingerprints; they do not expose the full secret value.
