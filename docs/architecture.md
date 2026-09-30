# SecretHawk Architecture

SecretHawk is organized around a small scanning pipeline:

1. **CLI** parses commands and output options.
2. **Scanner** walks authorized source trees and streams text files.
3. **Detectors** identify provider-specific and generic secret patterns.
4. **Model** normalizes findings.
5. **Output** renders terminal or JSON results.

## Design goals

- Keep detectors independent and testable.
- Never print complete detected credentials.
- Avoid network validation by default.
- Make CI integration deterministic.
- Keep public APIs small while allowing internal implementation changes.

## Planned pipeline

`filesystem -> git/history -> normalization -> detectors -> scoring -> deduplication -> output`

Future releases will add Git history scanning, entropy scoring, SARIF, baselines and configurable detector packs.
