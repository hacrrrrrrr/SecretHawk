# Threat Model

SecretHawk is a defensive source-scanning tool.

## In scope

- accidental credential exposure in authorized source trees;
- secrets committed to Git repositories;
- developer and CI workflows that need deterministic findings.

## Out of scope

- credential theft;
- unauthorized repository access;
- automatic credential use or exploitation.

SecretHawk does not validate credentials against external services by default and redacts matches in normal output.
