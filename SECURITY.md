# Security Policy

## Supported versions

SecretHawk is an actively developed security research and defensive scanning project.

Because development is currently rapid, security fixes should be reported against the latest commit on the default branch whenever possible.

## Reporting a vulnerability

If you discover a security issue in SecretHawk itself, please report it privately rather than opening a public issue with exploit details.

**Security contact:** hunterkritik@gmail.com

When reporting, please include:

- a clear description of the issue;
- affected component or file;
- reproducible steps or a minimal proof of concept;
- expected behavior;
- observed behavior;
- affected version or commit;
- relevant logs or stack traces with sensitive values removed.

Please **do not include live API keys, passwords, access tokens, private keys, or other credentials** in reports.

## Secret exposure reports

If SecretHawk identifies a credential belonging to a real organization or service, do not use, test, or attempt to authenticate with that credential unless you have explicit authorization.

Instead:

1. Preserve only the minimum information needed to establish the finding.
2. Redact the credential.
3. Notify the appropriate repository owner or security contact.
4. Follow the affected organization's responsible-disclosure process.

## Safe research

SecretHawk is intended for authorized defensive security work.

The project does not require contacting third-party services to perform normal scanning. Users are responsible for ensuring that their scanning activity is authorized.

## Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability in the SecretHawk project.

Coordinated disclosure is preferred where practical.

## Contact

For vulnerability reports, sponsorship, collaboration, and security research inquiries:

**hunterkritik@gmail.com**
