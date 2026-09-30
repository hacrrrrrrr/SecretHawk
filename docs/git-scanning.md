# Git Scanning

SecretHawk can scan a local Git repository or clone a public/authorized Git URL into a temporary directory.

## Local repository

`secrethawk git ./my-repository`

## Remote repository

`secrethawk git https://github.com/example/project.git`

The remote repository is cloned using the local Git executable. The temporary checkout is removed after the scan.

## History

Add `--history` to inspect commit diffs:

`secrethawk git ./my-repository --history`

History findings are redacted and associated with their commit identifier.

## Authentication

SecretHawk does not ask for or transmit GitHub credentials. For private repositories, configure your normal Git credential helper or SSH setup before invoking SecretHawk.

Only scan repositories you are authorized to inspect.
