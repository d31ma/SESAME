# Security Policy

## Supported Versions

SESAME is pre-release software and makes no production-support claim yet.
Security fixes are applied to the default branch. A supported-version window
will be published before v1.0.

| Version | Security support |
| --- | --- |
| Default branch | Best effort |
| Tagged previews | No guaranteed backports |

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability.

Use the repository's
[private vulnerability reporting form](https://github.com/d31ma/sesame/security/advisories/new).
Include:

- affected version or commit;
- impact and attacker prerequisites;
- minimal reproduction or proof of concept;
- whether the issue is already public;
- suggested remediation, if known.

Do not include real credentials, personal data, production tokens, or private
keys. Maintainers will coordinate validation, remediation, disclosure, and
credit with the reporter. Please allow a reasonable remediation window before
public disclosure.

## Scope

Reports concerning authentication, authorization, tenant isolation, token or
session lifecycle, cryptography, secret exposure, SSRF, FYLO persistence,
recovery, update integrity, or SDK protocol confusion are in scope.

General support requests, deployment questions, and feature proposals belong in
the public issue tracker.
