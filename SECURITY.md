# Security Policy

## Scope

This tool is built to test **OWASP Juice Shop**, a deliberately vulnerable
training application, for educational and authorized-testing purposes only.

This policy covers vulnerabilities **in the tool itself** (e.g. a bug that
could make it unsafe to run, leak credentials, or behave unexpectedly
against a target). It does not cover vulnerabilities in Juice Shop itself —
those are intentional by design and documented by the
[OWASP Juice Shop project](https://github.com/juice-shop/juice-shop).

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |

## Reporting a Vulnerability

If you find a security issue in this tool itself (not in Juice Shop), please
report it privately rather than opening a public issue:

1. Open a [GitHub Security Advisory](../../security/advisories/new) on this
   repository, **or**
2. Contact the maintainer directly: [@MAliXCS](https://github.com/MAliXCS)

Please include:
- A description of the issue and its potential impact
- Steps to reproduce
- The version of the tool and your Python version

We'll acknowledge reports as quickly as possible and keep you updated as a
fix is worked on.

## Responsible Use

This tool sends real HTTP requests, including authenticated write
operations (e.g. `PUT` requests during the IDOR test), to whatever
`--target` you give it. **Only point it at OWASP Juice Shop instances you
own or have explicit written permission to test.** Misuse against
third-party infrastructure is outside the scope of what this project
supports or condones.
