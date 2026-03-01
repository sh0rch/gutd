# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via GitHub's
[Security Advisories](https://github.com/sh0rch/gutd/security/advisories/new)
or by emailing the maintainer directly (see the commit history for contact).

Please include:

- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- Affected versions
- Potential impact

You will receive an acknowledgement within 72 hours. A fix will be prepared
privately and released with a coordinated disclosure.

## Scope

Areas of particular concern:

- BPF program safety (verifier bypass, out-of-bounds access)
- Key handling or key material leakage
- Packet injection or decryption without a valid shared key
- Privilege escalation via the `gutd` daemon

## Out of Scope

- Attacks that require physical access to the host
- Denial of service via resource exhaustion on the host OS
- Vulnerabilities in upstream Linux kernel or WireGuard itself
