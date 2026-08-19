# Security Policy

Passman is a local-only password manager: there is no server component, and vaults never leave the user's devices except over the LAN sync described in the [security model](docs/security-model.md). Vulnerabilities in the crypto, key storage, pairing, or sync layers are all in scope, including the `k2k` submodule.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Email **sterling.albury@gmail.com** with a description of the issue, the affected component, and reproduction steps if you have them. You should receive an acknowledgement within a week. Please allow a reasonable window for a fix to ship before public disclosure.

## What to expect

- The project is maintained by one person and has **not** had an independent security audit.
- Only the latest release is supported; cross-version sync is explicitly unsupported.
- Known, accepted limits (for example, the RSA-2048 transport identity) are documented in the [security model](docs/security-model.md) — reports about documented accepted risks are still welcome if they change the practical picture.
