# Security Policy

## Reporting a Vulnerability

The BOLA Strike Enterprise team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contribution.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report vulnerabilities through one of the following channels:

| Channel | Contact |
|---|---|
| **Email** | [security@nicolasferrer.dev](mailto:security@nicolasferrer.dev) |
| **GitHub Security Advisories** | [Report a vulnerability](../../security/advisories/new) |

### PGP Encryption

For sensitive disclosures, you may encrypt your report using our PGP public key:

- **Key ID:** `0xB0LA5TR1K3SEC0PS`
- **Fingerprint:** `E4F2 9A1B 7C3D 8E5F 6A0B  1D2C 3E4F 5A6B 7C8D 9E0F`
- **Public Key:** Available at [keys.openpgp.org](https://keys.openpgp.org) or in the `docs/pgp/` directory of this repository.

We strongly recommend encrypting any report that contains proof-of-concept exploit code, credentials, or personally identifiable information.

---

## Coordinated Disclosure Timeline

We follow a **90-day coordinated disclosure** policy aligned with industry standards (Google Project Zero, CERT/CC):

| Day | Milestone |
|---|---|
| **Day 0** | Vulnerability report received. |
| **Day 1** | Acknowledgement sent to reporter with a tracking ID. |
| **Day 7** | Initial triage and severity assessment completed (CVSS v3.1). |
| **Day 14** | Reporter receives a detailed status update with remediation plan. |
| **Day 30** | Target date for patch development and internal validation. |
| **Day 60** | Patch released in a security advisory (if applicable). |
| **Day 90** | Full public disclosure. Reporter credited (unless anonymity requested). |

If a fix requires more than 90 days due to exceptional complexity, we will negotiate an extension in good faith with the reporter. Critical vulnerabilities affecting production deployments will be fast-tracked with an expedited SLA of **≤ 7 days**.

---

## Scope

### In Scope

The following components are covered by this security policy:

- **Core Fuzzer Engine** — `bola_strike.py`, `cli_runner.py`, and all modules under `backend/app/`
- **Frontend Dashboard** — React/TypeScript application under `frontend/src/`
- **Docker & Kubernetes Manifests** — `docker-compose.yml`, Helm charts, and all IaC templates
- **CI/CD Pipelines** — GitHub Actions workflows under `.github/workflows/`
- **API Endpoints** — All REST and GraphQL endpoints exposed by the backend service
- **Authentication & Authorization** — JWT issuance, validation, RBAC enforcement, and Zero Trust token handling
- **Cryptographic Components** — Post-quantum ledger, HMAC signing, and key management routines
- **eBPF/XDP Programs** — Kernel-level packet filtering and auto-remediation modules

### Out of Scope

The following are explicitly excluded:

- Third-party dependencies (report these upstream; we will assist with coordination if needed)
- Social engineering attacks against maintainers or contributors
- Denial-of-service attacks against project infrastructure (GitHub, CI runners)
- Findings from automated scanners without a validated proof-of-concept
- Vulnerabilities in demo/example configurations not intended for production use

---

## Severity Classification

We use **CVSS v3.1** for severity scoring and follow the rating scale below:

| Rating | CVSS Score | Response SLA |
|---|---|---|
| **Critical** | 9.0 – 10.0 | ≤ 72 hours |
| **High** | 7.0 – 8.9 | ≤ 7 days |
| **Medium** | 4.0 – 6.9 | ≤ 30 days |
| **Low** | 0.1 – 3.9 | Next scheduled release |

---

## Supported Versions

| Version | Supported |
|---|---|
| **12.x** (current) | ✅ Full support |
| **11.x** | ✅ Security patches only |
| **10.x** | ⚠️ Critical fixes only |
| **< 10.0** | ❌ End of life |

---

## Recognition

We maintain a [SECURITY_HALL_OF_FAME.md](docs/SECURITY_HALL_OF_FAME.md) to publicly credit researchers who report valid vulnerabilities. If you prefer to remain anonymous, please indicate this in your initial report.

---

## Safe Harbor

BOLA Strike Enterprise supports safe harbor for security research conducted in good faith. We will not initiate legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, or service disruption.
- Only interact with accounts they own or with explicit permission of the account holder.
- Report vulnerabilities through the channels described above.
- Allow reasonable time for remediation before any public disclosure.

---

**Thank you for helping keep BOLA Strike Enterprise and its users safe.**
