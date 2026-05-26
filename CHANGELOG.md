# Changelog

All notable changes to **BOLA Strike Enterprise** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [12.0.0] — 2026-05-20 — God-Level Convergence

### Added
- **Unified Command Center** — Single-pane orchestration dashboard aggregating all 11 prior phases into a real-time operational view.
- **Autonomous Attack Campaigns** — End-to-end attack chain generation: discovery → fuzzing → exploitation → evidence collection → remediation → verification, with zero human intervention.
- **Adaptive Threat Modeling** — Continuous STRIDE/DREAD recalculation as new endpoints are discovered mid-scan.
- **Multi-Tenant SaaS Mode** — Fully isolated tenant workspaces with per-tenant encryption keys, RBAC policies, and billing meters.
- **Compliance-as-Code Profiles** — Pre-built audit profiles for OSFI B-13, SOC 2 Type II, PCI DSS 4.0, HIPAA, and NIST 800-53 Rev 5.
- **Executive Risk Dashboards** — Board-ready visualizations: annualized loss expectancy trends, risk heat maps, and remediation velocity KPIs.

### Changed
- Consolidated all CLI entry points into a unified `bola-strike` command with subcommands (`scan`, `report`, `deploy`, `heal`).
- Upgraded Python runtime baseline to 3.12 for performance gains and `asyncio` task groups.
- Migrated frontend from Create React App remnants to Vite 6 with React 19 and Server Components.

### Fixed
- Race condition in concurrent GraphQL subscription fuzzing causing duplicate findings.
- Memory leak in eBPF map cleanup when kernel version < 6.1.
- PDF report renderer crash on non-Latin UTF-8 characters in endpoint paths.

### Security
- Enforced FIPS 140-3 validated cryptographic modules for all at-rest and in-transit encryption.
- Added SBOM (Software Bill of Materials) generation in CycloneDX and SPDX formats.

---

## [11.0.0] — 2026-03-10 — Platform Hardening

### Added
- **Supply Chain Security Gate** — SLSA Level 3 provenance attestations for all container images and release artifacts.
- **Signed Releases** — Sigstore/cosign integration for tamper-evident release binaries and Helm charts.
- **Runtime Integrity Monitoring** — Continuous binary attestation verification using in-toto framework.
- **Chaos Engineering Module** — Controlled fault injection (latency, packet loss, service kill) to validate resilience of remediation workflows.

### Changed
- Hardened all Docker images: distroless base, non-root user, read-only filesystem, no shell.
- Replaced `requests` with `httpx` across entire backend for HTTP/2 and async-first networking.
- Upgraded Helm chart to v2 API with JSON Schema validation for `values.yaml`.

### Fixed
- TLS certificate rotation in service mesh sidecar causing 5-second scan interruptions.
- Prometheus metric cardinality explosion when scanning APIs with >10,000 path parameters.

### Deprecated
- Legacy XML report format. Use SARIF or CycloneDX instead (removal in v13.0).

---

## [10.0.0] — 2026-01-15 — Quantum Ledger Audit

### Added
- **Post-Quantum Cryptographic Ledger** — Immutable audit trail using CRYSTALS-Dilithium signatures and Kyber-1024 key encapsulation.
- **Tamper-Evident Evidence Chain** — Every finding, remediation action, and policy decision is hash-chained with Merkle tree verification.
- **Regulatory Evidence Export** — One-click export of cryptographically signed audit bundles for regulators (OSFI, OCC, FCA).
- **Long-Term Archive** — Evidence packages sealed with hybrid RSA-4096 + Dilithium for 25-year cryptographic validity.

### Changed
- Migrated secrets management from environment variables to HashiCorp Vault with dynamic credentials.
- Evidence storage backend now supports S3, GCS, Azure Blob, and MinIO with client-side encryption.

### Fixed
- Clock drift compensation in distributed scan coordinators causing evidence timestamp inconsistencies.
- Duplicate finding deduplication failing on GraphQL alias permutations.

---

## [9.0.0] — 2025-11-01 — eBPF Kernel Healer

### Added
- **eBPF/XDP Packet Filter** — Kernel-level request interception dropping malicious BOLA exploit patterns at line rate (< 1 μs latency).
- **Automatic Kernel Patch Loader** — Dynamically compiles and loads eBPF programs matching discovered vulnerability signatures.
- **Live Attack Containment** — Real-time connection termination for active IDOR exploitation attempts without impacting legitimate traffic.
- **Kernel Telemetry Pipeline** — eBPF ring buffer → Prometheus → Grafana for sub-millisecond observability of blocked attacks.

### Changed
- Minimum Linux kernel version raised to 5.15 for BTF (BPF Type Format) support.
- Replaced user-space packet inspection with XDP hooks for 40x throughput improvement.

### Fixed
- False positive in stateful fuzzing when APIs return identical response bodies for different object IDs.
- Helm chart `securityContext` missing `NET_ADMIN` capability required for eBPF attachment.

---

## [8.0.0] — 2025-08-20 — Kubernetes Orchestration

### Added
- **Helm Chart** — Production-ready Helm chart with configurable replicas, resource limits, HPA, PDB, and network policies.
- **CronJob Scanner** — Scheduled Kubernetes CronJobs for continuous compliance scanning of all in-cluster APIs.
- **Sidecar Injection** — Automatic sidecar injection via MutatingAdmissionWebhook for transparent API traffic interception.
- **Multi-Cluster Federation** — Centralized scan coordination across multiple Kubernetes clusters via gRPC control plane.
- **Pod Security Standards** — Enforced `restricted` PSS profile; all pods run as non-root with read-only root filesystem.

### Changed
- Backend refactored to async-first architecture using `asyncio` + `uvloop` for 3x scan throughput.
- Container images reduced from 1.2 GB to 89 MB using multi-stage builds and Alpine base.

### Fixed
- Scan job OOMKilled on APIs with >5,000 endpoints. Implemented streaming endpoint processing.
- Service account token auto-mount disabled by default for least-privilege compliance.

---

## [7.0.0] — 2025-06-10 — FAIR Financial Telemetry

### Added
- **FAIR Risk Engine** — Full Factor Analysis of Information Risk (FAIR) quantification: Annualized Loss Expectancy (ALE), Single Loss Expectancy (SLE), and Loss Event Frequency (LEF).
- **Currency-Aware Reporting** — Financial impact calculated in CAD, USD, EUR, and GBP with real-time exchange rate integration.
- **CI/CD Risk Gate** — Configurable pipeline gate: block deployments when estimated annual risk exceeds a defined threshold (e.g., `--max-ale 50000`).
- **SIEM Integration** — Structured event export in ArcSight CEF, Splunk HEC, and Elastic Common Schema (ECS) formats.
- **Executive PDF Reports** — Auto-generated C-suite reports with risk trends, cost projections, and remediation ROI analysis.

### Changed
- Finding severity model migrated from qualitative (Low/Med/High/Critical) to quantitative (dollar-denominated risk).
- Report template engine replaced with Jinja2 for full customization support.

### Fixed
- Incorrect CVSS temporal score calculation when exploit maturity data was unavailable.
- PDF generation failing silently on systems without `wkhtmltopdf` — now falls back to `weasyprint`.

---

## [6.0.0] — 2025-04-01 — LLM-Powered AI Fuzzing

### Added
- **Generative AI Payloads** — GPT-4 / Claude integration for context-aware, semantically valid fuzz payload generation.
- **Schema-Aware Mutation** — LLM reads OpenAPI/GraphQL schemas and generates type-correct but boundary-violating payloads.
- **Natural Language Attack Plans** — Describe an attack in plain English (e.g., "try to access another user's invoice") and the AI translates it into a multi-step exploit chain.
- **AI-Assisted Triage** — Automatic false-positive filtering using LLM-based response semantic analysis.
- **Prompt Injection Scanner** — Detects prompt injection vulnerabilities in LLM-backed API endpoints.

### Changed
- Default payload generation strategy switched from random to AI-guided (fallback to random if no API key configured).
- CLI flag `--enable-ai` added; AI features are opt-in to respect air-gapped environments.

### Fixed
- Unicode normalization bypass in WAF evasion module not handling supplementary plane characters.
- Rate limiter not respecting `Retry-After` headers from target APIs.

---

## [5.0.0] — 2025-01-20 — Service Mesh Integration

### Added
- **Envoy/Istio Sidecar Support** — Direct integration with service mesh data planes for authenticated inter-service fuzzing.
- **mTLS Passthrough** — Automatic client certificate provisioning from mesh CA for mutual TLS handshakes.
- **Traffic Mirroring** — Non-intrusive scan mode using Istio traffic mirroring; zero impact on production traffic.
- **Service Dependency Graph** — Auto-discovery of upstream/downstream service relationships from mesh control plane.
- **Canary Analysis** — Compare BOLA vulnerability surface between canary and stable deployments.

### Changed
- Network layer refactored to support both direct HTTP and mesh-proxied connections transparently.
- Configuration format migrated from flat YAML to hierarchical `config.yaml` with JSON Schema validation.

### Fixed
- Connection pool exhaustion when scanning >200 endpoints concurrently through Envoy proxy.
- gRPC reflection-based endpoint discovery missing streaming RPC methods.

---

## [4.0.0] — 2024-10-15 — WAF Evasion & Reporting

### Added
- **WAF Evasion Engine** — Multi-layer encoding bypass: double URL encoding, Unicode homoglyphs, case randomization, chunked transfer, and HTTP/2 pseudo-header manipulation.
- **Evasion Profiles** — Pre-configured profiles for Cloudflare, AWS WAF, Akamai, Azure Front Door, and ModSecurity CRS.
- **SARIF Report Export** — Static Analysis Results Interchange Format output for GitHub Advanced Security and Azure DevOps integration.
- **HTML Evidence Report** — Interactive single-file HTML report with request/response diffs, timeline visualization, and executive summary.
- **Slack/Teams Notifications** — Real-time alerting to collaboration platforms on critical findings.

### Changed
- Request engine now supports HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) protocols.
- Evasion level configurable via `--evasion-level` flag: `none`, `moderate`, `aggressive`.

### Fixed
- Cookie jar not persisting `Set-Cookie` headers across stateful multi-step scan sequences.
- Race condition in parallel scan workers causing duplicate finding entries in the report.

---

## [3.0.0] — 2024-08-01 — JWT Security Module

### Added
- **JWT Cracker** — Brute-force and dictionary attacks against HS256/HS384/HS512 symmetric keys.
- **Algorithm Confusion Attack** — Automated RS256 → HS256 algorithm substitution exploit.
- **Claim Manipulation** — Systematic fuzzing of `sub`, `role`, `aud`, `iss`, and custom claims to test authorization boundaries.
- **JWK/JWKS Poisoning** — Injection of attacker-controlled public keys via `jku` and `x5u` header parameters.
- **Token Replay Detection** — Validates whether APIs enforce `jti` (JWT ID) uniqueness and `exp` expiration.

### Changed
- Authentication module refactored to support Bearer tokens, API keys, OAuth 2.0 client credentials, and session cookies.
- Token extraction now auto-detects JWT in `Authorization`, `Cookie`, and custom headers.

### Fixed
- Base64url padding handling for malformed JWT segments causing silent scan failures.
- `--depth` parameter not respected in nested object traversal for BOLA path enumeration.

---

## [2.0.0] — 2024-05-15 — GraphQL Support

### Added
- **GraphQL Introspection Fuzzer** — Automatic schema extraction and mutation/query generation for BOLA testing.
- **Nested Query Depth Attack** — Recursive query generation to test authorization at every resolver depth level.
- **Batch Query Exploitation** — Multiplexed queries testing cross-object access within a single GraphQL request.
- **Alias-Based Enumeration** — Uses GraphQL aliases to test multiple object IDs in a single query without triggering rate limits.
- **Subscription Fuzzing** — WebSocket-based subscription interception for real-time data stream authorization testing.

### Changed
- Core engine abstracted to support both REST and GraphQL API paradigms through a unified `Target` interface.
- OpenAPI parser upgraded to support OpenAPI 3.1.0 with JSON Schema 2020-12 vocabularies.

### Fixed
- False negatives when APIs return identical HTTP 200 responses for both authorized and unauthorized requests (now uses response body diffing).
- Scan progress bar rendering incorrectly in non-TTY environments (CI/CD pipelines).

---

## [1.0.0] — 2024-02-01 — Core BOLA Fuzzer

### Added
- **OpenAPI/Swagger Parser** — Automatic endpoint discovery from OpenAPI 2.0 and 3.0 specification files.
- **BOLA/IDOR Detection Engine** — Cross-user object ID substitution with configurable ID patterns (integer, UUID, slug).
- **Multi-Method Fuzzing** — Support for GET, POST, PUT, PATCH, and DELETE HTTP methods.
- **Stateful Scan Sequences** — Multi-step authentication → action → verification workflows for realistic attack simulation.
- **Evidence Collection** — Full HTTP request/response capture with timestamps for forensic review.
- **CLI Interface** — `bola_strike.py` with `--target`, `--method`, `--depth`, and `--output` flags.
- **JSON Report Output** — Machine-readable findings export with severity ratings and reproduction steps.
- **Rate Limiting** — Configurable requests-per-second throttling to avoid overwhelming target APIs.
- **Proxy Support** — HTTP/SOCKS5 proxy routing for testing through network inspection tools (Burp Suite, mitmproxy).

### Security
- All credentials handled via environment variables; no hardcoded secrets.
- TLS certificate verification enabled by default with opt-out flag for development environments.

---

[12.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v11.0.0...v12.0.0
[11.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v10.0.0...v11.0.0
[10.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v9.0.0...v10.0.0
[9.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v8.0.0...v9.0.0
[8.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v7.0.0...v8.0.0
[7.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v6.0.0...v7.0.0
[6.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v5.0.0...v6.0.0
[5.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v4.0.0...v5.0.0
[4.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/nicolasferrer/bola-strike-enterprise/releases/tag/v1.0.0
