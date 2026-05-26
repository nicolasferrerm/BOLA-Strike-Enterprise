# Contributing to BOLA Strike Enterprise

First off, thank you for considering contributing to BOLA Strike Enterprise! 🎉 Every contribution makes this platform more robust and valuable for the global security community.

This document provides guidelines and best practices for contributing. Please read it carefully before submitting your first pull request.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Branching Strategy](#branching-strategy)
- [Making Changes](#making-changes)
- [Code Style](#code-style)
- [Commit Conventions](#commit-conventions)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Please report unacceptable behavior to [conduct@nicolasferrer.dev](mailto:conduct@nicolasferrer.dev).

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/bola-strike-enterprise.git
   cd bola-strike-enterprise/Tools/API_Logic_Fuzzer
   ```
3. **Add the upstream remote:**
   ```bash
   git remote add upstream https://github.com/nicolasferrer/bola-strike-enterprise.git
   ```
4. **Sync regularly** to stay up to date:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

---

## Development Setup

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | ≥ 3.10 | Backend runtime |
| Node.js | ≥ 18 LTS | Frontend build toolchain |
| Docker | ≥ 24.0 | Container builds & integration tests |
| Git | ≥ 2.40 | Version control |

### Backend Setup

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\Activate.ps1   # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Verify installation
python bola_strike.py --version
```

### Frontend Setup

```bash
cd frontend
npm ci
npm run dev
```

### Environment Variables

Copy the example environment file and configure your local secrets:

```bash
cp .env.example .env
# Edit .env with your local configuration
```

> ⚠️ **Never commit `.env` files.** They are listed in `.gitignore` for a reason.

---

## Branching Strategy

We follow a **trunk-based development** model with short-lived feature branches:

| Branch | Purpose |
|---|---|
| `main` | Production-ready code. Protected; requires PR review. |
| `feature/<ticket>-<description>` | New features (e.g., `feature/142-graphql-introspection`) |
| `fix/<ticket>-<description>` | Bug fixes (e.g., `fix/208-jwt-exp-validation`) |
| `docs/<description>` | Documentation-only changes |
| `refactor/<description>` | Code restructuring with no behavior change |
| `security/<description>` | Security patches (coordinate with maintainers first) |

### Rules

- Always branch from the latest `main`.
- Keep branches focused — one feature or fix per branch.
- Rebase (do not merge) from `main` to keep a linear history.
- Delete branches after merging.

---

## Making Changes

1. Create your feature branch:
   ```bash
   git checkout -b feature/142-graphql-introspection
   ```
2. Make your changes with clear, incremental commits.
3. Ensure all tests pass locally before pushing.
4. Push to your fork:
   ```bash
   git push origin feature/142-graphql-introspection
   ```
5. Open a Pull Request against `upstream/main`.

---

## Code Style

### Python (Backend)

We enforce consistent code style using **[Ruff](https://docs.astral.sh/ruff/)** as our all-in-one linter and formatter.

```bash
# Lint
ruff check .

# Auto-fix linting issues
ruff check . --fix

# Format
ruff format .

# Check formatting without modifying files
ruff format . --check
```

**Key rules enforced:**

- Line length: **120 characters** max.
- Import sorting: `isort`-compatible (handled by Ruff).
- Docstrings: Google-style for all public functions, classes, and modules.
- Type hints: Required for all function signatures.
- No unused imports or variables.

Configuration is defined in `pyproject.toml` under `[tool.ruff]`.

### TypeScript / React (Frontend)

```bash
cd frontend

# Lint
npx eslint src/

# Format
npx prettier --write src/
```

- Follow the existing ESLint configuration in `eslint.config.js`.
- Use functional React components with TypeScript.
- Prefer named exports over default exports.

### General

- Use **English** for all code, comments, documentation, and commit messages.
- Prefer explicit over implicit — clarity always wins.
- Write self-documenting code; add comments only when the *why* is non-obvious.

---

## Commit Conventions

We follow the **[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)** specification. Every commit message must follow this format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|---|---|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation-only changes |
| `style` | Code style (formatting, no logic change) |
| `refactor` | Code restructuring (no feature or fix) |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `build` | Build system or dependency changes |
| `ci` | CI/CD pipeline changes |
| `chore` | Maintenance tasks (deps, configs) |
| `security` | Security-related changes |

### Scopes

Use the module or component name: `core`, `graphql`, `jwt`, `waf`, `frontend`, `k8s`, `ebpf`, `fair`, `llm`, `docker`, `ci`, `docs`.

### Examples

```
feat(graphql): add introspection-based query mutation fuzzing

fix(jwt): validate exp claim before signature verification

docs(contributing): add ruff formatting instructions

security(core): sanitize user-supplied object IDs in path parameters
```

### Rules

- Use the **imperative mood** in the description ("add" not "added").
- Do **not** end the description with a period.
- Keep the first line under **72 characters**.
- Reference issue numbers in the footer: `Closes #142`.

---

## Testing Requirements

All contributions **must** include appropriate tests. Pull requests without tests for new functionality will not be merged.

### Test Structure

```
tests/
├── unit/               # Fast, isolated unit tests
├── integration/        # Tests requiring Docker or external services
├── e2e/                # End-to-end API workflow tests
└── fixtures/           # Shared test data and mock OpenAPI specs
```

### Running Tests

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run with coverage report
pytest tests/ --cov=backend --cov-report=html --cov-fail-under=80

# Run a specific test file
pytest tests/unit/test_jwt_cracker.py -v

# Run integration tests (requires Docker)
docker compose -f docker-compose.test.yml up -d
pytest tests/integration/ -v --timeout=120
```

### Coverage Requirements

| Component | Minimum Coverage |
|---|---|
| Core Fuzzer (`bola_strike.py`) | 85% |
| Backend API (`backend/app/`) | 80% |
| JWT / Auth modules | 90% |
| Utility / Helper modules | 75% |

### Writing Good Tests

- Test both **happy paths** and **edge cases** (malformed input, auth failures, timeouts).
- Use `pytest` fixtures for setup and teardown.
- Mock external services — tests must run offline.
- Name tests descriptively: `test_should_reject_expired_jwt_token`.

---

## Pull Request Process

1. **Self-review** your code before requesting reviews.
2. Fill out the **PR template** completely (description, testing steps, screenshots if UI).
3. Ensure all CI checks pass (lint, test, build, security scan).
4. Request review from at least **one** maintainer.
5. Address all review feedback. Use `fixup!` commits, then squash before merge.
6. A maintainer will merge using **Squash and Merge** to keep history clean.

### PR Checklist

- [ ] Branch is up to date with `main`.
- [ ] Code passes `ruff check .` and `ruff format . --check`.
- [ ] All new and existing tests pass (`pytest`).
- [ ] Coverage thresholds are met.
- [ ] Documentation is updated (if applicable).
- [ ] Commit messages follow Conventional Commits.
- [ ] No secrets, credentials, or `.env` values are committed.
- [ ] Breaking changes are documented in the PR body.

---

## Issue Guidelines

### Bug Reports

Please include:

- **Environment:** OS, Python version, Docker version, browser (if frontend).
- **Steps to Reproduce:** Minimal, deterministic reproduction steps.
- **Expected Behavior:** What you expected to happen.
- **Actual Behavior:** What actually happened (include logs/tracebacks).
- **Screenshots/Recordings:** If applicable (especially for frontend issues).

### Feature Requests

Please include:

- **Problem Statement:** What problem does this solve?
- **Proposed Solution:** How should it work?
- **Alternatives Considered:** What other approaches did you evaluate?
- **Impact:** Who benefits and how?

---

## Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities. Please follow the responsible disclosure process described in [SECURITY.md](SECURITY.md).

---

## License

By contributing to BOLA Strike Enterprise, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

**Thank you for making BOLA Strike Enterprise better!** 🛡️
