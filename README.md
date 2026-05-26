# BOLA Strike Enterprise (v12.0)

**Autonomous API Warfare, DevSecOps Orchestration & Financial Risk Telemetry**

[![Quantum Ready](https://img.shields.io/badge/Cryptography-Quantum_Ready-purple.svg)]()
[![OSFI Compliant](https://img.shields.io/badge/Compliance-OSFI%20%7C%20SOC2-blue.svg)]()
[![eBPF Healer](https://img.shields.io/badge/Kernel-eBPF%2FXDP-black.svg)]()

*(Versión en español disponible en [README_es.md](README_es.md))*

Welcome to BOLA Strike Enterprise! This platform is designed to find and fix the most dangerous API vulnerability on the internet today: **Broken Object Level Authorization (BOLA/IDOR)**. 

While the technology inside is built for elite cybersecurity experts (using AI and Kernel-level defenses), we've designed this guide to be as easy to follow as possible, even if you are new to DevSecOps!

---

## 🚀 Quick Start Guide (For Beginners)

Want to see it in action quickly? Follow these simple steps to run a local audit on an API.

### Prerequisites
You only need two things installed on your computer:
1. **Python 3.10+** (Download from python.org)
2. **Git** (To clone this repository)

### Step 1: Install the tool
Open your terminal (or Command Prompt) and run these commands:
```bash
# Clone the repository
git clone https://github.com/nicolasferrer/bola-strike-enterprise.git
cd bola-strike-enterprise/Tools/API_Logic_Fuzzer

# Install required Python packages
pip install -r requirements.txt
```

### Step 2: Run your first API Scan
Let's pretend you want to test a development API at `http://localhost:8000/openapi.json`. Run this command:
```bash
python bola_strike.py --target http://localhost:8000/openapi.json --method ALL --depth 3
```
**What just happened?**
The tool read your API documentation, figured out all the endpoints (like `/users` or `/invoices`), and tried to hack them by crossing user IDs to see if User A can delete User B's data!

---

## 📖 How to Use it Like a Pro (Advanced Modes)

BOLA Strike can do much more than a simple scan. Here are the 3 main ways to use it:

### 1. The Ethical Hacker Mode (Local Execution)
If you are testing an API and want to use our **Artificial Intelligence** to generate smart attacks:
```bash
python bola_strike.py --target https://api.yourcompany.com/v1/swagger.yaml \
                      --enable-ai \
                      --evasion-level aggressive \
                      --export-pdf my_report.pdf
```
*   `--enable-ai`: Turns on the AI. Instead of sending random garbage data, the AI reads your API and generates realistic UUIDs, emails, and financial data.
*   `--evasion-level aggressive`: Hides the attack from Web Application Firewalls (WAF) using clever encoding.
*   `--export-pdf`: Generates a beautiful PDF report you can give to your boss.

### 2. The DevSecOps Mode (CI/CD Pipelines)
You can set up BOLA Strike to automatically test every code change before it goes live. Add this to your GitHub Actions (`.github/workflows/bola_strike.yml`):
```yaml
      - name: Run BOLA Strike Security Gate
        run: python cli_runner.py --target ./openapi.yaml
        env:
          ZERO_TRUST_TOKEN: ${{ secrets.MY_SECRET_TOKEN }}
```
**How it works:** If a developer accidentally writes vulnerable code, BOLA Strike calculates how much money the company could lose (in Dollars). If the risk is too high, it **cancels the deployment** instantly!

### 3. The Cloud Architect Mode (Kubernetes)
If you have a massive company with hundreds of APIs in Kubernetes:
```bash
helm install bola-strike ./kubernetes/bola-strike-helm-chart -n secops
```
**How it works:** The tool will launch hundreds of tiny, invisible "pods" in your cloud. They will swarm your network, test every single microservice simultaneously, report the vulnerabilities, and then delete themselves without a trace.

---

## 🧠 What Makes BOLA Strike "God-Level"? (The 12 Phases Explained Simply)

Behind the scenes, the platform is running 12 incredibly advanced phases. Here is what they do in plain English:

1. **API Discovery:** It finds hidden or undocumented APIs by listening to your network traffic.
2. **State Machine Fuzzing:** It doesn't just attack one page. It learns to "Create a user -> Log in -> Add item to cart -> Try to steal someone else's cart".
3. **GraphQL Support:** It can hack modern GraphQL databases just as easily as traditional REST APIs.
4. **JWT Cracking:** It tries to forge login tokens (JSON Web Tokens) to trick the system into thinking it is the Admin.
5. **WAF Evasion:** It acts like a ninja, sneaking past firewalls like Cloudflare.
6. **Executive Reporting:** It creates reports for developers (SARIF) and for SIEMs (ArcSight CEF).
7. **Service Mesh Integration:** It connects directly to your cloud router (Envoy/Istio).
8. **Generative AI (LLM):** It uses AI to think like a human hacker.
9. **Financial Risk (FAIR):** It doesn't just say "High Risk". It says "This bug could cost us $150,000 CAD in fines".
10. **Auto-Remediation:** It writes code (Terraform) to patch the firewall automatically while your developers fix the bug.
11. **eBPF Kernel Healer:** If it detects a live attack, it drops the hacker's connection instantly at the computer's network card, meaning 0 latency and 0 lag for your real users.
12. **Quantum Ledger:** It saves all audit logs into a private blockchain using Post-Quantum cryptography. This means even a supercomputer in the year 2035 couldn't alter your security logs.

---
**Developed by Nicolas Ferrer** | *Chief Security Architect & DevSecOps Strategist*
