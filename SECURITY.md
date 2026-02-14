# 🔐 Security Policy

Thank you for helping improve the security of **GQL-ASA**. 🛡️  
This document explains how to report vulnerabilities responsibly.

---

## ✅ Supported Versions

Security updates are provided for the latest release and the `main` branch.

| Version | Supported |
|--------:|:---------|
| Latest release | ✅ |
| `main` branch | ✅ |
| Older versions | ❌ |

---

## 🚨 Reporting a Vulnerability

Please **do not** open public GitHub issues for security vulnerabilities.

Instead, report privately with:
- A clear description of the issue
- Steps to reproduce
- Impact assessment (what can be done?)
- Screenshots/logs if applicable
- Your environment details (Burp version, Java version, OS)

### Preferred channel
- GitHub **Security Advisories** (Private report)

If that is not available:
- Open a private discussion with the maintainers (or share a secure contact method in the repository).

---

## ⏱️ Response Timeline

We aim to:
- Acknowledge reports within **72 hours**
- Provide an initial assessment within **7 days**
- Ship a fix as soon as reasonably possible depending on severity

---

## 🧠 Scope

In scope:
- Code execution risks
- Supply-chain risks in build artifacts
- Data leakage from Burp context
- Unsafe request handling leading to SSRF-like behavior
- Injection flaws in request crafting/parsing
- Any vulnerability that impacts users running the extension

Out of scope:
- Vulnerabilities in third-party targets you scan (those belong to the target application)
- Social engineering

---

## 🙏 Responsible Disclosure

Please give us time to patch before public disclosure.  
We will credit you (if you want) in release notes or advisories.
