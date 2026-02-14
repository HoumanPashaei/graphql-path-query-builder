# 🤝 Contributing to GQL-ASA

Thanks for considering contributing! 🚀  
This guide helps you set up the project and submit high-quality contributions.

---

## 🧩 What You Can Contribute

- 🐛 Bug fixes
- ✨ New detection scenarios / improved heuristics
- 🧪 Better test-case coverage (DoS / CSRF)
- 🖥️ UI/UX improvements for Burp workflows
- 📚 Documentation enhancements

---

## 🛠️ Development Setup

### Requirements
- Java 17+
- Maven 3.8+
- Burp Suite (Community/Pro)

### Build
```bash
mvn clean package
```

### Load into Burp
1. Burp → Extensions → Installed → Add
2. Type: Java
3. Select the built JAR

---

## ✅ Coding Guidelines

### General
- Keep changes **focused** and **reviewable**
- Prefer small PRs over large refactors
- Avoid breaking existing tabs/features unless explicitly intended

### Security & Safety
- Never store user secrets
- Do not introduce risky parsing/serialization behavior
- Avoid network calls that could cause SSRF-like behavior unintentionally
- Always preserve Burp request integrity when cloning/modifying requests:
  - handle `Content-Length`
  - keep headers consistent
  - avoid malformed JSON or double-encoding

### UI
- Keep UI responsive:
  - run network scans off the EDT
  - use SwingWorker or background threads safely
- Avoid large blocking operations on the UI thread

---

## 🧪 Testing Checklist

Before submitting a PR:
- ✅ Build succeeds: `mvn clean package`
- ✅ Extension loads in Burp without runtime errors
- ✅ Key workflows tested:
  - Send request to Query Builder
  - Send request to DoS Scanner
  - Send request to CSRF Scanner
  - Send generated requests to Repeater/Intruder
- ✅ Verify no regression in existing tabs

---

## 📦 Submitting a Pull Request

1. Fork the repo
2. Create a feature branch:
```bash
git checkout -b feature/my-change
```
3. Commit with a clear message:
```bash
git commit -m "Fix: preserve GET variants in CSRF scanner"
```
4. Push:
```bash
git push origin feature/my-change
```
5. Open a PR with:
- Summary of the change
- Why it matters
- How it was tested
- Screenshots (if UI changed)

---

## 🏷️ Issue Labels (suggested)

- `bug`
- `enhancement`
- `security`
- `ui/ux`
- `docs`

---

## 🙌 Thanks

Every contribution helps improve the project. Thank you! 💙
