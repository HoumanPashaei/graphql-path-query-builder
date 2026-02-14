# 🛡️ GQL-ASA — GraphQL Attack Surface Analyzer (Burp Suite Extension)

A Burp Suite extension for analyzing GraphQL attack surface and running focused security checks (DoS + CSRF) with a clean workflow and actionable outputs.

> ✅ Built for real-world pentesting workflows: **Proxy / Repeater / History / Intruder → Send to Extension → Analyze & Inspect → Send back to Repeater/Intruder**

---

## ✨ Features

### 🧭 Query Builder
- Discover GraphQL paths/operations from traffic
- Build/inspect queries and send them to Repeater/Intruder
- Schema view + formatting tools

### ⚡ DoS Scanner (GraphQL Cop-style)
Detects common GraphQL Denial-of-Service patterns:
- Alias Overloading
- Batch Queries
- Field Duplication
- Directive Overloading
- Circular Introspection Query
- Query Depth / Nested Selections
- Fragment Explosion / Nested Fragments
- Argument / Variable Bomb
- List Size / Pagination Abuse
- Heavy Objects / Slow Resolver candidates (schema-driven)

Includes:
- Results table + Request/Response viewer
- Severity + Vulnerable tri-state output
- Attack Guide (scenario cards)

### 🧪 CSRF Scanner (GraphQL-aware)
Tests GraphQL CSRF-relevant patterns using safe, realistic variants:
- Content-Type mutation scenarios (where relevant)
- GET variants are always included
- Origin/Referer tests run only when CSRF-relevant (GET / x-www-form-urlencoded / multipart / text/plain)
- Baseline vs variant similarity checks

---

## 🧩 Installation

### Option A — Load the built JAR
1. Build the project
2. In Burp Suite:
   - **Extensions → Installed → Add**
   - Extension type: **Java**
   - Select the built JAR file

### Option B — Build from source
Requirements:
- Java 17+
- Maven 3.8+

Build:
```bash
mvn clean package
```

---

## 🚀 Usage

1. Capture GraphQL traffic in Burp (Proxy/Repeater/Logger)
2. Right click a request → **Send to GQL-ASA**
3. Open the extension tab:
   - Query Builder: explore operations and schema
   - DoS Scanner: run DoS patterns + inspect results
   - CSRF Scanner: run CSRF-relevant variants and compare outcomes

---

## 📌 Notes & Limitations

- CSRF results depend heavily on the application’s GraphQL implementation and strictness around **Content-Type**, **CORS**, and **preflight** behavior.
- “Vulnerable” output is derived from measurable signals (status, timing, response similarity, error patterns). Always validate findings manually.

---

## 🛣️ Roadmap (high-level)

- ✅ Improve scenario coverage and reduce false positives
- ✅ Improve UI/UX for investigation workflows
- ⏳ Add more schema-driven heuristics (heavy resolver detection)
- ⏳ Add export/reporting (optional)

---

## 🤝 Contributing

Contributions are welcome! Please see **CONTRIBUTING.md**.

---

## 🔐 Security

If you find a vulnerability in this extension, please follow **SECURITY.md**.

---

## 📜 License

MIT License
