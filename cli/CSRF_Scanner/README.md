# 🛡️ GraphQL CSRF Checker (CLI)

A fast CLI tool to detect **CSRF-equivalent behavior** in GraphQL endpoints by replaying a baseline request and then testing **alternative request shapes** (GET / form-POST / header manipulations) to see whether the server performs the same state-changing action without the typical “browser protections”.

This is especially useful for GraphQL APIs where:
- the endpoint accepts **GET requests** for operations,
- accepts **`application/x-www-form-urlencoded`** or **`multipart/form-data`** bodies,
- does not validate **Origin/Referer** (or accepts missing Origin/Referer),
- uses **cookie-based auth** (session cookies) and relies on “same-site” assumptions.

---

## ✨ What the tool detects

The tool flags a request as potentially CSRF-able when it finds **CSRF-equivalent behavior**, meaning:

✅ A transformed request (e.g., GET or form POST) returns a response **equivalent** to the baseline JSON POST response.

Depending on options, equivalence can be checked via:
- full JSON response comparison, or
- **`data`-only** comparison (`--compare-data-only`), and optionally including `extensions`.

The tool is designed for GraphQL and works best on requests that include:
- `{"query": "...", "variables": {...}}`
- an `operationName` (optional but recommended)

---

## 🧪 Test vectors covered

### 1) ✅ Baseline JSON POST
- Replays the original request in a consistent normalized form.

### 2) 🧾 POST `application/x-www-form-urlencoded` (optional)
- Encodes GraphQL payload into a form body.

Enabled by default (disable with `--no-urlencoded-post`).

### 3) 📎 POST `multipart/form-data` (optional)
- Sends GraphQL payload as multipart fields.

Enabled by default (disable with `--no-urlencoded-post`).

### 4) 🔎 GET querystring (optional)
- Converts GraphQL payload into URL parameters: `?query=...&variables=...`

Enabled by default (unless `--no-get`).

### 5) 🧨 Content-Type fuzzing (optional)
Enable with `--fuzz-content-type`:
- tests additional variants (e.g., `text/plain` / variations) where applicable.

### 6) 🧷 Header scenario testing (optional)
Enable with `--test-headers`:
- Drops Origin/Referer
- Uses “evil” Origin/Referer
- Simulates browser-like CSRF contexts

You can customize with:
- `--evil-origin`
- `--evil-referer`

---

## 🧠 Comparison logic (how “equivalent” is decided)

The tool compares the transformed response against the baseline response.

You can tune comparisons:

- `--ignore-keys`  
  Ignore noisy keys like timestamps, ids, traceId, etc.

- `--compare-data-only`  
  Compare only GraphQL `data` (recommended for stability).

- `--allow-graphql-errors`  
  Treat responses with an `errors` array as comparable candidates.

- `--include-extensions`  
  Include `extensions` in comparisons.

---

## 🧰 Installation

### Requirements
- Python 3.10+
- `httpx`

Install dependencies:
```bash
pip install -r requirements.txt
# or
pip install httpx
```

---

## 🚀 Usage

### Basic
```bash
python CSRF-Checker.py -i Request.txt
```

### Recommended (more coverage)
```bash
python CSRF-Checker.py -i Request.txt -fct -th -age -cdo -ie
```

### Proxy through Burp (enabled only when you pass `-p`)
```bash
python CSRF-Checker.py -i Request.txt -p http://127.0.0.1:8080 -fct -th
```

Notes:
- By default the tool does **not** use any proxy (and ignores environment proxy variables).
- When `-p/--proxy` is provided, requests are sent through that proxy.

### Show generated requests
```bash
python CSRF-Checker.py -i Request.txt -sr
```

### Disable GET testing
```bash
python CSRF-Checker.py -i Request.txt -ng
```

### Disable urlencoded + multipart testing
```bash
python CSRF-Checker.py -i Request.txt -nup
```

---

## 📄 Reports

### JSON report
```bash
python CSRF-Checker.py -i Request.txt -rj report.json
```

### HTML report
```bash
python CSRF-Checker.py -i Request.txt -rh report.html
```

---

## 🧷 Options (with short flags)

| Purpose | Long | Short |
|---|---|---|
| Input file/dir | `--input` | `-i` |
| Input directory | `--input-dir` | `-id` |
| Glob | `--glob` | `-g` |
| Show generated requests | `--show-request` | `-sr` |
| Disable progress output | `--no-progress` | `-np` |
| Disable GET vectors | `--no-get` | `-ng` |
| Disable urlencoded/multipart | `--no-urlencoded-post` | `-nup` |
| Fuzz Content-Type | `--fuzz-content-type` | `-fct` |
| Test Origin/Referer scenarios | `--test-headers` | `-th` |
| Evil Origin | `--evil-origin` | `-eo` |
| Evil Referer | `--evil-referer` | `-er` |
| Allow GraphQL errors | `--allow-graphql-errors` | `-age` |
| Compare data only | `--compare-data-only` | `-cdo` |
| Include extensions | `--include-extensions` | `-ie` |
| Ignore keys | `--ignore-keys` | `-ik` |
| Snippet length | `--snippet-len` | `-sl` |
| JSON report path | `--report-json` | `-rj` |
| HTML report path | `--report-html` | `-rh` |
| Proxy | `--proxy` | `-p` |
| Timeout | `--timeout` | `-t` |
| Insecure TLS | `--insecure` | `-k` |

---

## 🧩 Input format

The `-i` file must contain a **raw HTTP request**, like what Burp can copy:

```
POST /graphql HTTP/2
Host: example.com
Content-Type: application/json
Cookie: session=...

{"query":"...","variables":{...}}
```

---

## ⚠️ Interpretation guidance

A “match” (baseline ≈ transformed) is a **strong signal** that the endpoint might be exploitable via CSRF in browser contexts, but you should still validate:

- whether authentication is cookie-based in the browser,
- SameSite cookie settings,
- CORS / preflight behaviors,
- and Origin/Referer enforcement on the server.

---

## ✅ Changelog / Next steps

- Proxy handling is **off by default** and only enabled with `-p`.
- The tool prints a **live progress line** while requests are being sent (use `-np` to disable).

