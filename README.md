# 🧭 GraphQL Surface Mapper

A monorepo that contains:

- **CLI**: GraphQL Path Query Builder (generate Burp-ready GraphQL request bodies from an introspection schema).
- **Burp Extension** (Montoya): a multi-tab **GraphQL Attack Surface Analyzer** (Path → Query Builder tab will reuse the CLI logic/behavior in the UI and support *Send to Repeater*).

> Intended for **authorized security testing and internal analysis only**.

---

## 📦 Repository Structure

- `cli/`  
  Python CLI tool and examples. See: `cli/README.md`

- `burp-extension/`  
  Burp Suite extension (Java, Montoya API). See: `burp-extension/README.md` (to be added in upcoming versions)

- `docs/`  
  Documentation assets (images, notes)

---

## 🚀 Quick Start (CLI)

1) Install deps
```bash
pip install -r cli/requirements.txt
```

2) Run
```bash
python cli/gql_path_query_builder.py -s cli/examples/Schema.simple.json -t User -m burp -M 10
```

---

## 🚀 Quick Start (Burp Extension)

The Burp extension is under active development.
Planned MVP tabs:
- General Config (Target + headers)
- Schema (Import/Paste/Fetch introspection)
- Path → Query Builder (paths table + preview + copy body + send to repeater)

---

## 🖥️ Documentation

- Security policy: `SECURITY.md`
- Contributing: `CONTRIBUTING.md`
- Changelog: `CHANGELOG.md`

---

## 🧾 License

See: `LICENSE`
