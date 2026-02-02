# Contributing

This project welcomes issues and pull requests.

## 1) Development setup

### Prerequisites
- Python 3.9+  
- Git  

### Create and activate a virtual environment (recommended)

Create:
```bash
python -m venv .venv
```

Activate on Windows (PowerShell):
```powershell
.venv\Scripts\Activate.ps1
```

Activate on Windows (CMD):
```cmd
.venv\Scripts\activate.bat
```

Activate on Linux/macOS:
```bash
source .venv/bin/activate
```

### Install dependencies
```bash
pip install -r requirements.txt
```

## 2) Smoke tests

Help:
```bash
python gql_path_query_builder.py -h
```

Run against the example schema:
```bash
python gql_path_query_builder.py -s examples/Schema.simple.json -t User -m burp -M 10
```

Paths-only mode:
```bash
python gql_path_query_builder.py -s examples/Schema.simple.json -t User -p -M 10
```

## 3) Bug reports

When opening an issue, please include:
- OS (Windows/Linux/macOS) and Python version
- The exact command you ran
- Console output / stack trace
- Expected vs actual behavior
- A minimal schema sample (sanitized if necessary)

## 4) Pull requests

Guidelines:
- Keep PRs focused (one change per PR when possible)
- Add short flag aliases for new CLI options
- Update `README.md` if user-facing behavior changes
- Update `CHANGELOG.md` for user-visible changes
- Ensure CI passes

## 5) Code style

- Prefer explicit, readable code
- Avoid unnecessary dependencies
- Keep backward compatibility for CLI flags when possible
