import sys
import json
import re
from pathlib import Path
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CSRF-Checker (GraphQL)

Purpose:
  Detect CSRF-equivalent behavior in GraphQL endpoints by replaying the same operation
  under different request shapes and cross-site header conditions.

Key ideas:
  - Many GraphQL servers accept operations over different content-types or via GET.
  - If a state-changing operation (usually mutation) can be executed without CSRF defenses
    (Origin/Referer validation, custom headers, same-site cookies, etc.), it may be vulnerable.

This script:
  1) Reads a raw HTTP request file (Burp-style).
  2) Extracts target URL, method, headers, body.
  3) Sends a baseline request.
  4) Sends transformed variants:
       - POST application/x-www-form-urlencoded
       - GET with query + variables in query string
       - Optional Content-Type fuzzing
       - Optional header scenarios (Origin/Referer stripped/spoofed)
  5) Compares responses (status/length and optionally data-only JSON) to infer "CSRF-equivalent" behavior.

Outputs are NDJSON-compatible bodies for easy copy into Burp, plus human-friendly console output.
"""

import argparse
import dataclasses
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any, List
from urllib.parse import urljoin, urlencode, urlparse

import time
import threading

import httpx

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


# -----------------------------
# Models
# -----------------------------

@dataclass
class ParsedRequest:
    url: str
    method: str
    http_version: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass
class ScenarioResult:
    scenario_name: str = ""
    sent_method: str = ""
    sent_url: str = ""
    sent_headers: Dict[str, str] = field(default_factory=dict)
    sent_body: bytes = b""

    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_content_type: str = ""
    response_text: str = ""
    response_len: int = 0

    comparable_payload: str = ""  # string used for comparisons (data-only or full text)

    baseline_equal: Optional[bool] = None
    rationale: str = ""


# -----------------------------
# Spinner / progress helpers
# -----------------------------

class Spinner:
    def __init__(self, label: str):
        self.label = label
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)

    def _run(self) -> None:
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        i = 0
        while not self._stop.is_set():
            sys.stdout.write("\r" + Fore.CYAN + f"{frames[i%len(frames)]} {self.label}" + Style.RESET_ALL)
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)
        # clear line
        sys.stdout.write("\r" + " " * (len(self.label) + 6) + "\r")
        sys.stdout.flush()


def hr(char: str = "=", width: int = 72) -> str:
    return char * width


def pretty_http_request(method: str, url: str, headers: Dict[str, str], body: bytes) -> str:
    u = urlparse(url)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {u.netloc}"]
    for k, v in headers.items():
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        try:
            lines.append(body.decode("utf-8", "replace"))
        except Exception:
            lines.append(repr(body))
    return "\n".join(lines)


# -----------------------------
# Parsing
# -----------------------------

def parse_raw_request_file(path: str) -> ParsedRequest:
    raw = Path(path).read_bytes()
    # normalize line endings for parsing
    text = raw.decode("utf-8", "replace")
    # split headers/body by first blank line
    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
        head_lines = head.split("\r\n")
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
        head_lines = head.split("\n")
    else:
        raise ValueError("Input does not look like a raw HTTP request (no blank line separating headers/body).")

    req_line = head_lines[0].strip()
    m = re.match(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<http>HTTP/\d(?:\.\d)?)$", req_line)
    if not m:
        raise ValueError(f"Invalid request line: {req_line}")

    method = m.group("method")
    target = m.group("target")
    http_ver = m.group("http")

    headers: Dict[str, str] = {}
    for line in head_lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    host = headers.get("Host") or headers.get("host")
    if not host:
        raise ValueError("Missing Host header in the input request.")

    # If target is absolute URL, keep it. Otherwise derive from Host + scheme.
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        scheme = "https" if headers.get("X-Forwarded-Proto", "").lower() == "https" else "https"
        url = f"{scheme}://{host}{target}"

    return ParsedRequest(
        url=url,
        method=method,
        http_version=http_ver,
        headers=headers,
        body=body.encode("utf-8", "replace"),
    )


# -----------------------------
# GraphQL helpers
# -----------------------------

def extract_graphql_json(body: bytes) -> Dict[str, Any]:
    try:
        obj = json.loads(body.decode("utf-8", "replace"))
        if not isinstance(obj, dict) or "query" not in obj:
            raise ValueError("Body is not a GraphQL JSON object (expected {query, variables?, operationName?}).")
        return obj
    except json.JSONDecodeError as e:
        raise ValueError(f"Body is not valid JSON: {e}") from e


def build_post_urlencoded_payload(gql: Dict[str, Any]) -> Tuple[bytes, str]:
    # GraphQL over form: query, variables, operationName
    data = {
        "query": gql.get("query", ""),
        "operationName": gql.get("operationName") or "",
        "variables": json.dumps(gql.get("variables") or {}, ensure_ascii=False),
    }
    encoded = urlencode(data).encode("utf-8")
    return encoded, "application/x-www-form-urlencoded"


def build_get_url(gql: Dict[str, Any], base_url: str) -> str:
    params = {
        "query": gql.get("query", ""),
    }
    if gql.get("operationName") is not None:
        params["operationName"] = gql.get("operationName") or ""
    if gql.get("variables") is not None:
        params["variables"] = json.dumps(gql.get("variables") or {}, ensure_ascii=False)
    u = urlparse(base_url)
    query = urlencode(params)
    new = u._replace(query=query)
    return new.geturl()


def comparable_text(resp_text: str, compare_data_only: bool, include_extensions: bool) -> str:
    if not compare_data_only:
        return resp_text
    try:
        j = json.loads(resp_text)
        if not isinstance(j, dict):
            return resp_text
        slim = {}
        if "data" in j:
            slim["data"] = j.get("data")
        if include_extensions and "extensions" in j:
            slim["extensions"] = j.get("extensions")
        # We intentionally ignore "errors" when compare_data_only is true
        return json.dumps(slim, sort_keys=True, ensure_ascii=False)
    except Exception:
        return resp_text


def is_graphql_error(resp_text: str) -> bool:
    try:
        j = json.loads(resp_text)
        return isinstance(j, dict) and "errors" in j and bool(j["errors"])
    except Exception:
        return False


# -----------------------------
# HTTP sending
# -----------------------------

def make_client(timeout: float, proxy: Optional[str], verify: bool) -> httpx.Client:
    kwargs = dict(timeout=timeout, follow_redirects=True, verify=verify)
    if proxy:
        # httpx API changed across versions; support both.
        try:
            return httpx.Client(proxies=proxy, **kwargs)  # type: ignore
        except TypeError:
            return httpx.Client(proxy=proxy, **kwargs)  # type: ignore
    return httpx.Client(**kwargs)


def send_request(
    client: httpx.Client,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
) -> httpx.Response:
    # Ensure Content-Length isn't stale
    h = dict(headers)
    h.pop("Content-Length", None)
    h.pop("content-length", None)
    return client.request(method, url, headers=h, content=body)


# -----------------------------
# Scenario generation
# -----------------------------

def base_headers_for_send(parsed: ParsedRequest) -> Dict[str, str]:
    # Remove hop-by-hop headers, keep relevant ones
    drop = {"content-length", "accept-encoding", "connection"}
    out = {}
    for k, v in parsed.headers.items():
        if k.lower() in drop:
            continue
        out[k] = v
    return out


def apply_header_scenario(headers: Dict[str, str], scenario: str) -> Dict[str, str]:
    h = dict(headers)
    # normalize key access
    def pop_any(keys: List[str]):
        for kk in list(h.keys()):
            if kk.lower() in [k.lower() for k in keys]:
                h.pop(kk, None)

    if scenario == "as_is":
        return h

    if scenario == "no_origin_referer":
        pop_any(["Origin", "Referer"])
        return h

    if scenario == "cross_site":
        # Fake attacker origin
        h["Origin"] = "https://evil.example"
        h["Referer"] = "https://evil.example/"
        return h

    if scenario == "null_origin":
        h["Origin"] = "null"
        pop_any(["Referer"])
        return h

    return h


def build_scenarios(
    parsed: ParsedRequest,
    gql: Dict[str, Any],
    fuzz_content_type: bool,
    test_headers: bool,
) -> List[Tuple[str, str, str, Dict[str, str], Optional[bytes]]]:
    """
    Returns list of (scenario_name, method, url, headers, body)
    """
    scenarios: List[Tuple[str, str, str, Dict[str, str], Optional[bytes]]] = []
    base_h = base_headers_for_send(parsed)

    header_modes = ["as_is"]
    if test_headers:
        header_modes = ["as_is", "no_origin_referer", "cross_site", "null_origin"]

    # Baseline (JSON)
    for hm in header_modes:
        h = apply_header_scenario(base_h, hm)
        h["Content-Type"] = "application/json"
        scenarios.append((f"BASELINE_JSON | {hm}", "POST", parsed.url, h, json.dumps(gql, ensure_ascii=False).encode("utf-8")))

    # POST urlencoded
    encoded_body, ct = build_post_urlencoded_payload(gql)
    for hm in header_modes:
        h = apply_header_scenario(base_h, hm)
        h["Content-Type"] = ct
        scenarios.append((f"POST_URLENCODED | {hm}", "POST", parsed.url, h, encoded_body))

    # GET querystring
    get_url = build_get_url(gql, parsed.url)
    for hm in header_modes:
        h = apply_header_scenario(base_h, hm)
        # Many servers ignore CT on GET, but keep Accept if present
        h.pop("Content-Type", None)
        scenarios.append((f"GET_QUERYSTRING | {hm}", "GET", get_url, h, None))

    if fuzz_content_type:
        fuzz_types = [
            "text/plain",
            "application/graphql",
            "application/x-json",
            "application/json; charset=utf-8",
            "application/x-www-form-urlencoded; charset=utf-8",
        ]
        for fct in fuzz_types:
            for hm in header_modes:
                h = apply_header_scenario(base_h, hm)
                h["Content-Type"] = fct
                scenarios.append((f"FUZZ_CONTENT_TYPE({fct}) | {hm}", "POST", parsed.url, h, json.dumps(gql, ensure_ascii=False).encode("utf-8")))

    return scenarios


# -----------------------------
# Analysis / printing
# -----------------------------

def print_section(title: str, color=Fore.YELLOW) -> None:
    print(Fore.WHITE + hr("-"))
    print(color + title + Style.RESET_ALL)
    print(Fore.WHITE + hr("-"))


def score_equivalence(baseline: ScenarioResult, cand: ScenarioResult, allow_graphql_errors: bool) -> Tuple[bool, str]:
    """
    Determine if cand is "equivalent enough" to baseline.
    """
    if cand.status_code is None or baseline.status_code is None:
        return False, "No HTTP response received."

    # If candidate produces graphql errors and we disallow them -> not equivalent
    if (not allow_graphql_errors) and is_graphql_error(cand.response_text):
        return False, "Candidate response contains GraphQL errors (disallowed by settings)."

    same_status = cand.status_code == baseline.status_code
    same_payload = cand.comparable_payload == baseline.comparable_payload

    if same_status and same_payload:
        return True, "HTTP status and comparable response payload match baseline."
    if same_status and abs(cand.response_len - baseline.response_len) <= 10:
        return True, "HTTP status matches baseline and response length is very close."
    return False, "Response differs from baseline (status/payload/length)."


def should_flag_csrf_like(scenario_name: str, baseline_equal: bool) -> bool:
    # We flag when a cross-site-ish or alternate transport matches baseline
    if not baseline_equal:
        return False
    # Anything other than BASELINE_JSON|as_is is interesting
    if scenario_name.startswith("BASELINE_JSON | as_is"):
        return False
    return True


def rationale_for(scenario_name: str) -> str:
    # Human explanation used in output
    if scenario_name.startswith("POST_URLENCODED"):
        return "Server accepted GraphQL operation using application/x-www-form-urlencoded (common CSRF delivery vector)."
    if scenario_name.startswith("GET_QUERYSTRING"):
        return "Server accepted GraphQL operation via GET query-string (can be triggered cross-site)."
    if "cross_site" in scenario_name:
        return "Request included cross-site Origin/Referer; if accepted, Origin/Referer validation may be missing."
    if "no_origin_referer" in scenario_name:
        return "Request worked without Origin/Referer; CSRF defenses relying on these headers may be absent."
    if "null_origin" in scenario_name:
        return "Request worked with Origin: null; some CSRF bypasses rely on null origins."
    if scenario_name.startswith("FUZZ_CONTENT_TYPE"):
        return "Server accepted non-standard Content-Type; may allow CSRF via permissive content-type handling."
    return "Variant behavior matched baseline."


def build_burp_body(method: str, url: str, headers: Dict[str, str], gql: Dict[str, Any], variant: str) -> Dict[str, Any]:
    """
    Output is JSON body suitable for Burp Repeater GraphQL tab.
    We keep it GraphQL JSON always, because Burp GraphQL tab expects JSON.
    """
    op = gql.get("operationName")
    return {
        "query": gql.get("query", ""),
        "operationName": op if op else None,
        "variables": gql.get("variables") or {},
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="CSRF-Checker.py",
        formatter_class=argparse.RawTextHelpFormatter,
        description="GraphQL CSRF-equivalent checker (replays GraphQL operation under CSRF-friendly request shapes).",
    )
    ap.add_argument("-i", "--input", required=True, help="Raw HTTP request file (Burp-style).")

    ap.add_argument("-p", "--proxy", default=None, help="Proxy URL, e.g. http://127.0.0.1:8080")
    ap.add_argument("-t", "--timeout", type=float, default=25.0, help="Timeout seconds (default: 25).")
    ap.add_argument("-k", "--insecure", action="store_true", help="Disable TLS verification.")

    ap.add_argument("-fct", "--fuzz-content-type", action="store_true", help="Fuzz Content-Type values.")
    ap.add_argument("-th", "--test-headers", action="store_true", help="Test Origin/Referer scenarios.")
    ap.add_argument("-age", "--allow-graphql-errors", action="store_true", help="Treat responses with GraphQL errors as comparable.")
    ap.add_argument("-cdo", "--compare-data-only", action="store_true", help="Compare only JSON.data (and optionally extensions).")
    ap.add_argument("-ie", "--include-extensions", action="store_true", help="When -cdo is set, include JSON.extensions in comparison.")

    ap.add_argument("-sr", "--show-request", action="store_true", help="Show each sent request.")
    ap.add_argument("-sp", "--show-response", action="store_true", help="Show each received response body (may be large).")

    args = ap.parse_args()

    print(hr("="))
    print(f"FILE: {args.input}")
    print(hr("="))

    try:
        parsed = parse_raw_request_file(args.input)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to parse input request: {e}" + Style.RESET_ALL)
        return 2

    # We expect GraphQL JSON in the input request body
    try:
        gql = extract_graphql_json(parsed.body)
    except Exception as e:
        print(Fore.RED + f"[!] Input request body is not GraphQL JSON: {e}" + Style.RESET_ALL)
        return 2

    verify = not args.insecure

    spinner = Spinner("Sending requests & analyzing responses...")
    spinner.start()
    try:
        with make_client(timeout=args.timeout, proxy=args.proxy, verify=verify) as client:
            scenarios = build_scenarios(parsed, gql, args.fuzz_content_type, args.test_headers)

            results: List[ScenarioResult] = []
            baseline: Optional[ScenarioResult] = None

            for (name, m, url, headers, body) in scenarios:
                r = ScenarioResult(scenario_name=name, sent_method=m, sent_url=url, sent_headers=headers, sent_body=body or b"")
                try:
                    resp = send_request(client, m, url, headers, body)
                    # Ensure body is fully read before accessing text (avoid streaming surprises)
                    resp.read()
                    r.status_code = resp.status_code
                    r.response_headers = {k: v for k, v in resp.headers.items()}
                    r.response_content_type = resp.headers.get("content-type", "")
                    r.response_text = resp.text
                    r.response_len = len(resp.content or b"")
                    r.comparable_payload = comparable_text(resp.text, args.compare_data_only, args.include_extensions)
                except Exception as ex:
                    r.status_code = None
                    r.response_text = f"[request error] {ex}"
                    r.comparable_payload = r.response_text
                results.append(r)

                if name.startswith("BASELINE_JSON | as_is") and baseline is None:
                    baseline = r

            if baseline is None:
                baseline = results[0] if results else ScenarioResult(scenario_name="BASELINE_MISSING")

            # Compare all to baseline
            for r in results:
                eq, why = score_equivalence(baseline, r, args.allow_graphql_errors)
                r.baseline_equal = eq
                if should_flag_csrf_like(r.scenario_name, eq):
                    r.rationale = rationale_for(r.scenario_name) + " " + why
                else:
                    r.rationale = why

    finally:
        spinner.stop()

    # Print results (human-friendly)
    print(Fore.GREEN + "[+] Completed.\n" + Style.RESET_ALL)

    baseline_res = next((x for x in results if x.scenario_name.startswith("BASELINE_JSON | as_is")), None)
    if baseline_res is None and results:
        baseline_res = results[0]

    # Summary
    suspects = [r for r in results if r.baseline_equal and should_flag_csrf_like(r.scenario_name, True)]
    print_section("SUMMARY", Fore.CYAN)
    print(f"Total scenarios tested: {len(results)}")
    print(f"Potential CSRF-equivalent scenarios: {len(suspects)}")
    if suspects:
        print(Fore.YELLOW + "Candidates:" + Style.RESET_ALL)
        for s in suspects:
            print(f" - {s.scenario_name}")

    # Detailed per scenario
    for idx, r in enumerate(results, 1):
        print("\n" + hr("="))
        title_color = Fore.YELLOW if (r.baseline_equal and should_flag_csrf_like(r.scenario_name, True)) else Fore.WHITE
        print(title_color + f"[{idx}] TEST: {r.scenario_name}" + Style.RESET_ALL)
        print(hr("="))

        # Sent request
        if args.show_request or True:
            print_section("SENT REQUEST", Fore.MAGENTA)
            print(pretty_http_request(r.sent_method, r.sent_url, r.sent_headers, r.sent_body))

        # Response
        print_section("RECEIVED RESPONSE (headers + status)", Fore.BLUE)
        sc = r.status_code if r.status_code is not None else "N/A"
        print(f"Status: {sc}")
        ct = r.response_content_type or ""
        print(f"Content-Type: {ct}")
        print(f"Length: {r.response_len}")
        if args.show_response:
            print_section("RESPONSE BODY", Fore.BLUE)
            print(r.response_text)

        # Verdict
        is_candidate = bool(r.baseline_equal) and should_flag_csrf_like(r.scenario_name, True)
        verdict = "POTENTIAL CSRF-EQUIVALENT" if is_candidate else "not detected"
        vcol = Fore.RED if is_candidate else Fore.GREEN
        print_section("VERDICT", vcol)
        print(vcol + verdict + Style.RESET_ALL)
        print("Reason:", r.rationale)

        # Burp body (single line JSON) for easy copy
        print_section("BURP BODY (copy next line)", Fore.GREEN)
        burp_body = {"query": gql.get("query", ""), "operationName": gql.get("operationName"), "variables": gql.get("variables") or {}}
        print(json.dumps(burp_body, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
