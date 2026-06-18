#!/usr/bin/env python3
"""
Read-only smoke tests for the local NetGuard-AI Gateway Status API.
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_BASE_URL = "http://127.0.0.1:8787"


def build_url(base_url, path):
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def request(base_url, path, method="GET"):
    req = urllib.request.Request(build_url(base_url, path), method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
            content_type = resp.headers.get("Content-Type", "")
            return resp.status, content_type, body, None
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read(), None
    except urllib.error.URLError as exc:
        return None, "", b"", str(exc)


def parse_json(body):
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def ok(message):
    print(f"[OK] {message}")


def fail(message):
    print(f"[FAIL] {message}")


def check_healthz(base_url):
    status, _content_type, body, error = request(base_url, "/healthz")
    if error:
        fail(f"GET /healthz failed: {error}")
        return False
    if status != 200:
        fail(f"GET /healthz returned HTTP {status}, expected 200")
        return False

    payload = parse_json(body)
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        fail('GET /healthz did not return JSON status = "ok"')
        return False

    ok('GET /healthz returned HTTP 200 with status = "ok"')
    return True


def check_api_status(base_url):
    status, _content_type, body, error = request(base_url, "/api/status")
    if error:
        fail(f"GET /api/status failed: {error}")
        return False
    if status != 200:
        fail(f"GET /api/status returned HTTP {status}, expected 200")
        return False

    payload = parse_json(body)
    required = {"checks", "fail_count", "warn_count", "final_result"}
    if not isinstance(payload, dict):
        fail("GET /api/status did not return a JSON object")
        return False
    missing = sorted(required - payload.keys())
    if missing:
        fail(f"GET /api/status JSON missing keys: {', '.join(missing)}")
        return False

    ok("GET /api/status returned HTTP 200 with expected JSON keys")
    return True


def check_dashboard(base_url):
    status, _content_type, body, error = request(base_url, "/")
    if error:
        fail(f"GET / failed: {error}")
        return False
    if status != 200:
        fail(f"GET / returned HTTP {status}, expected 200")
        return False

    text = body.decode("utf-8", errors="replace")
    if "<html" not in text.lower() or "NetGuard-AI Gateway Control" not in text:
        fail("GET / did not contain expected dashboard HTML text")
        return False

    ok("GET / returned HTTP 200 with dashboard HTML")
    return True


def check_post_rejected(base_url):
    status, _content_type, _body, error = request(base_url, "/api/status", method="POST")
    if error:
        fail(f"POST /api/status failed: {error}")
        return False
    if status != 405:
        fail(f"POST /api/status returned HTTP {status}, expected 405")
        return False

    ok("POST /api/status returned HTTP 405 Method Not Allowed")
    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run read-only smoke tests against the Gateway Status API"
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    return parser.parse_args()


def main():
    args = parse_args()
    checks = (
        check_healthz,
        check_api_status,
        check_dashboard,
        check_post_rejected,
    )

    results = [check(args.base_url) for check in checks]
    passed = all(results)
    if passed:
        print("[RESULT] SMOKE TEST PASSED")
        return 0

    print("[RESULT] SMOKE TEST FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
