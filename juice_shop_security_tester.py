#!/usr/bin/env python3
"""
juice_shop_security_tester.py

Automated security testing tool for OWASP Juice Shop (authorized, self-hosted
instances only). Built as the Week 2 deliverable following the Week 1 attack
surface mapping report (CSL-INT-010).

Covers three attack points discovered during Week 1 recon, run through one
shared engine so they are a single coordinated tool rather than three
unrelated scripts:

  1. IDOR            - /rest/basket/:id (Broken Access Control, OWASP A01)
  2. AUTH-SWEEP       - Authorization consistency across API endpoints
                        (public vs. session-gated vs. admin-gated)
  3. DISCLOSURE       - Hidden/legacy paths and information-disclosure headers
                        (/ftp, /encryptionkeys, /robots.txt, X-Powered-By, etc.)

Author:  Muhammad Ali Mobeen (@MAliXCS) - Cronova Solutions Cybersecurity
         Internship - https://github.com/MAliXCS

Scope:   Only run this against OWASP Juice Shop instances you own or are
         explicitly authorized to test. Do not point this at third-party
         infrastructure.

Usage examples:
    python3 juice_shop_security_tester.py --target http://localhost:3000
    python3 juice_shop_security_tester.py --target http://localhost:3000 --test idor
    python3 juice_shop_security_tester.py --target http://localhost:3000 \
        --output report --format all
"""

import argparse
import base64
import html
import json
import os
import random
import re
import string
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
except ImportError:
    print("This tool requires the 'requests' library. Install it with:")
    print("    pip install requests --break-system-packages")
    sys.exit(1)


TOOL_NAME = "Juice Shop Security Tester"
TOOL_VERSION = "1.0"
AUTHOR_HANDLE = "@MAliXCS"
AUTHOR_URL = "https://github.com/MAliXCS"

# Directory the script itself lives in (not the current working directory).
# Reports are written here automatically so they always land next to the
# tool, regardless of where the user ran it from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Canonical severity ordering used everywhere a report groups/sorts findings
# (table of contents, grouped sections, summary bars, etc.)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# --------------------------------------------------------------------------- #
# Terminal colour engine
# --------------------------------------------------------------------------- #
# Plain ANSI escape codes - no external dependency required. Colour is
# automatically disabled when output isn't a real terminal (e.g. piped to a
# file) or when --no-color is passed, so reports and logs stay clean text.

COLOR_ENABLED = sys.stdout.isatty()

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "underline": "\033[4m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m",
}


def c(text, *styles) -> str:
    """Wrap text in ANSI style codes, or return it unchanged if colour is off."""
    if not COLOR_ENABLED or not styles:
        return str(text)
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}"


SEVERITY_STYLES = {
    "CRITICAL": ("bold", "bright_red"),
    "HIGH": ("red",),
    "MEDIUM": ("yellow",),
    "LOW": ("blue",),
    "INFO": ("dim", "white"),
}

SEVERITY_HEX = {
    # used for HTML/PDF export, independent of terminal colour support
    "CRITICAL": "#b00020",
    "HIGH": "#dc3545",
    "MEDIUM": "#e6962d",
    "LOW": "#2d7dd2",
    "INFO": "#6c757d",
}


def colorize_severity(sev: str) -> str:
    return c(sev, *SEVERITY_STYLES.get(sev, ()))


def print_banner():
    lines = [
        f"{TOOL_NAME.upper()}  v{TOOL_VERSION}",
        "IDOR  |  Authorization Sweep  |  Information Disclosure",
        f"Author: {AUTHOR_HANDLE}   ({AUTHOR_URL})",
        "For authorized security testing only.",
    ]
    line_styles = [
        ("bold", "bright_magenta"),
        ("bright_cyan",),
        ("dim", "white"),
        ("dim", "yellow"),
    ]
    width = max(len(l) for l in lines) + 4
    top = "\u2554" + "\u2550" * width + "\u2557"
    bottom = "\u255a" + "\u2550" * width + "\u255d"

    print(c(top, "bright_cyan"))
    for line, styles in zip(lines, line_styles):
        pad = width - len(line)
        left = pad // 2
        right = pad - left
        print(c("\u2551", "bright_cyan") + " " * left + c(line, *styles) +
              " " * right + c("\u2551", "bright_cyan"))
    print(c(bottom, "bright_cyan"))
    print()


# --------------------------------------------------------------------------- #
# Data model for findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    attack_point: str          # "IDOR" | "AUTH-SWEEP" | "DISCLOSURE"
    severity: str              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    endpoint: str
    evidence: str
    recommendation: str


@dataclass
class TestRun:
    target: str
    started_at: str
    finished_at: Optional[str] = None
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    tool: dict = field(default_factory=lambda: {
        "name": TOOL_NAME, "version": TOOL_VERSION,
        "author": AUTHOR_HANDLE, "author_url": AUTHOR_URL,
    })


# --------------------------------------------------------------------------- #
# Core engine
# --------------------------------------------------------------------------- #

class JuiceShopSecurityTester:
    """
    Shared engine: one HTTP session, one auth/token handling layer, one
    findings/report sink. Each attack-point test is a method on this class so
    they can reuse login state, request helpers, and the finding collector.
    """

    TIMEOUT = 8  # seconds - keep low so a hung/firewalled target fails fast

    def __init__(self, target: str, username: Optional[str] = None,
                 password: Optional[str] = None, verbose: bool = False):
        self.target = target.rstrip("/")
        self.session = requests.Session()
        self.verbose = verbose
        self.token = None          # JWT for primary test account
        self.user_id = None
        self.basket_id = None
        self.username = username
        self.password = password
        self.run = TestRun(target=self.target,
                            started_at=datetime.now(timezone.utc).isoformat())

    # ------------------------ low-level helpers --------------------------- #

    def log(self, msg: str):
        if self.verbose:
            print(c(f"[debug] {msg}", "dim"))

    def _request(self, method: str, path: str, auth: bool = False,
                 expect_json: bool = True, **kwargs):
        """
        Centralized request wrapper: handles timeouts, connection errors and
        non-JSON bodies uniformly so every test module gets the same error
        handling for free.
        """
        url = self.target + path
        headers = kwargs.pop("headers", {}) or {}
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = self.session.request(method, url, headers=headers,
                                         timeout=self.TIMEOUT, **kwargs)
        except requests.exceptions.ConnectTimeout:
            self._error(path, "Connection timed out - is the target reachable?")
            return None
        except requests.exceptions.ConnectionError as e:
            self._error(path, f"Connection error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            self._error(path, f"Unexpected request error: {e}")
            return None

        body = None
        if expect_json:
            try:
                body = resp.json()
            except ValueError:
                body = None  # non-JSON response; caller decides if that matters
        return resp, body

    def _error(self, path: str, message: str):
        self.run.errors.append({"endpoint": path, "error": message})
        print(c(f"[!] ERROR on {path}: {message}", "bright_red"))

    def _add_finding(self, attack_point: str, severity: str, title: str,
                      endpoint: str, evidence: str, recommendation: str):
        f = Finding(attack_point, severity, title, endpoint, evidence, recommendation)
        self.run.findings.append(asdict(f))
        print(f"  [{colorize_severity(severity)}] {title}  ->  {c(endpoint, 'bright_white')}")

    @staticmethod
    def _rand_str(n=8):
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    @staticmethod
    def _decode_jwt_payload(token: str) -> dict:
        """
        Juice Shop JWTs are signed but not encrypted, so the payload can be
        read without verifying the signature (we don't need to verify it -
        we already obtained this token from our own authenticated login).
        """
        try:
            payload_b64 = token.split(".")[1]
            padding = "=" * (-len(payload_b64) % 4)
            decoded = base64.urlsafe_b64decode(payload_b64 + padding)
            return json.loads(decoded)
        except (IndexError, ValueError, UnicodeDecodeError):
            return {}

    # ------------------------ account bootstrap ---------------------------- #

    def ensure_account(self):
        """
        Logs in with supplied credentials, or registers a fresh throwaway
        account if none were given. Needed because the IDOR and auth-sweep
        tests need a valid low-privilege session to compare against.
        """
        if not self.username:
            self.username = f"sectest_{self._rand_str()}@juice-sh.op"
            self.password = "TestPass123!"
            print(c(f"[*] No credentials supplied - registering throwaway account: "
                    f"{self.username}", "cyan"))
            result = self._request(
                "POST", "/api/Users",
                json={"email": self.username, "password": self.password,
                      "passwordRepeat": self.password, "securityQuestion": None,
                      "role": "customer"},
            )
            if result is None:
                print(c("[!] Could not register a test account; "
                        "auth-dependent tests will be skipped.", "bright_yellow"))
                return False
            resp, _ = result
            if resp.status_code not in (200, 201):
                print(c(f"[!] Registration returned HTTP {resp.status_code}; "
                        f"auth-dependent tests will be skipped.", "bright_yellow"))
                return False

        print(c(f"[*] Logging in as {self.username}", "cyan"))
        result = self._request("POST", "/rest/user/login",
                                json={"email": self.username, "password": self.password})
        if result is None:
            return False
        resp, body = result
        if resp.status_code != 200 or not body:
            print(c(f"[!] Login failed (HTTP {resp.status_code}); "
                    f"auth-dependent tests will be skipped.", "bright_yellow"))
            return False

        auth_block = body.get("authentication", {})
        self.token = auth_block.get("token")

        # Juice Shop's login response hands back the session's own basket id
        # directly as "bid" - no need to guess it.
        self.basket_id = auth_block.get("bid")

        # The numeric user id isn't in the login body at all; it's a claim
        # inside the JWT payload itself (under "data"). Decode it rather than
        # assuming a field name that may not exist in this response shape.
        jwt_payload = self._decode_jwt_payload(self.token) if self.token else {}
        self.user_id = (jwt_payload.get("data") or {}).get("id")

        self.log(f"Logged in, userId={self.user_id}, basket_id={self.basket_id}, "
                 f"token acquired={bool(self.token)}")
        return bool(self.token)

    def _get_own_basket_id(self):
        """
        Fallback only: used if the login response didn't include "bid" for
        some reason (e.g. a future Juice Shop version changes the response
        shape). Confirms a basket id by actually requesting it rather than
        assuming id == user id.
        """
        if self.basket_id is not None:
            return self.basket_id
        if self.user_id is not None:
            result = self._request("GET", "/rest/basket/" + str(self.user_id), auth=True)
            if result:
                resp, _ = result
                if resp.status_code == 200:
                    return self.user_id
        for candidate in range(1, 6):
            result = self._request("GET", f"/rest/basket/{candidate}", auth=True)
            if result is None:
                continue
            resp, _ = result
            if resp.status_code == 200:
                return candidate
        return None

    # ===================================================================== #
    # Attack Point 1: IDOR on /rest/basket/:id
    # ===================================================================== #

    def test_idor_basket(self, id_range: int = 6):
        """
        Methodology:
          1. Log in as a normal low-privilege account and identify its own
             basket id.
          2. Request a small window of basket ids on either side of the
             account's own id, using that account's own valid JWT.
          3. A basket id is a finding if the server returns HTTP 200 AND the
             returned basket's userId does not match the authenticated
             account's own user id (i.e. access-control, not just
             not-found, is broken).
          4. As a secondary check, attempt a PUT to a foreign basket id to
             see whether write access is also exposed, not just read.
        """
        print(c("\n=== Attack Point 1: IDOR - /rest/basket/:id ===", "bold", "bright_cyan"))
        if not self.token:
            print(c("[!] Skipped: no authenticated session available.", "bright_yellow"))
            return

        self.basket_id = self._get_own_basket_id()
        if self.basket_id is None:
            print(c("[!] Could not determine own basket id; skipping IDOR test.", "bright_yellow"))
            return
        print(c(f"[*] Own basket id resolved to: {self.basket_id}", "cyan"))

        tested = 0
        confirmed = 0
        low = max(1, self.basket_id - id_range)
        high = self.basket_id + id_range

        for candidate_id in range(low, high + 1):
            if candidate_id == self.basket_id:
                continue
            result = self._request("GET", f"/rest/basket/{candidate_id}", auth=True)
            tested += 1
            if result is None:
                continue
            resp, body = result

            try:
                if resp.status_code == 200 and isinstance(body, dict):
                    # .get("data", {}) only falls back to {} when the key is
                    # MISSING - if the key exists but is JSON null, it
                    # returns None instead, which then crashes the next
                    # .get() call. The "or {}" catches both cases.
                    data = body.get("data") or {}
                    if not isinstance(data, dict):
                        continue
                    owner = data.get("UserId") or data.get("userId")
                    if owner is not None and str(owner) != str(self.user_id):
                        confirmed += 1
                        self._add_finding(
                            attack_point="IDOR",
                            severity="CRITICAL",
                            title="Basket IDOR - cross-user basket read",
                            endpoint=f"GET /rest/basket/{candidate_id}",
                            evidence=(f"Authenticated as user {self.user_id}; request for "
                                      f"basket {candidate_id} returned HTTP 200 with data "
                                      f"belonging to UserId={owner}."),
                            recommendation=("Enforce an ownership check server-side: the "
                                             "basket id in the URL must belong to the "
                                             "authenticated user's own session before any "
                                             "data is returned."),
                        )
                        # secondary check: is write access also exposed?
                        put_result = self._request(
                            "PUT", f"/api/BasketItems/{candidate_id}", auth=True,
                            json={"quantity": 1})
                        if put_result:
                            put_resp, _ = put_result
                            if put_resp.status_code in (200, 201):
                                self._add_finding(
                                    attack_point="IDOR",
                                    severity="CRITICAL",
                                    title="Basket IDOR - cross-user WRITE access",
                                    endpoint=f"PUT /api/BasketItems/{candidate_id}",
                                    evidence=(f"Write to another user's basket item "
                                              f"succeeded with HTTP {put_resp.status_code}."),
                                    recommendation=("Ownership checks must cover write "
                                                     "operations, not only reads."),
                                )
                elif resp.status_code not in (401, 403, 404):
                    self.log(f"Unexpected status {resp.status_code} for basket {candidate_id}")
            except (AttributeError, TypeError, KeyError) as e:
                # A malformed/unexpected response shape on one id should never
                # take down the whole test run - log it and keep going.
                self._error(f"/rest/basket/{candidate_id}",
                            f"Could not parse response body: {e}")

        self.run.summary["idor_baskets_tested"] = tested
        self.run.summary["idor_confirmed"] = confirmed
        if confirmed == 0:
            print(c(f"[*] Tested {tested} neighboring basket ids - "
                    f"no cross-user access observed.", "green"))

    # ===================================================================== #
    # Attack Point 2: Authorization consistency sweep
    # ===================================================================== #

    def test_auth_sweep(self):
        """
        Methodology:
          Each endpoint below is tagged with its *expected* access level based
          on Week 1 manual testing. The tool sends each request two ways -
          with no token and with a valid low-privilege token - and flags any
          endpoint whose observed behaviour doesn't match the expected level.
          This turns the manual RBAC spot-checks from Week 1 (admin panel vs.
          /#/accounting) into a repeatable sweep that also covers the
          underlying API, not just the two routes checked by hand.

          expected values:
            "public"        -> should return 200 with no auth at all
            "auth"          -> should return 401/403 with no auth,
                                200 with a valid session
            "admin"         -> should return 401/403 for both anonymous
                                AND a normal low-privilege session
        """
        print(c("\n=== Attack Point 2: Authorization consistency sweep ===", "bold", "bright_cyan"))

        endpoints = [
            ("GET",  "/api/Products",            "public"),
            ("GET",  "/api/Challenges",           "public"),
            ("GET",  "/api-docs",                 "public"),
            ("GET",  "/api/Users",                "auth"),
            ("GET",  f"/rest/basket/{self.user_id or 1}", "auth"),
            ("GET",  "/api/SecurityAnswers",      "auth"),
            ("DELETE", "/api/Products/1",         "admin"),
        ]

        for method, path, expected in endpoints:
            # 1) anonymous
            anon_sess = requests.Session()
            try:
                anon_resp = anon_sess.request(method, self.target + path, timeout=self.TIMEOUT)
            except requests.exceptions.RequestException as e:
                self._error(path, f"Anonymous request failed: {e}")
                continue

            # 2) authenticated (low privilege)
            auth_status = None
            if self.token:
                result = self._request(method, path, auth=True, expect_json=False)
                if result:
                    auth_resp, _ = result
                    auth_status = auth_resp.status_code

            anon_status = anon_resp.status_code
            self.log(f"{method} {path}: anon={anon_status} auth={auth_status} expected={expected}")

            if expected == "public":
                if anon_status >= 400:
                    self._add_finding(
                        attack_point="AUTH-SWEEP", severity="LOW",
                        title="Expected-public endpoint unexpectedly restricted",
                        endpoint=f"{method} {path}",
                        evidence=f"Anonymous request returned HTTP {anon_status}, "
                                 f"expected 2xx for a documented public endpoint.",
                        recommendation="Confirm this is intentional; otherwise verify "
                                        "legitimate anonymous use cases still work.")
            elif expected == "auth":
                if anon_status < 400:
                    self._add_finding(
                        attack_point="AUTH-SWEEP", severity="HIGH",
                        title="Session-gated endpoint reachable without authentication",
                        endpoint=f"{method} {path}",
                        evidence=f"Anonymous request returned HTTP {anon_status} "
                                 f"instead of a 401/403 for an endpoint that should "
                                 f"require a valid session.",
                        recommendation="Add/verify server-side authentication "
                                        "middleware on this route.")
                if auth_status is not None and auth_status >= 400:
                    self.log(f"Note: authenticated request to {path} also rejected "
                             f"({auth_status}); may indicate a broken, not missing, check.")
            elif expected == "admin":
                if anon_status < 400:
                    self._add_finding(
                        attack_point="AUTH-SWEEP", severity="CRITICAL",
                        title="Admin-only endpoint reachable without authentication",
                        endpoint=f"{method} {path}",
                        evidence=f"Anonymous request returned HTTP {anon_status}.",
                        recommendation="Require authentication and an explicit role "
                                        "check before executing this action.")
                elif auth_status is not None and auth_status < 400:
                    self._add_finding(
                        attack_point="AUTH-SWEEP", severity="HIGH",
                        title="Admin-only endpoint reachable by a low-privilege account",
                        endpoint=f"{method} {path}",
                        evidence=f"A standard (non-admin) authenticated session "
                                 f"received HTTP {auth_status} instead of 401/403.",
                        recommendation="Add an explicit role check (e.g. role==admin) "
                                        "in addition to authentication.")

        sweep_findings = [f for f in self.run.findings if f["attack_point"] == "AUTH-SWEEP"]
        if sweep_findings:
            print(c(f"[*] Swept {len(endpoints)} endpoints - {len(sweep_findings)} "
                    f"authorization issue(s) found above.", "bright_yellow"))
        else:
            print(c(f"[*] Swept {len(endpoints)} endpoints - all behaved as expected "
                    f"(no authorization inconsistencies found).", "green"))

    # ===================================================================== #
    # Attack Point 3: Hidden path & information disclosure scan
    # ===================================================================== #

    def test_disclosure(self):
        """
        Methodology:
          Probe a fixed list of paths flagged as non-obvious or
          security-relevant during Week 1 recon (robots.txt-referenced /ftp,
          /encryptionkeys, Swagger docs) plus a short list of common
          backup/config file extensions inside any directory listing found.
          Also inspects response headers on the homepage for framework
          fingerprinting headers that aid reconnaissance. A finding is any
          path returning 200 with a directory listing or file content that
          should not be anonymously reachable, or a header that discloses
          stack details unnecessarily.
        """
        print(c("\n=== Attack Point 3: Hidden path & disclosure scan ===", "bold", "bright_cyan"))

        hidden_paths = [
            "/robots.txt",
            "/ftp",
            "/ftp/",
            "/encryptionkeys",
            "/encryptionkeys/",
            "/api-docs",
            "/.well-known/security.txt",
        ]
        backup_extensions = [".bak", ".kdbx", ".yml", ".key", ".md"]

        for path in hidden_paths:
            result = self._request("GET", path, expect_json=False)
            if result is None:
                continue
            resp, _ = result
            if resp.status_code == 200:
                text_sample = resp.text[:200].replace("\n", " ")
                looks_like_listing = any(ext in resp.text for ext in backup_extensions)
                severity = "HIGH" if looks_like_listing or "ftp" in path or "encryptionkeys" in path else "LOW"
                self._add_finding(
                    attack_point="DISCLOSURE",
                    severity=severity,
                    title=f"Anonymously reachable path: {path}",
                    endpoint=f"GET {path}",
                    evidence=f"HTTP 200. First 200 chars: {text_sample!r}",
                    recommendation=("Remove this path from the deployed build, or place "
                                     "it behind authentication / a reverse-proxy deny "
                                     "rule if it must exist.")
                )

        # Header fingerprinting
        result = self._request("GET", "/", expect_json=False)
        if result:
            resp, _ = result
            disclosive_headers = ["X-Powered-By", "Server"]
            found = {h: resp.headers[h] for h in disclosive_headers if h in resp.headers}
            if found:
                self._add_finding(
                    attack_point="DISCLOSURE",
                    severity="INFO",
                    title="Framework/stack fingerprinting header present",
                    endpoint="GET /",
                    evidence=f"Headers disclosed: {found}",
                    recommendation=("Suppress or rewrite default framework headers "
                                     "(e.g. via helmet's hidePoweredBy) in production.")
                )

        print(c(f"[*] Probed {len(hidden_paths)} hidden/legacy paths and response headers.", "cyan"))

    # ------------------------------ report --------------------------------- #

    def finalize(self):
        if self.run.finished_at is None:
            self.run.finished_at = datetime.now(timezone.utc).isoformat()
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.run.findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        self.run.summary["severity_counts"] = sev_counts
        self.run.summary["total_findings"] = len(self.run.findings)
        self.run.summary["errors_encountered"] = len(self.run.errors)
        return self.run

    def _grouped_findings(self):
        """
        Returns findings grouped by severity, ordered CRITICAL -> INFO,
        skipping any severity with zero findings. Used so every report
        format (TOC, sectioned body, summary) agrees on the same grouping.
        """
        run = self.finalize()
        groups = {sev: [] for sev in SEVERITY_ORDER}
        for f in run.findings:
            groups.setdefault(f["severity"], []).append(f)
        return [(sev, items) for sev in SEVERITY_ORDER if (items := groups.get(sev))] + \
               [(sev, items) for sev, items in groups.items()
                if sev not in SEVERITY_ORDER and items]

    def print_report(self):
        run = self.finalize()
        width = 70
        print("\n" + c("=" * width, "bright_cyan"))
        print(c(f" SECURITY TEST REPORT - {run.target}", "bold", "bright_white"))
        print(c(f" Started:  {run.started_at}", "dim"))
        print(c(f" Finished: {run.finished_at}", "dim"))
        print(c(f" Tool: {TOOL_NAME} v{TOOL_VERSION}  |  Author: {AUTHOR_HANDLE}", "dim"))
        print(c("=" * width, "bright_cyan"))

        if not run.findings:
            print(c("\nNo findings recorded.", "green"))
        for f in run.findings:
            print(f"\n[{colorize_severity(f['severity'])}] {c(f['title'], 'bold')}")
            print(f"  Attack point : {f['attack_point']}")
            print(f"  Endpoint     : {c(f['endpoint'], 'bright_white')}")
            print(f"  Evidence     : {f['evidence']}")
            print(f"  Recommend    : {f['recommendation']}")

        if run.errors:
            print(c(f"\n{len(run.errors)} request error(s) encountered "
                    f"(see JSON/HTML report for detail).", "bright_yellow"))

        print(c("\nSeverity summary:", "bold"))
        for sev, count in run.summary.get("severity_counts", {}).items():
            bar = "\u2588" * count if count else ""
            print(f"  {colorize_severity(sev):>18}  {count:>3}  {c(bar, *SEVERITY_STYLES.get(sev, ()))}")

    # ---- export: JSON -------------------------------------------------- #

    def save_json(self, path: str):
        run = self.finalize()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(run), fh, indent=2)
        print(c(f"[*] JSON report written to {path}", "green"))

    # ---- export: HTML ---------------------------------------------------- #

    def save_html(self, path: str):
        run = self.finalize()
        grouped = self._grouped_findings()

        def esc(x):
            return html.escape(str(x))

        def anchor_for(sev, idx):
            return f"finding-{sev.lower()}-{idx}"

        # Table of contents: one color-coded block per severity level, each
        # listing its findings as jump links down to that finding's row.
        toc_blocks = ""
        for sev, items in grouped:
            color = SEVERITY_HEX.get(sev, "#444")
            toc_links = "".join(
                f'<li><a href="#{anchor_for(sev, i)}">{esc(f["title"])}'
                f'<span class="toc-endpoint"> &mdash; {esc(f["endpoint"])}</span></a></li>'
                for i, f in enumerate(items)
            )
            toc_blocks += (
                f'<div class="toc-group" style="border-left:4px solid {color}">'
                f'<div class="toc-heading" style="color:{color}">{esc(sev)} '
                f'<span class="toc-count">({len(items)})</span></div>'
                f'<ul>{toc_links}</ul></div>'
            )
        if not toc_blocks:
            toc_blocks = '<p style="color:#8b949e;">No findings recorded.</p>'

        # Findings body: grouped under the same severity sections as the TOC,
        # each finding anchored so the TOC links land on it directly.
        sections = ""
        for sev, items in grouped:
            color = SEVERITY_HEX.get(sev, "#444")
            rows = ""
            for i, f in enumerate(items):
                rows += (
                    f'<tr id="{anchor_for(sev, i)}">'
                    f'<td><span class="badge" style="background:{color}">{esc(f["severity"])}</span></td>'
                    f'<td>{esc(f["attack_point"])}</td>'
                    f'<td>{esc(f["title"])}</td>'
                    f'<td><code>{esc(f["endpoint"])}</code></td>'
                    f'<td>{esc(f["evidence"])}</td>'
                    f'<td>{esc(f["recommendation"])}</td>'
                    '</tr>'
                )
            sections += (
                f'<h3 style="color:{color}; border-bottom:2px solid {color};">'
                f'{esc(sev)} <span class="toc-count">({len(items)})</span></h3>'
                '<table><tr><th>Severity</th><th>Attack Point</th><th>Title</th>'
                '<th>Endpoint</th><th>Evidence</th><th>Recommendation</th></tr>'
                f'{rows}</table>'
            )
        if not sections:
            sections = '<p style="color:#8b949e;">No findings recorded.</p>'

        summary_cards = ""
        for sev, count in run.summary.get("severity_counts", {}).items():
            color = SEVERITY_HEX.get(sev, "#444")
            summary_cards += (
                f'<div class="card" style="border-top:4px solid {color}">'
                f'<div class="count" style="color:{color}">{count}</div>'
                f'<div class="label">{sev}</div></div>'
            )

        error_rows = ""
        for e in run.errors:
            error_rows += f'<li><code>{esc(e["endpoint"])}</code> — {esc(e["error"])}</li>'
        errors_block = (
            f'<h2>Request Errors ({len(run.errors)})</h2><ul>{error_rows}</ul>'
            if run.errors else ""
        )

        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{esc(TOOL_NAME)} — Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    font-family: "Segoe UI", Roboto, Arial, sans-serif;
    background: #0d1117; color: #c9d1d9; margin: 0; padding: 2.5rem;
    line-height: 1.5;
  }}
  h1 {{ color: #58a6ff; margin-bottom: 0.25rem; }}
  h2 {{ color: #58a6ff; margin-top: 2.5rem; }}
  .subtitle {{ color: #8b949e; margin-bottom: 1.75rem; font-size: 0.95rem; }}
  .meta {{ color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }}
  .meta code {{ color: #79c0ff; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{
    background: #161b22; border-radius: 10px; padding: 1rem 1.75rem;
    min-width: 110px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.4);
  }}
  .card .count {{ font-size: 2.1rem; font-weight: 700; }}
  .card .label {{ color: #8b949e; font-size: 0.8rem; letter-spacing: 1px; margin-top: 0.25rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; }}
  th, td {{ padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.88rem; vertical-align: top; }}
  th {{ background: #21262d; color: #58a6ff; font-weight: 600; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ color: white; padding: 3px 11px; border-radius: 12px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.5px; white-space: nowrap; }}
  .toc {{ background: #161b22; border-radius: 10px; padding: 1.25rem 1.75rem; margin-bottom: 2rem; }}
  .toc-group {{ padding: 0.5rem 0 0.5rem 1rem; margin-bottom: 0.5rem; }}
  .toc-heading {{ font-weight: 700; letter-spacing: 0.5px; font-size: 0.95rem; margin-bottom: 0.3rem; }}
  .toc-count {{ color: #8b949e; font-weight: 400; }}
  .toc-group ul {{ margin: 0; padding-left: 1.1rem; }}
  .toc-group li {{ margin: 0.2rem 0; }}
  .toc-group a {{ color: #c9d1d9; text-decoration: none; }}
  .toc-group a:hover {{ text-decoration: underline; }}
  .toc-endpoint {{ color: #6e7681; font-size: 0.82rem; }}
  code {{ color: #79c0ff; background: #0d1117; padding: 1px 5px; border-radius: 4px; }}
  ul {{ color: #c9d1d9; }}
  footer {{ margin-top: 3rem; color: #6e7681; font-size: 0.82rem; border-top: 1px solid #21262d; padding-top: 1rem; }}
  footer a {{ color: #58a6ff; text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
  <h1>&#x1F9C3; OWASP Juice Shop &mdash; Security Test Report</h1>
  <div class="subtitle">Automated attack-point testing: IDOR &middot; Authorization Sweep &middot; Information Disclosure</div>
  <div class="meta">
    Target: <code>{esc(run.target)}</code><br>
    Started: {esc(run.started_at)}<br>
    Finished: {esc(run.finished_at)}<br>
    Total findings: {esc(run.summary.get("total_findings", 0))} &nbsp;|&nbsp; Request errors: {esc(len(run.errors))}
  </div>

  <div class="summary">{summary_cards}</div>

  <h2>Table of Contents</h2>
  <div class="toc">{toc_blocks}</div>

  <h2>Findings</h2>
  {sections}

  {errors_block}

  <footer>
    Generated by <strong>{esc(TOOL_NAME)} v{esc(TOOL_VERSION)}</strong><br>
    Author: <a href="{esc(AUTHOR_URL)}">{esc(AUTHOR_HANDLE)}</a> &mdash;
    For authorized security testing only.
  </footer>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(doc)
        print(c(f"[*] HTML report written to {path}", "green"))

    # ---- export: PDF ------------------------------------------------------ #

    def save_pdf(self, path: str):
        try:
            from fpdf import FPDF
            from fpdf.enums import XPos, YPos
        except ImportError:
            print(c("[!] PDF export requires the 'fpdf2' package. Install with:\n"
                    "    pip install fpdf2 --break-system-packages", "bright_yellow"))
            return

        run = self.finalize()

        def safe(text) -> str:
            # Core PDF fonts only support latin-1; replace anything outside it
            # rather than crashing the whole report over one odd character.
            return str(text).encode("latin-1", "replace").decode("latin-1")

        def hex_to_rgb(h):
            h = h.lstrip("#")
            return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

        def wrappable(text, chunk=40) -> str:
            """
            fpdf2 can only wrap a line at whitespace/hyphens. A long
            unbroken token (a URL with no slash near the margin, a raw
            stack trace, etc.) can otherwise be wider than the page and
            crash multi_cell with FPDFException. Insert a plain space every
            `chunk` characters inside any run of non-whitespace longer than
            that, so it always has somewhere to break. (Not a zero-width
            space: the core PDF fonts are latin-1 only, and safe() would
            replace a zero-width space with a visible '?'.)
            """
            return re.sub(
                r"\S{%d,}" % chunk,
                lambda m: " ".join(
                    m.group(0)[i:i + chunk] for i in range(0, len(m.group(0)), chunk)
                ),
                str(text),
            )

        def safe_multicell(w, h, text):
            """
            Resilient replacement for pdf.multi_cell(). fpdf2 can end up
            with the cursor not fully back at the left margin after an
            automatic page break fires mid-list - even on short, harmless
            text - which then makes multi_cell compute a near-zero
            available width and raise FPDFException. Force the cursor back
            to the left margin before writing, retry once on a fresh page
            if that still fails, and as a last resort fall back to a
            single truncated line rather than letting one bad line take
            down the entire report.
            """
            try:
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(w, h, text)
                return
            except Exception:
                pass
            try:
                pdf.add_page()
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(w, h, text)
                return
            except Exception:
                pass
            print(c("[!] PDF: had to shorten one report line to keep rendering "
                    "(full text is still in the JSON/HTML report).", "bright_yellow"))
            try:
                pdf.set_x(pdf.l_margin)
                truncated = text if len(text) <= 90 else text[:87] + "..."
                pdf.cell(0, h, truncated, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            except Exception:
                pass  # genuinely nothing more we can safely try - skip this line

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 17)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 10, safe("OWASP Juice Shop - Security Test Report"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(90, 90, 90)
        pdf.cell(0, 6, safe(f"Target: {run.target}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 6, safe(f"Started:  {run.started_at}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 6, safe(f"Finished: {run.finished_at}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 6, safe(f"Tool: {TOOL_NAME} v{TOOL_VERSION}  |  Author: {AUTHOR_HANDLE} ({AUTHOR_URL})"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Severity Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        for sev, count in run.summary.get("severity_counts", {}).items():
            r, g, b = hex_to_rgb(SEVERITY_HEX.get(sev, "#333333"))
            pdf.set_text_color(r, g, b)
            pdf.cell(0, 6, safe(f"{sev}: {count}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        grouped = self._grouped_findings()

        # One internal link target per finding, created up front so the TOC
        # (rendered before we know what page each finding lands on) can
        # already point at it; set_link() below binds each target once we
        # actually render that finding.
        link_ids = {
            (sev, i): pdf.add_link()
            for sev, items in grouped for i in range(len(items))
        }

        # ---- Table of Contents: one color-coded, clickable block per
        # severity level, grouped the same way the findings body is. ---- #
        pdf.add_page()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 10, "Table of Contents", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        if not grouped:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(90, 90, 90)
            safe_multicell(0, 6, "No findings recorded.")

        for sev, items in grouped:
            r, g, b = hex_to_rgb(SEVERITY_HEX.get(sev, "#333333"))
            pdf.set_text_color(r, g, b)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, safe(f"{sev}  ({len(items)})"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(40, 40, 40)
            for i, f in enumerate(items):
                pdf.cell(6)  # indent
                pdf.cell(0, 6, safe(wrappable(f"- {f['title']}  [{f['endpoint']}]")),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT, link=link_ids[(sev, i)])
            pdf.ln(3)

        # ---- Findings body: grouped under the same color-coded section
        # headers as the TOC; each finding's link target is bound here. ---- #
        pdf.add_page()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 10, "Findings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if not run.findings:
            pdf.set_font("Helvetica", "", 10)
            safe_multicell(0, 6, "No findings recorded.")

        for sev, items in grouped:
            r, g, b = hex_to_rgb(SEVERITY_HEX.get(sev, "#333333"))
            pdf.ln(3)
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, safe(f"  {sev}  ({len(items)})"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
            pdf.set_text_color(0, 0, 0)

            for i, f in enumerate(items):
                pdf.set_link(link_ids[(sev, i)], y=-1)
                pdf.set_xy(pdf.l_margin, pdf.get_y() + 2)
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(r, g, b)
                safe_multicell(0, 6, safe(wrappable(f"[{f['severity']}] {f['title']}")))
                pdf.set_text_color(40, 40, 40)
                pdf.set_font("Helvetica", "", 9.5)
                safe_multicell(0, 5, safe(f"Attack point: {f['attack_point']}"))
                safe_multicell(0, 5, safe(wrappable(f"Endpoint: {f['endpoint']}")))
                safe_multicell(0, 5, safe(wrappable(f"Evidence: {f['evidence']}")))
                safe_multicell(0, 5, safe(wrappable(f"Recommendation: {f['recommendation']}")))

        if run.errors:
            pdf.ln(4)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, f"Request Errors ({len(run.errors)})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 9.5)
            for e in run.errors:
                safe_multicell(0, 5, safe(wrappable(f"- {e['endpoint']}: {e['error']}")))

        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(130, 130, 130)
        pdf.ln(6)
        pdf.multi_cell(0, 5, safe(f"Generated by {TOOL_NAME} v{TOOL_VERSION} "
                                  f"- Author {AUTHOR_HANDLE} ({AUTHOR_URL}) "
                                  f"- For authorized security testing only."))

        pdf.output(path)
        print(c(f"[*] PDF report written to {path}", "green"))

    def export(self, base_path: str, fmt: str):
        """fmt: 'json' | 'html' | 'pdf' | 'all'"""
        if fmt in ("json", "all"):
            self.save_json(base_path + ".json")
        if fmt in ("html", "all"):
            self.save_html(base_path + ".html")
        if fmt in ("pdf", "all"):
            self.save_pdf(base_path + ".pdf")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Automated security tester for authorized OWASP Juice Shop instances."
    )
    parser.add_argument("--target", required=True,
                         help="Base URL of the Juice Shop instance, e.g. http://localhost:3000")
    parser.add_argument("--test", choices=["idor", "auth", "disclosure", "all"], default="all",
                         help="Which attack point(s) to run (default: all)")
    parser.add_argument("--username", help="Existing account email (optional)")
    parser.add_argument("--password", help="Existing account password (optional)")
    parser.add_argument("--output", default="juice_shop_report",
                         help="Base filename (no extension) for the report (default: "
                              "juice_shop_report). If a relative name is given, the "
                              "report is still written next to this script, not the "
                              "current working directory - pass an absolute path to "
                              "override that.")
    parser.add_argument("--format", choices=["json", "html", "pdf", "all"], default="all",
                         help="Report format(s) to generate (default: all - JSON, HTML "
                              "and PDF are generated automatically on every run)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--verbose", action="store_true", help="Print debug info")
    args = parser.parse_args()

    global COLOR_ENABLED
    if args.no_color:
        COLOR_ENABLED = False

    print_banner()
    print(c(f"[*] Target: {args.target}", "bold"))
    print(c("[*] Reminder: only run this against instances you own or are authorized to test.\n",
            "dim", "yellow"))

    tester = JuiceShopSecurityTester(args.target, args.username, args.password, args.verbose)

    # Basic reachability check before doing anything else
    result = tester._request("GET", "/", expect_json=False)
    if result is None:
        print(c("[!] Target unreachable. Aborting.", "bold", "bright_red"))
        sys.exit(1)

    auth_ready = tester.ensure_account()

    if args.test in ("idor", "all"):
        if auth_ready:
            tester.test_idor_basket()
        else:
            print(c("\n=== Attack Point 1: IDOR - skipped (no auth session) ===", "bright_yellow"))

    if args.test in ("auth", "all"):
        tester.test_auth_sweep()

    if args.test in ("disclosure", "all"):
        tester.test_disclosure()

    tester.print_report()

    # Always land reports in the folder this script lives in, regardless of
    # the caller's current working directory - unless they explicitly gave
    # an absolute path, in which case that choice wins.
    output_base = args.output if os.path.isabs(args.output) \
        else os.path.join(SCRIPT_DIR, args.output)
    tester.export(output_base, args.format)


if __name__ == "__main__":
    main()
