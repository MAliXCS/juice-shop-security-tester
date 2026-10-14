# User Manual — Juice Shop Security Tester v1.0

A complete, step-by-step guide to every feature and the exact command that
triggers it. See the main [README](../README.md) for installation.

## Table of Contents

- [1. First run](#1-first-run)
- [2. Feature: IDOR test](#2-feature-idor-test)
- [3. Feature: Authorization sweep](#3-feature-authorization-sweep)
- [4. Feature: Disclosure scan](#4-feature-disclosure-scan)
- [5. Feature: Running as a known account](#5-feature-running-as-a-known-account)
- [6. Feature: Choosing report format(s)](#6-feature-choosing-report-formats)
- [7. Feature: Naming/placing the report](#7-feature-namingplacing-the-report)
- [8. Feature: Verbose debugging](#8-feature-verbose-debugging)
- [9. Reading the generated reports](#9-reading-the-generated-reports)

---

## 1. First run

**Command:**
```bash
python3 juice_shop_security_tester.py --target http://localhost:3000
```

**What happens:** the tool prints its banner (`v1.0`), does a reachability
check against your `--target`, registers a throwaway account
(`sectest_<random>@juice-sh.op`), logs in, and runs all three attack points
in order: IDOR → Authorization Sweep → Disclosure Scan. At the end it prints
a color-coded severity summary and writes `juice_shop_report.json`,
`juice_shop_report.html`, and `juice_shop_report.pdf` next to the script.

![Full run output](../screenshots/01-idor-attack.png)

---

## 2. Feature: IDOR test

**What it does:** confirms whether a normal user's session can read (and
write) *other users'* shopping baskets just by changing the basket id in
the URL.

**Command — run it on its own:**
```bash
python3 juice_shop_security_tester.py --target http://localhost:3000 --test idor
```

**How to read the result:** each `[CRITICAL]` line shows the exact endpoint
hit (`GET /rest/basket/6`) and an arrow to what it did. "cross-user basket
read" means a `GET` leaked another user's basket; "cross-user WRITE access"
means a `PUT` let you modify it. Both are logged separately, because an
application can block reads but still forget to block writes (or vice
versa).

![IDOR findings in the terminal](../screenshots/01-idor-attack.png)

---

## 3. Feature: Authorization sweep

**What it does:** walks a set of endpoints that are each supposed to behave
a specific way (public / needs login / needs admin) and checks that they
actually do.

**Command — run it on its own:**
```bash
python3 juice_shop_security_tester.py --target http://localhost:3000 --test auth
```

**How to read the result:** if everything behaves as expected, you'll see
`Swept N endpoints — all behaved as expected (no authorization
inconsistencies found).` If something is wrong, it's logged as a finding the
same way the other two tests are — same severity grouping, same report
sections.

---

## 4. Feature: Disclosure scan

**What it does:** checks a curated list of legacy/forgotten paths
(`/ftp`, `/encryptionkeys`, `/.well-known/security.txt`, etc.) and response
headers for anything an anonymous visitor shouldn't be able to see.

**Command — run it on its own:**
```bash
python3 juice_shop_security_tester.py --target http://localhost:3000 --test disclosure
```

**How to read the result:** `[HIGH]` findings are things like exposed
directory listings or key material; `[LOW]` findings are lower-risk metadata
(e.g. `robots.txt`). Each line shows the path, the endpoint hit, and in the
full report, the first 200 characters of what was actually returned.

![Disclosure scan findings](../screenshots/02-disclosure-and-findings.png)

---

## 5. Feature: Running as a known account

**What it does:** by default the tool registers a brand-new throwaway
account every run. If you'd rather test with an account you already know
the behavior of, supply both flags together:

```bash
python3 juice_shop_security_tester.py --target http://localhost:3000 \
  --username test@juice-sh.op --password TestPass123!
```

**When to use this:** useful for repeatable testing against a specific
seeded account, or when you want IDOR results to reference a predictable
user id instead of a randomly registered one.

---

## 6. Feature: Choosing report format(s)

**What it does:** by default the tool writes all three formats
(`--format all`). You can narrow that to just what you need:

```bash
# just JSON — good for piping into other tooling
python3 juice_shop_security_tester.py --target http://localhost:3000 --format json

# just the HTML report
python3 juice_shop_security_tester.py --target http://localhost:3000 --format html

# just the PDF report
python3 juice_shop_security_tester.py --target http://localhost:3000 --format pdf
```

**Why it matters:** PDF generation requires `fpdf2`; if it's not installed,
`--format json` or `--format html` still work with zero extra dependencies.

![Severity summary and all three reports written](../screenshots/03-severity-summary.png)

---

## 7. Feature: Naming/placing the report

**What it does:** controls the base filename (no extension) for the
generated reports.

```bash
# relative name — still lands next to the script itself
python3 juice_shop_security_tester.py --target http://localhost:3000 --output my_pentest_run

# absolute path — overrides that and writes exactly there
python3 juice_shop_security_tester.py --target http://localhost:3000 \
  --output /home/kali/reports/2026-10-13_juiceshop
```

**Why it matters:** no matter what directory you launched the script from,
a *relative* `--output` always writes next to `juice_shop_security_tester.py`
itself — so reports don't get scattered depending on your current shell
directory.

![Reports sitting next to the script](../screenshots/04-generated-reports-folder.png)

---

## 8. Feature: Verbose debugging

**What it does:** prints extra `[debug]` lines covering login state,
resolved basket/user ids, and any unexpected (non-finding) status codes
seen during the run.

```bash
python3 juice_shop_security_tester.py --target http://localhost:3000 --verbose
```

**When to use this:** first thing to reach for when a test is silently
skipping or behaving differently than expected — it shows you exactly what
the tool saw at each step.

---

## 9. Reading the generated reports

All three formats share the same structure:

1. **Severity summary** — counts per severity level.
2. **Table of contents** — color-coded, grouped by severity, with clickable
   jump links (HTML and PDF) straight to each finding.
3. **Findings**, grouped under color-coded severity section headers, each
   showing: attack point, endpoint, evidence, and recommendation.

Open `juice_shop_report.html` in any browser for the easiest way to browse
findings interactively, or `juice_shop_report.pdf` for something to hand to
someone else as-is. `juice_shop_report.json` is the same data in raw form,
for feeding into other tooling.
