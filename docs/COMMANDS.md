# Command Reference

Standalone reference for every flag `juice_shop_security_tester.py` accepts.
See the main [README](../README.md) for installation and conceptual docs.

## Syntax

```
python3 juice_shop_security_tester.py --target <url> [options]
```

`--target` is the only required argument. Everything else has a sensible
default (every test runs, every report format is generated).

## Flags at a glance

| Flag | Required | Takes a value | Choices | Default | Purpose |
|---|---|---|---|---|---|
| `--target` | Yes | Yes | any URL | — | Base URL of the Juice Shop instance to test |
| `--test` | No | Yes | `idor`, `auth`, `disclosure`, `all` | `all` | Which attack point(s) to run |
| `--username` | No | Yes | any string | — | Existing account email |
| `--password` | No | Yes | any string | — | Existing account password |
| `--output` | No | Yes | any filename/path | `juice_shop_report` | Base filename (no extension) for reports |
| `--format` | No | Yes | `json`, `html`, `pdf`, `all` | `all` | Which report format(s) to write |
| `--no-color` | No | No (flag) | — | off | Disable ANSI color in terminal output |
| `--verbose` | No | No (flag) | — | off | Print `[debug]` diagnostic lines |

## `--target`

```bash
--target http://localhost:3000
--target http://192.168.1.50:3000
--target https://juice-shop.internal.example.com
```

Must include the scheme (`http://` or `https://`). The tool strips any
trailing slash automatically.

## `--test`

```bash
--test all          # default — run IDOR, AUTH-SWEEP, and DISCLOSURE
--test idor          # only the /rest/basket/:id IDOR test
--test auth           # only the authorization consistency sweep
--test disclosure      # only the hidden-path/header disclosure scan
```

## `--username` / `--password`

Must be supplied **together**. If neither is given, the tool registers a
throwaway account automatically (`sectest_<8 random chars>@juice-sh.op`).

```bash
--username test@juice-sh.op --password TestPass123!
```

## `--output`

```bash
--output juice_shop_report          # default
--output my_pentest_run              # relative -> written next to the script
--output /home/kali/reports/run1      # absolute -> written exactly there
--output ~/reports/$(date +%F)_scan    # absolute, dated (shell-expanded)
```

Extensions are added automatically per format (`.json`, `.html`, `.pdf`) —
don't include them yourself.

## `--format`

```bash
--format all     # default — json + html + pdf
--format json      # just the JSON report
--format html        # just the HTML report
--format pdf           # just the PDF report
```

## `--no-color`

```bash
--no-color
```

Color is already auto-disabled when stdout isn't a real terminal (e.g. piped
to a file or `| tee`), so this flag mainly matters for a live terminal
session where you specifically don't want ANSI codes.

## `--verbose`

```bash
--verbose
```

Adds `[debug]` lines covering: login state (user id, basket id, whether a
token was acquired), unexpected (non-finding) status codes seen during the
IDOR sweep, and similar internals. Use this first when a test is behaving
unexpectedly or silently skipping.

## Full combinations

```bash
# Everything, defaults
python3 juice_shop_security_tester.py --target http://localhost:3000

# Authenticated, IDOR only, PDF only
python3 juice_shop_security_tester.py --target http://localhost:3000 \
  --username test@juice-sh.op --password TestPass123! \
  --test idor --format pdf

# Disclosure scan only, verbose, no color, logged to a file
python3 juice_shop_security_tester.py --target http://localhost:3000 \
  --test disclosure --verbose --no-color > scan.log

# Custom absolute output path, all formats
python3 juice_shop_security_tester.py --target http://localhost:3000 \
  --output /home/kali/reports/2026-10-13_juiceshop --format all

# Auth sweep only, throwaway account, JSON only (e.g. for CI pipelines)
python3 juice_shop_security_tester.py --target http://localhost:3000 \
  --test auth --format json --output ci_run
```
