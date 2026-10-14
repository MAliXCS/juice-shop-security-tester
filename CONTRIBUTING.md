# Contributing

Contributions are welcome, especially:

- New attack-point tests against Juice Shop (please follow the existing
  pattern: a method on `JuiceShopSecurityTester`, using `self._add_finding()`
  so it flows through the shared report pipeline automatically).
- Report format improvements (JSON / HTML / PDF).
- Bug fixes, especially around the PDF export (fpdf2 can be finicky across
  versions — see `safe_multicell()` for the defensive pattern already used
  there).

## Development setup

```bash
git clone https://github.com/MAliXCS/juice-shop-security-tester.git
cd juice-shop-security-tester
pip install -r requirements.txt -r requirements-dev.txt --break-system-packages
docker run --rm -p 3000:3000 bkimminich/juice-shop
python3 juice_shop_security_tester.py --target http://localhost:3000 --verbose
```

Please also read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) before
participating, and use the PR template that's pre-filled when you open a
pull request.

## Guidelines

- Keep every new test authorized-scope only — this tool is for testing
  instances you own or are explicitly permitted to test, and should never
  be adapted to target third-party infrastructure.
- New findings should go through `self._add_finding(attack_point, severity,
  title, endpoint, evidence, recommendation)` so they automatically appear
  in the severity summary, the table of contents, and all three report
  formats.
- If you touch `save_pdf()`, keep using the modern fpdf2 `new_x`/`new_y` API
  (not the deprecated `ln=True`) and route any new `multi_cell()` calls
  through `safe_multicell()` rather than calling it directly.
- Open a PR with a short description of what you tested it against (Juice
  Shop version, Python version, OS).

## Reporting a bug

Open an issue using the **Bug report** template (`.github/ISSUE_TEMPLATE/bug_report.md`),
which already prompts for:
- The exact command you ran
- Full traceback (if any)
- Your Python version and `pip show requests fpdf2` output
- Which Juice Shop version/deployment you targeted

If what you found is a **security** issue in the tool itself (not in Juice
Shop), see [`SECURITY.md`](SECURITY.md) instead of opening a public issue.
