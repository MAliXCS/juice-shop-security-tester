# Changelog

## v1.0 — Initial Release

Three-attack-point engine against OWASP Juice Shop, with a unified
severity-grouped reporting pipeline across JSON, HTML, and PDF.

**Attack points**
- IDOR sweep on `/rest/basket/:id` — confirms cross-user basket read **and**
  write access using only the testing account's own session.
- Authorization consistency sweep across public, session-gated, and
  admin-gated endpoints.
- Hidden-path & information-disclosure scan (legacy paths, exposed headers).

**Reporting**
- Color-coded, severity-grouped table of contents in both the HTML and PDF
  reports, with clickable jump links straight to each finding.
- Findings grouped into color-coded sections by severity
  (`CRITICAL → HIGH → MEDIUM → LOW → INFO`) across all report formats.
- Reports write to the folder the script itself lives in, not the caller's
  current working directory, unless an absolute `--output` path is given.
- `--format` defaults to `all` (JSON + HTML + PDF generated every run).

**PDF reliability**
- Replaced all deprecated fpdf2 `ln=True` calls with the modern
  `new_x`/`new_y` API, fixing a cursor-drift bug that could crash PDF
  generation (`FPDFException: Not enough horizontal space to render a
  single character`).
- Added `safe_multicell()`: a resilient wrapper around fpdf2's `multi_cell`
  that forces the cursor back to the left margin before writing, retries
  once on a fresh page on failure, and falls back to a truncated line (with
  a visible warning) rather than crashing the whole report.
- Added `wrappable()`: inserts safe break points into long unbroken strings
  (long URLs, raw evidence text) so they can never overflow a PDF cell.
- Removed dead space-padding on PDF field labels that could cause a label
  to wrap awkwardly onto its own line in a proportional font.
