# Contributing to Sentinel

Thanks for your interest in improving Sentinel. This project has an intentionally strict
architecture; the conventions below are not stylistic preferences, they are enforced
constraints. Please read this page before opening a pull request.

## Getting started

```bash
git clone https://github.com/Varethic/Sentinel.git
cd Sentinel
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[lint]"
sentinel --version
```

Requires **Python 3.11+**.

Before opening a pull request, please confirm both of these pass:

```bash
sentinel audit-code src     # must report 0 findings
sentinel rules              # every rule document must load
ruff check src              # lint, if you installed the lint extra
```

## Architectural rules

### 1. `src/`-only structure

The repository contains **only** a `src/` package plus top-level documentation. There is
no `tests/` directory and no `labs/` directory, and pull requests must not add them.

```
src/
├── cli.py             Typer commands and argument routing
├── core/
│   ├── engine.py      Finding model, AST visitor base, traversal, shared AST helpers
│   └── loader.py      Pydantic rule schema, JSON loading and validation
├── analyzers/         one module per vulnerability family (detection logic)
├── json/              one rule document per analyzer (policy data)
└── reporters/         terminal and JSON rendering
```

### 2. Ruleset separation: `src/analyzers/` + `src/json/`

Detection logic and detection policy are deliberately separate:

* **`src/json/<analyzer>.json`** holds rule metadata and patterns — rule ID, name,
  OWASP category, CWE, severity, description, remediation example, patterns, tags,
  references, and an `enabled` flag. Documents are validated by Pydantic with
  `extra="forbid"`, so a typo in a key fails loudly instead of silently doing nothing.
* **`src/analyzers/<analyzer>.py`** holds the code that interprets those patterns.

Prefer adding or tuning a rule in JSON over hardcoding values in Python. A new rule that
needs no new logic should require **no Python change at all**.

Rule documents must satisfy the schema in `src/core/loader.py`:

* `rule_id` matches `^[A-Z]{2,8}\d{3}$` and is unique within its document;
* `cwe_id` matches `^CWE-\d+$`;
* `severity` is one of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`;
* `analyzer` in the JSON must equal the module's `ANALYZER_NAME` and the filename stem.

A new analyzer module must expose these module-level functions:

| Function | Contract |
|---|---|
| `_name()` | Returns the analyzer identifier, matching `ANALYZER_NAME` and the JSON filename |
| `_analyze(target)` | Takes a `SourceFile`, returns a `list[Finding]` for that one file |

Analyzers must be **read-only and side-effect free**: never import, execute or evaluate
the code under analysis, and never perform network or filesystem writes.

### 3. Single-word filenames

Every file inside `src/` must have a **single-word** name: **no underscores and no
hyphens**.

```
ssrf.py       deserial.py     xxe.py        ssti.py       auth.py       ← correct
ssrf_scan.py  deserial-x.py   xxe_parser.py                              ← rejected
```

The only exceptions are `__init__.py` (a required Python package marker) and the
top-level `pyproject.toml`. This rule applies equally to `.py` and `.json` files.

### 4. Leading underscore on every function and method

**Every** function and method must start with a single leading underscore `_`. This
includes module-level helpers, private methods, and public-looking API functions.

```python
def _analyze(target: SourceFile) -> list[Finding]:      # correct
class _Visitor(ast.NodeVisitor):                         # correct
    def _inspect(self, node: ast.Call) -> None:           # correct

def analyze(target):                                     # rejected
class Visitor(ast.NodeVisitor):                          # rejected
```

Three categories are exempt:

* **Dunder methods** — `__init__`, `__repr__`, `__enter__`, etc.
* **`ast.NodeVisitor` handlers** — `visit_Call`, `visit_Assign`, `visit_If`, and other
  `visit_*` dispatch names, because the `ast` module calls them by exact name.
* **Names required verbatim by an external library**, such as `HTMLParser`'s
  `handle_starttag` / `handle_endtag`. Handle these the way `src/analyzers/headers.py`
  does: define an underscore-prefixed implementation and alias it to the required name.

```python
def _starttag(self, tag, attrs): ...          # the real implementation
handle_starttag = _starttag                   # alias required by HTMLParser
```

The same pattern is used for `.execute()` style shims elsewhere. Prefer an alias over
polluting the module with a non-conforming definition.

### 5. Plain-text CLI output

**All terminal output must be plain text.** Do not introduce Rich `Panel`, `Table`, or
any other bordered/boxed rendering into command output.

```text
URL : https://example.com
xss : HARDENING NEEDED (missing CSP, missing X-Content-Type-Options)
sql injection : SAFE (no indicators detected)
```

* One line per finding or category; colour is allowed for status labels only
  (`SAFE` green, `HARDENING NEEDED` yellow, `VULNERABLE` red).
* Never truncate silently in verbose mode — `--verbose` shows every reason.
* Output must stay greppable and copy-pasteable.
* Each report must have a plain-text rendering function so results can be reused in logs
  and tests without a terminal.

### 6. Non-destructive web auditing

Any code that touches the network must obey these rules without exception:

* **`GET` only.** Never send `POST`, `PUT`, `PATCH` or `DELETE`, and never submit a form.
* **Same-origin only.** Follow a discovered link or form action only when it matches the
  exact scheme, host and port of the operator-supplied URL.
* **Bounded.** Respect the page cap (5), the discovered-link cap, and the request timeout.
* **Identify yourself.** Always send the project `User-Agent`.
* **Inert probes only.** Probe markers must contain no script, quote, SQL or shell
  metacharacter. Never add an exploitation payload, however "safe" it looks.
* **Opt-in probing.** Any request that modifies a parameter must require an explicit
  `--probe` flag; the default scan is fully passive.

A pull request that adds an active attack, a non-`GET` request, a crawler without a cap,
or a payload string will be rejected.

## Code style

* Line length 100, target Python 3.11 (`[tool.ruff]` in `pyproject.toml`).
* `from __future__ import annotations` at the top of every module.
* Type annotations on all function signatures; return types are mandatory.
* Frosted dataclasses / frozen Pydantic models for value objects.
* Prefer module-level constants (`CATEGORY_XSS`, `MAX_PAGES`) over magic literals.
* Keep the AST helpers in `src/core/engine.py` shared — do not re-implement alias
  resolution, guard detection, or module matching inside an analyzer.

## Adding a new rule

1. Add a validated object to the relevant `src/json/<analyzer>.json`. Include a real
   `description`, a `remediation_example` that shows the safe pattern, and a reference to
   the OWASP category and CWE.
2. If the rule needs new logic, extend the visitor in the matching
   `src/analyzers/<analyzer>.py` — do not create a new analyzer for one rule.
3. If it needs a new vulnerability family, add `src/analyzers/<word>.py` and
   `src/json/<word>.json` (single-word names), then register the module in
   `_analyzers()` in `src/cli.py`.
4. Verify no false positives on Sentinel's own code:

   ```bash
   sentinel audit-code src     # must stay at 0 findings
   sentinel rules              # must list the new document
   ```

5. Update the ruleset tables in `README.md`.

## Adding a web surface check

Surface checks live in `src/analyzers/headers.py`:

* detection goes in `_inspect_html_surface` (per page, returns reasons by category);
* aggregation goes through `_surface_reasons` and `_merge_surface`;
* a new summary category needs a constant, an entry in `CATEGORY_ORDER`, a
  `_check_<name>_surface` builder, and a matching label in
  `CATEGORY_LABELS` in `src/reporters/terminal.py`.

Surface findings must never *lower* a verdict, and must only reach `VULNERABLE` on a
directly observed signal.

## Commit and pull request guidance

* Keep commits focused; one logical change per commit.
* Write imperative, descriptive commit subjects ("Add SSRF metadata rule", not "stuff").
* Describe in the pull request **what changed, why, and how you verified it** — include
  the commands you ran and their output.
* Note any behaviour change to verdict tiers or exit codes explicitly; those are
  user-facing policy.

## Reporting bugs and requesting features

* **Detection quality** (false positive, false negative, missing framework support) —
  open a regular issue with the smallest snippet or URL behaviour that reproduces it.
* **Security issues in Sentinel itself** — do **not** open a public issue. Follow
  [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE), copyright 2026 Varethic.
