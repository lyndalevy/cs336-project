# TaintTrace — Static Taint Analysis Tool

**CS336: Program Analysis for Security &amp; Privacy — Spring 2026**

Detects SQL injection, XSS, and command-injection vulnerabilities by tracking
untrusted user input through a program without running it. Supports both
**IMP** (toy language) and real **Python** (.py) files. Built from scratch in OCaml
with a pure-Python frontend for Python target analysis.

📖 **[Full documentation &amp; demo website →](https://yourusername.github.io/taint_analysis/)**

---

## Setup

### IMP mode (OCaml)

Requires OCaml 4.14+ and Dune 3.0+.

```bash
cd taint_analysis
dune build
```

### Python mode

Requires Python 3.8+. No installation needed — uses only the stdlib `ast` module.

```bash
python3 python_frontend/taint_py.py --help
```

---

## Usage

### Analyze an IMP file

```bash
dune exec src/main.exe -- tests/test1_sqli.imp
```

### Analyze an IMP file with a custom policy

```bash
dune exec src/main.exe -- --policy policies/webapp.json tests/test1_sqli.imp
```

### Analyze a real Python file

```bash
python3 python_frontend/taint_py.py tests/test_xss.py
```

### Analyze a Python file with a custom policy

```bash
python3 python_frontend/taint_py.py --policy policies/webapp.json tests/test_sqli.py
```

---

## External Policy Files

The tool is fully configurable. Pass `--policy <file.json>` to define what counts
as a source, sink, or sanitizer for your specific tech stack.

**Format** (`policies/webapp.json`):

```json
{
  "sources":    ["input", "get_param", "cookie"],
  "sinks":      ["sql_exec", "html_output", "eval"],
  "sanitizers": ["escape", "parameterize", "my_custom_cleaner"]
}
```

Missing keys fall back to the built-in defaults. Three bundled policies:

| File | Focus |
|------|-------|
| `policies/default.json` | General-purpose (all built-in rules) |
| `policies/webapp.json` | Web apps: SQLi + XSS |
| `policies/cmdinject.json` | OS command injection |

---

## Test Cases

### IMP tests

| File | What it checks | Expected |
|------|---------------|----------|
| `test1_sqli.imp` | Input flows directly to `sql_exec` | 1 WARNING |
| `test2_sanitized.imp` | Sanitizer removes taint before sink | CLEAN |
| `test3_propagation.imp` | Taint tracked through assignment chain | 1 WARNING |
| `test4_conditional.imp` | Branch merging with sound over-approximation | 1 WARNING |
| `test5_loop.imp` | Fixed-point iteration catches taint in loops | 1 WARNING |
| `test6_clean.imp` | Clean program — no false positives | CLEAN |

### Python tests

| File | What it checks | Expected |
|------|---------------|----------|
| `test_sqli.py` | `input()` flows to `cursor.execute()` (SQLi) | 1 WARNING |
| `test_sanitized.py` | `parameterize()` cleans before sink | CLEAN |
| `test_xss.py` | Flask `request.args.get()` → `render_template_string()` (XSS) | 1 WARNING |
| `test_cmdinject.py` | User input reaches `os.system()` | 1 WARNING |

---

## How It Works

1. **Source** — Values from `input`, `get_param`, `request.args.get`, etc. are marked *tainted*.
2. **Propagate** — Taint flows through assignments, binary ops, if/else branches (merged), and while loops (fixed-point iteration).
3. **Sink** — Tainted data reaching `sql_exec`, `eval`, `os.system`, etc. generates a warning with a full flow path.
4. **Sanitizer** — Calls to `escape`, `parameterize`, etc. remove the taint label — no false alarm.

---

## Project Structure

```
src/
  ast.ml              — AST type definitions
  lexer.ml            — Tokenizer
  parser.ml           — Recursive-descent parser
  taint.ml            — Core taint engine + policy loader
  main.ml             — CLI entry point (supports --policy)
python_frontend/
  taint_py.py         — Standalone Python taint analyzer (real .py files)
tests/
  test1_sqli.imp      — IMP test cases
  ...
  test_sqli.py        — Python test cases
  test_xss.py
  ...
policies/
  default.json        — Built-in rules as JSON
  webapp.json         — Web security policy
  cmdinject.json      — Command injection policy
docs/
  index.html          — GitHub Pages documentation site
```

---

## Windows (WSL)

```bash
wsl
sudo apt install opam build-essential -y
opam init -y && eval $(opam env) && opam install dune -y
cd ~/taint_analysis && dune build
dune exec src/main.exe -- tests/test1_sqli.imp
```
