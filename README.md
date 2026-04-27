# Static Taint Analysis Tool

**CS336: Program Analysis for Security & Privacy — Spring 2026**

Detects SQL injection and XSS vulnerabilities by tracking untrusted user input through a program without running it. Built from scratch in OCaml.

## Setup

Requires OCaml 4.14+ and Dune 3.0+.

```bash
cd taint_analysis
dune build
```

## Usage

```bash
dune exec src/main.exe -- <file.imp>
```

Example:
```bash
dune exec src/main.exe -- tests/test1_sqli.imp
```

## Test Cases

| Test | What it checks |
|------|---------------|
| test1_sqli.imp | SQL injection — input flows to sql_exec |
| test2_sanitized.imp | Sanitizer removes taint — no warning |
| test3_propagation.imp | Taint tracked through assignment chain |
| test4_conditional.imp | Branch merging with sound over-approximation |
| test5_loop.imp | Fixed-point iteration catches taint in loops |
| test6_clean.imp | Clean program — no false positives |
| web_login.imp | Login form SQL injection |
| web_search_xss.imp | Search page XSS vulnerability |
| web_search_safe.imp | Sanitized search page — no warning |
| web_contact_form.imp | Multiple sinks hit from form inputs |
| web_admin_redirect.imp | Open redirect through conditional |
| web_comments_xss.imp | Comment system with stored XSS |
| web_comments_safe.imp | Properly sanitized comment system |
| web_api_eval.imp | Eval/exec code injection |

## Project Structure

```
src/ast.ml       — AST type definitions
src/lexer.ml     — Tokenizer
src/parser.ml    — Recursive-descent parser
src/taint.ml     — Core taint analysis engine
src/main.ml      — Entry point
tests/           — Test programs (.imp files)
```

## Windows (WSL)

```bash
wsl
sudo apt install opam build-essential -y
opam init -y && eval $(opam env) && opam install dune -y
cd ~/taint_analysis && dune build
dune exec src/main.exe -- tests/test1_sqli.imp
```
