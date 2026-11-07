# DeepGuard: Static Analysis (SAST) for AI-Generated Code

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![Security: SAST](https://img.shields.io/badge/Security-SAST-red.svg)]()

DeepGuard is a lightweight, fast, and highly precise Static Application Security Testing (SAST) tool designed to detect vulnerabilities in Python code **without executing it**. It is specifically engineered for auditing AI-generated code, where LLMs often produce safe-looking snippets that hide critical flaws like SQL Injection and Command Injection.

## Executive Summary
LLMs are exceptional at writing functional code, but they frequently hallucinate safety. A model might use an f-string for a SQL query or pass raw user input to `os.system()`. Traditional linters (like `flake8` or `pylint`) will not catch this because they only look at syntax, not data flow.

DeepGuard solves this using **Abstract Syntax Trees (AST)** and **Inter-procedural Taint Analysis**. It tracks how untrusted input (taint) flows through your code, across function calls, until it hits a dangerous sink (like `cursor.execute()`).

## Key Capabilities
- **Inter-procedural Taint Analysis:** Unlike basic scanners, DeepGuard tracks data across functions. If `get_user(input)` passes a tainted variable to `execute_query(query)`, DeepGuard catches it.
- **YAML-Driven Rule Engine:** Sinks and dangerous builtins (`eval`, `os.system`) are configured in `rules.yaml`. No hardcoded logic.
- **Context-Aware Sanitization:** Zero false positives on parameterized SQL (`cursor.execute(query, (x,))`) and safe subprocess lists (`subprocess.run(["ping", x])`).
- **AutoFix AI Pipeline:** Includes `autofix.py`, a pipeline that takes DeepGuard's findings, sends them to an LLM, and forces the LLM to rewrite the code safely.

## Benchmark & Precision (The Metrics)
We validate the tool against a dataset of safe and vulnerable AI-generated snippets.

| Metric | Result |
| :--- | :--- |
| **Precision** | 100.00% (Zero false positives) |
| **Recall** | 100.00% (No vulnerabilities missed) |
| **F1-Score** | 100.00% |

## Architecture
- `src/deepguard/analyzer.py`: The AST Visitor and Taint Tracker.
- `src/deepguard/cli.py`: The CLI (built with Typer & Rich).
- `autofix.py`: The LLM feedback loop.
- `benchmark.py`: The Precision/Recall evaluation script.
- `Dockerfile`: Ready for CI/CD integration.

## How to Run & Evaluate
1. Install the package locally:
   pip install -e .
2. Scan a vulnerable file:
   deepguard scan examples/vulnerable_code.py
3. Run the benchmark (Precision/Recall):
   python benchmark.py
4. Run the AutoFix AI Pipeline (simulates an LLM fixing its own bugs):
   python autofix.py

## Honest Limitations (Staff-Level Self-Audit)
- **Intra-file Analysis Only:** DeepGuard does not follow imports across multiple files (requires a full Call Graph).
- **Synthetic Dataset:** The 100% Precision/Recall is measured on a curated 6-file dataset. Real-world validation against the OWASP Benchmark would yield lower (but more realistic) scores.
- **Mock LLM:** The `autofix.py` pipeline uses a mock LLM for deterministic testing. In production, it connects to the OpenAI API.

## Relevance for AI Evaluation
AI platforms (Mercor, Outlier, Scale AI) need humans to audit the code their models generate. This repository is a demonstration of how to build the tooling for that audit. It proves that the author understands ASTs, data flow, and how to construct a deterministic test suite for security.