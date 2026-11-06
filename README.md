# DeepGuard

A Static Application Security Testing (SAST) tool designed to detect vulnerabilities in AI-generated Python code.

## Features
- Abstract Syntax Tree (AST) parsing
- Detection of dangerous function calls (eval, exec, os.system)
- Fast and zero-execution analysis

## Usage
```bash
deepguard scan examples/vulnerable_code.py
```