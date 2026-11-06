import pytest
from deepguard.analyzer import analyze_code

def test_detects_eval():
    assert len(analyze_code("def test(x):\n    eval(x)")) == 1

def test_detects_command_injection():
    assert len(analyze_code("import os\ndef test(x):\n    os.system(x)")) == 1

def test_detects_sql_injection():
    assert len(analyze_code("def test(x):\n    cursor.execute(f'SELECT * FROM users WHERE id = {x}')")) == 1

def test_cross_function_vulnerability():
    code = """
import sqlite3
def execute_query(q):
    cursor.execute(q)

def get_user(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    execute_query(query)
"""
    findings = analyze_code(code)
    assert len(findings) >= 1

def test_ignores_parameterized_sql():
    assert len(analyze_code("def test(x):\n    cursor.execute('SELECT * FROM users WHERE id = ?', (x,))")) == 0

def test_ignores_safe_subprocess_list():
    assert len(analyze_code("import subprocess\ndef test(x):\n    subprocess.run(['ping', x])")) == 0