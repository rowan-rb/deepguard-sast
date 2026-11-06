import os
import ast
from deepguard.analyzer import analyze_code

def mock_llm_fix(vulnerable_code, findings):
    print("  -> [Mock LLM] Analyzing DeepGuard findings...")
    print("  -> [Mock LLM] Rewriting code to fix vulnerabilities...")
    
    lines = vulnerable_code.split('\n')
    fixed_lines = []
    
    for line in lines:
        # 1. Fix Command Injection
        if 'os.system("ping " + user_input)' in line:
            fixed_lines.append("    # FIXED: Command Injection")
            fixed_lines.append('    print(f"Pinging: {user_input}")')
            continue
            
        # 2. Fix eval()
        if 'result = eval(expression)' in line:
            fixed_lines.append("    # FIXED: Dangerous eval")
            fixed_lines.append("    result = ast.literal_eval(expression)")
            continue
            
        # 3. Fix SQL Injection (query line)
        if 'query = f"SELECT * FROM users WHERE id' in line:
            fixed_lines.append('    # FIXED: SQL Injection')
            fixed_lines.append('    query = "SELECT * FROM users WHERE id = ?"')
            continue
            
        # 4. Fix SQL Injection (execute line)
        if 'cursor.execute(query)' in line:
            fixed_lines.append('    cursor.execute(query, (user_id,))')
            continue
            
        fixed_lines.append(line)
        
    fixed_code = '\n'.join(fixed_lines)
    
    # Add import ast if we fixed eval
    if "ast.literal_eval" in fixed_code and "import ast" not in fixed_code:
        fixed_code = "import ast\n" + fixed_code

    return fixed_code

def run_autofix_pipeline(file_path):
    print(f"\n--- AutoFix AI Pipeline: {file_path} ---")
    
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        original_code = f.read()

    print("\n[Step 1] Scanning original code with DeepGuard...")
    findings = analyze_code(original_code)
    
    if not findings:
        print("No vulnerabilities found. Code is already safe.")
        return

    print(f"Found {len(findings)} vulnerabilities!")
    for f in findings:
        print(f"  - Line {f.line}: {f.message}")

    print("\n[Step 2] Sending code and findings to the LLM for auto-fixing...")
    fixed_code = mock_llm_fix(original_code, findings)

    print("\n[Step 3] Re-scanning the AI-generated fix with DeepGuard...")
    new_findings = analyze_code(fixed_code)
    
    if len(new_findings) == 0:
        print("\n[SUCCESS] The AI successfully fixed all vulnerabilities! DeepGuard reports 0 findings.")
    else:
        print(f"\n[FAILURE] The AI's fix still has {len(new_findings)} vulnerabilities.")
        for f in new_findings:
            print(f"  - Line {f.line}: {f.message}")
    
    print("\n--- Fixed Code Preview ---")
    print(fixed_code)
    print("--------------------------\n")

if __name__ == "__main__":
    run_autofix_pipeline("examples/vulnerable_code.py")