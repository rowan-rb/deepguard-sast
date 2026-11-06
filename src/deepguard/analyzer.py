import ast
import yaml
from dataclasses import dataclass
from typing import List, Set, Dict, Any

@dataclass
class Finding:
    line: int
    col: int
    message: str
    severity: str

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, rules_path: str = "rules.yaml"):
        self.findings: List[Finding] = []
        self.tainted_vars: Set[str] = set()
        self.function_taint_map: Dict[str, Set[str]] = {}
        
        with open(rules_path, "r") as f:
            rules = yaml.safe_load(f)
        
        self.sinks = rules.get("sinks", {})
        self.dangerous_builtins = rules.get("dangerous_builtins", [])

    def visit_FunctionDef(self, node: ast.FunctionDef):
        local_tainted = set()
        for arg in node.args.args:
            local_tainted.add(arg.arg)
        
        self.tainted_vars = local_tainted
        self.generic_visit(node)
        self.function_taint_map[node.name] = local_tainted
        self.tainted_vars = set()

    def visit_Assign(self, node: ast.Assign):
        is_tainted = False
        for child in ast.walk(node.value):
            if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                is_tainted = True
                break
        if is_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def is_node_tainted(self, node) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                return True
        return False

    def visit_Call(self, node: ast.Call):
        func_name = ""
        callee_name = None
        module_name = None
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            callee_name = func_name
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                func_name = node.func.attr
                callee_name = f"{module_name}.{func_name}"

        for built in self.dangerous_builtins:
            if callee_name == built["name"]:
                for arg in node.args:
                    if self.is_node_tainted(arg):
                        self.findings.append(Finding(node.lineno, node.col_offset, f"Dangerous function {callee_name}() with tainted input.", built["severity"]))
                        break

        for type, config in self.sinks.items():
            for m in config["modules"]:
                if (module_name == m["module"] and func_name == m["function"]):
                    if node.args and not isinstance(node.args[0], ast.List):
                        if self.is_node_tainted(node.args[0]):
                            self.findings.append(Finding(node.lineno, node.col_offset, f"Potential {type.replace('_', ' ').title()} via '{callee_name}'.", config["severity"]))

        if callee_name in self.function_taint_map:
            for arg in node.args:
                if self.is_node_tainted(arg):
                    self.findings.append(Finding(node.lineno, node.col_offset, f"Tainted input passed to function '{callee_name}()' which contains tainted state.", "MEDIUM"))
                    break

        self.generic_visit(node)

def analyze_code(source_code: str, rules_path: str = "rules.yaml") -> List[Finding]:
    try:
        tree = ast.parse(source_code)
        visitor = SecurityVisitor(rules_path)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError as e:
        return [Finding(e.lineno or 0, e.offset or 0, f"Syntax Error: {e.msg}", "ERROR")]