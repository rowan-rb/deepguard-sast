import os
from pathlib import Path
from deepguard.analyzer import analyze_code

def run_benchmark():
    print("=" * 40)
    print("DEEPGUARD BENCHMARK (Precision & Recall)")
    print("=" * 40)

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    dataset_dir = Path("dataset")
    
    # Test Vulnerable files (Should detect > 0 findings)
    for file in dataset_dir.glob("vuln_*.py"):
        code = file.read_text()
        findings = analyze_code(code)
        if len(findings) > 0:
            print(f"[PASS] Detected vulnerabilities in {file.name}")
            true_positives += 1
        else:
            print(f"[FAIL] Missed vulnerabilities in {file.name}")
            false_negatives += 1

    # Test Safe files (Should detect 0 findings)
    for file in dataset_dir.glob("safe_*.py"):
        code = file.read_text()
        findings = analyze_code(code)
        if len(findings) == 0:
            print(f"[PASS] Correctly ignored {file.name}")
            true_negatives += 1
        else:
            print(f"[FAIL] False positive in {file.name}")
            false_positives += 1

    # Calculate metrics
    print("\n--- METRICS ---")
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"True Positives (TP):  {true_positives}")
    print(f"False Positives (FP): {false_positives}")
    print(f"True Negatives (TN):  {true_negatives}")
    print(f"False Negatives (FN): {false_negatives}")
    print("-" * 20)
    print(f"Precision: {precision * 100:.2f}% (Qué porcentaje de las alertas son reales)")
    print(f"Recall:    {recall * 100:.2f}% (Qué porcentaje de los bugs reales ha encontrado)")
    print(f"F1-Score:  {f1_score * 100:.2f}%")

if __name__ == "__main__":
    run_benchmark()