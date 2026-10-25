"""
eval/run_eval.py – Evaluate detectors + ensemble on a labeled CSV.

Expected CSV columns: id, category, label (INJECTION|BENIGN), text

Outputs:
  - Per-detector and ensemble accuracy / precision / recall / FP / FN
  - Per-category recall for injection
  - Per-prompt result CSV saved alongside the input file
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import Any, Optional

# Allow running as: python -m eval.run_eval or python eval/run_eval.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detectors.deberta import DeBERTaDetector
from app.detectors.promptguard import PromptGuardDetector
from app.ensemble import run_ensemble


def _metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    total = len(y_true)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def run_eval(csv_path: str) -> None:
    input_path = Path(csv_path)
    if not input_path.exists():
        print(f"[ERROR] File not found: {csv_path}")
        sys.exit(1)

    deberta = DeBERTaDetector()
    promptguard = PromptGuardDetector()

    rows: list[dict] = []
    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print(f"Loaded {len(rows)} samples from {csv_path}")

    results: list[dict] = []

    for i, row in enumerate(rows, 1):
        text = row["text"]
        true_label = row["label"].strip().upper()  # INJECTION | BENIGN
        category = row.get("category", "unknown")

        print(f"  [{i}/{len(rows)}] category={category} label={true_label} ...", end="", flush=True)

        # DeBERTa
        db_res = deberta.scan(text)
        # PromptGuard
        pg_res = promptguard.scan(text)
        # Ensemble
        ens = run_ensemble(text, source="prompt")

        results.append({
            "id": row.get("id", i),
            "category": category,
            "true_label": true_label,
            "deberta_label": db_res.label,
            "deberta_score": db_res.score,
            "deberta_error": db_res.error,
            "promptguard_label": pg_res.label,
            "promptguard_score": pg_res.score,
            "promptguard_error": pg_res.error,
            "ensemble_label": ens.final_label,
            "ensemble_reason": ens.final_reason,
            "gemini_used": ens.gemini_used,
            "gemini_label": ens.gemini.label if ens.gemini_used else "",
        })
        print(f" deberta={db_res.label} pg={pg_res.label} ensemble={ens.final_label}")

    # ── Metrics ──────────────────────────────────────────────────────────────
    def _to_binary(label: str) -> int:
        return 1 if label == "INJECTION" else 0

    y_true = [_to_binary(r["true_label"]) for r in results]

    for det_name, pred_key in [("deberta", "deberta_label"), ("promptguard", "promptguard_label"), ("ensemble", "ensemble_label")]:
        y_pred = [_to_binary(r[pred_key]) for r in results]
        m = _metrics(y_true, y_pred)
        print(f"\n{'='*40}")
        print(f"DETECTOR: {det_name.upper()}")
        print(f"  Accuracy:  {m['accuracy']:.3f}")
        print(f"  Precision: {m['precision']:.3f}")
        print(f"  Recall:    {m['recall']:.3f}")
        print(f"  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")

        # Per-category recall
        categories = sorted(set(r["category"] for r in results))
        print(f"  Per-category recall (INJECTION only):")
        for cat in categories:
            cat_rows = [r for r in results if r["category"] == cat and r["true_label"] == "INJECTION"]
            if not cat_rows:
                continue
            cat_tp = sum(1 for r in cat_rows if r[pred_key] == "INJECTION")
            cat_recall = cat_tp / len(cat_rows)
            print(f"    {cat}: {cat_recall:.3f} ({cat_tp}/{len(cat_rows)})")

    # ── Save per-prompt CSV ───────────────────────────────────────────────────
    out_path = input_path.parent / (input_path.stem + "_results.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\nPer-prompt results saved to: {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate detectors on labeled CSV")
    parser.add_argument("csv_path", nargs="?", default="eval/data/benchmark_100.csv")
    args = parser.parse_args()
    run_eval(args.csv_path)
