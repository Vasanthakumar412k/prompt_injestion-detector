"""
scripts/run_lab_cli.py – CLI script to execute the Red-Team Security Lab.

Usage:
  python scripts/run_lab_cli.py [--models large,medium,qwen] [--configs none,full] [--split dev|test] [--max 30]
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import SessionLocal, init_db
from app.lab.report import generate_reports
from app.lab.runner import run_lab


def main():
    parser = argparse.ArgumentParser(description="Run the Red-Team Lab")
    parser.add_argument("--models", type=str, default="large,medium,qwen", help="Comma-separated models")
    parser.add_argument("--configs", type=str, default="none,full", help="Comma-separated configs")
    parser.add_argument("--splits", type=str, default="dev", help="Comma-separated splits: dev,test")
    parser.add_argument("--max", type=int, default=None, help="Max attacks per split (useful for quota limits)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay in seconds between API calls")
    parser.add_argument("--run-id", type=str, default=None, help="Existing run ID to resume (e.g. run_b2dbbc1af8cd)")
    args = parser.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    splits = [s.strip() for s in args.splits.split(",") if s.strip()]

    print("=" * 70)
    print("RED-TEAM SECURITY LAB EVALUATION")
    print(f"Run ID:  {args.run_id or '(new)'}")
    print(f"Models:  {models}")
    print(f"Configs: {configs}")
    print(f"Splits:  {splits}")
    print(f"Max items: {args.max}")
    print(f"Delay:   {args.delay}s")
    print("=" * 70)

    init_db()
    t0 = time.monotonic()
    run_id = run_lab(
        models=models,
        configs=configs,
        splits=splits,
        run_id=args.run_id,
        max_attacks=args.max,
        delay_between_calls=args.delay,
    )
    elapsed = time.monotonic() - t0

    print(f"\nRun completed in {elapsed:.1f}s.")
    print(f"Run ID: {run_id}")

    # Generate and print summary
    db = SessionLocal()
    try:
        metrics = generate_reports(run_id, db)
        print("\nReports generated:")
        print(f"  - reports/{run_id}/report.json")
        print(f"  - reports/{run_id}/results.csv")
        print(f"  - reports/{run_id}/report.html")
        print(f"  - reports/{run_id}/summary.md")
    finally:
        db.close()


if __name__ == "__main__":
    main()
