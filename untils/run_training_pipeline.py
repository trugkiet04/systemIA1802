#!/usr/bin/env python3
# untils/run_training_pipeline.py

"""
Master Training Pipeline
========================

Orchestrates the full training workflow in the correct order:

  Step 1  Build Dataset   — collect CVEs from NVD API
  Step 2  Train TF-IDF    — fast baseline (scikit-learn, ~5 min)
  Step 3  Fine-tune BERT  — SecBERT severity classifier (GPU: ~30 min)
  Step 4  Build CPE Index — FAISS semantic search index (~2 min)
  Step 5  Evaluate        — compare all models, write report

Each step is skipped if its output already exists (--force to override).

Usage
-----
    # Run all steps (uses existing outputs if present)
    python untils/run_training_pipeline.py

    # Rebuild everything from scratch
    python untils/run_training_pipeline.py --force

    # Download full NVD dataset first (recommended for thesis)
    python untils/run_training_pipeline.py --bulk-data

    # Skip BERT fine-tuning (CPU-only environment)
    python untils/run_training_pipeline.py --skip-bert

    # With NVD API key (10x faster data collection)
    NVD_API_KEY=your_key python untils/run_training_pipeline.py --bulk-data

Dataset Sources
---------------
    Primary: NVD CVE API v2  (https://services.nvd.nist.gov/rest/json/cves/2.0/)
    Content: CVE description, CVSS score, severity, vector string

    The NVD dataset is the authoritative source for the thesis because:
    - Official NIST database, widely cited in academic literature
    - Structured CVSS scores provide ground-truth severity labels
    - 220k+ CVEs covering all software categories
    - API freely accessible (free API key available at nvd.nist.gov)

    Academic reference:
        NIST. (2024). National Vulnerability Database.
        https://nvd.nist.gov

Model Architecture Summary
---------------------------
    TF-IDF + LR:  Statistical baseline. TF-IDF vectorises CVE text;
                  Logistic Regression classifies severity. Fast, interpretable.

    SecBERT:      Transformer fine-tuned on cybersecurity corpora.
                  Domain vocabulary improves representation of vuln text.
                  Fine-tuned end-to-end on NVD severity labels.

    Zero-Shot:    BART-MNLI. No training required. Classifies via natural-
                  language inference. Baseline for comparison.

    FAISS CPE:    Semantic nearest-neighbour index for CPE string lookup.
                  Sentence-transformers embed software names; FAISS retrieves
                  the closest CPE in sub-millisecond time.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT         = Path(__file__).parent.parent
UTILS        = ROOT / "untils"
MODELS       = ROOT / "models"
DATA_CSV     = ROOT / "data" / "training" / "cve_severity_train.csv"
CWE_CSV      = ROOT / "data" / "training" / "cve_cwe_train.csv"

# Minimum records to consider dataset usable
MIN_DATASET_RECORDS = 500


# ── Step helpers ───────────────────────────────────────────────────────────────

def _run(cmd: list[str], label: str) -> bool:
    """Run subprocess, stream output, return True on success."""
    print(f"\n{'─'*60}")
    print(f"  RUNNING: {' '.join(cmd)}")
    print(f"{'─'*60}")
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, check=True)
        elapsed = time.time() - t0
        print(f"\n[OK] {label} completed in {elapsed:.1f}s")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n[FAIL] {label} exited with code {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"\n[FAIL] Command not found: {cmd[0]}")
        return False


def _count_csv(path: Path) -> int:
    """Count data rows in a CSV file (excluding header)."""
    if not path.exists():
        return 0
    try:
        with open(path) as f:
            return sum(1 for _ in f) - 1  # subtract header
    except Exception:
        return 0


def _check_output(paths: list[Path]) -> bool:
    """Return True if ALL paths exist and have non-zero size."""
    return all(p.exists() and p.stat().st_size > 0 for p in paths)


# ── Steps ─────────────────────────────────────────────────────────────────────

def step_build_dataset(bulk: bool, force: bool, api_key: str) -> bool:
    """Step 1: Build training CSV from NVD API."""
    n = _count_csv(DATA_CSV)
    if not force and n >= MIN_DATASET_RECORDS:
        print(f"\n[SKIP] Dataset exists: {DATA_CSV.name} ({n:,} records)")
        return True

    print(f"\n[Step 1] Building training dataset …")
    if bulk:
        print("  Mode: BULK (download ALL NVD CVEs — may take 30–60 min)")
    else:
        print("  Mode: KEYWORD (faster, ~5–15 min)")

    import os
    env = os.environ.copy()
    if api_key:
        env["NVD_API_KEY"] = api_key

    cmd = [sys.executable, str(UTILS / "build_training_data.py")]
    if bulk:
        cmd.append("--bulk")
    cmd += ["--balance", "oversample"]

    t0 = time.time()
    try:
        proc = subprocess.run(cmd, check=True, env=env)
        elapsed = time.time() - t0
        n = _count_csv(DATA_CSV)
        print(f"\n[OK] Dataset built: {n:,} records ({elapsed:.0f}s)")
        return True
    except subprocess.CalledProcessError:
        print("\n[FAIL] Dataset build failed")
        return False


def step_train_tfidf(force: bool) -> bool:
    """Step 2: Train TF-IDF + Logistic Regression."""
    out = MODELS / "severity_clf.pkl"
    if not force and _check_output([out]):
        print(f"\n[SKIP] TF-IDF model exists: {out.name}")
        return True

    print("\n[Step 2] Training TF-IDF + Logistic Regression …")
    ok = _run(
        [sys.executable, str(UTILS / "train_severity_model.py")],
        "TF-IDF training",
    )
    return ok


def step_finetune_bert(force: bool, bert_model: str, epochs: int, batch: int) -> bool:
    """Step 3: Fine-tune SecBERT/DistilBERT."""
    out_dir  = MODELS / "bert_severity"
    out_meta = MODELS / "bert_severity_meta.json"

    if not force and _check_output([out_meta]) and out_dir.exists():
        print(f"\n[SKIP] BERT model exists: {out_dir.name}/")
        return True

    print(f"\n[Step 3] Fine-tuning {bert_model} …")
    ok = _run(
        [
            sys.executable, str(UTILS / "finetune_bert_severity.py"),
            "--model",  bert_model,
            "--epochs", str(epochs),
            "--batch",  str(batch),
        ],
        "BERT fine-tuning",
    )
    return ok


def step_train_cwe(force: bool, bert_model: str, epochs: int, batch: int) -> bool:
    """Step 3.5: Fine-tune SecBERT for CWE classification (Hướng 3)."""
    out_dir  = MODELS / "bert_cwe"
    out_meta = MODELS / "bert_cwe_meta.json"

    if not force and _check_output([out_meta]) and out_dir.exists():
        print(f"\n[SKIP] CWE model exists: {out_dir.name}/")
        return True

    if not CWE_CSV.exists() or _count_csv(CWE_CSV) < 100:
        print(f"\n[SKIP] CWE dataset not ready: {CWE_CSV.name}")
        print("       Run build_training_data.py first to generate cve_cwe_train.csv")
        return False

    print(f"\n[Step 3.5] Fine-tuning CWE classifier ({bert_model}) …")
    ok = _run(
        [
            sys.executable, str(UTILS / "train_cwe_classifier.py"),
            "--model",  bert_model,
            "--epochs", str(epochs),
            "--batch",  str(batch),
        ],
        "CWE classifier fine-tuning",
    )
    return ok


def step_build_cpe_index(force: bool) -> bool:
    """Step 4: Build FAISS CPE semantic search index."""
    out_idx  = MODELS / "cpe_index.faiss"
    out_meta = MODELS / "cpe_meta.pkl"

    if not force and _check_output([out_idx, out_meta]):
        print(f"\n[SKIP] CPE index exists: {out_idx.name}")
        return True

    print("\n[Step 4] Building FAISS CPE index …")
    ok = _run(
        [sys.executable, str(UTILS / "build_cpe_index.py")],
        "CPE index build",
    )
    return ok


def step_evaluate(skip_zeroshot: bool) -> bool:
    """Step 5: Evaluate all models, write report."""
    print("\n[Step 5] Evaluating all models …")
    cmd = [sys.executable, str(UTILS / "evaluate_models.py")]
    if skip_zeroshot:
        cmd.append("--skip-zeroshot")
    ok = _run(cmd, "Model evaluation")
    return ok


# ── Summary ────────────────────────────────────────────────────────────────────

def print_summary(results: dict[str, bool]) -> None:
    print("\n" + "=" * 60)
    print("  TRAINING PIPELINE SUMMARY")
    print("=" * 60)

    labels = {
        "dataset":   "Dataset (NVD CVEs)",
        "tfidf":     "TF-IDF + Logistic Regression",
        "bert":      "Fine-tuned SecBERT (Severity)",
        "cwe":       "Fine-tuned SecBERT (CWE — Hướng 3)",
        "cpe_index": "FAISS CPE Index",
        "evaluate":  "Model Evaluation",
    }

    for key, label in labels.items():
        status = results.get(key)
        if status is None:
            icon = "—"
            note = "skipped"
        elif status:
            icon = "OK"
            note = ""
        else:
            icon = "FAIL"
            note = "check error above"
        print(f"  [{icon:^4}] {label}" + (f"  ({note})" if note else ""))

    report_json = MODELS / "evaluation_report.json"
    report_txt  = MODELS / "evaluation_report.txt"

    print("\n  Output files:")
    for p in [
        DATA_CSV,
        CWE_CSV,
        MODELS / "severity_clf.pkl",
        MODELS / "severity_report.txt",
        MODELS / "bert_severity_meta.json",
        MODELS / "bert_cwe_meta.json",
        MODELS / "cpe_index.faiss",
        report_json,
        report_txt,
    ]:
        if p.exists():
            size = p.stat().st_size
            size_str = f"{size/1024:.1f} KB" if size < 1_000_000 else f"{size/1_000_000:.1f} MB"
            print(f"    {size_str:>10}  {p.relative_to(ROOT)}")

    print("\n  Next step: start the web server")
    print("    python backend/app.py")
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run the full training pipeline for CVE severity classification"
    )
    parser.add_argument(
        "--bulk-data", action="store_true",
        help="Download ALL NVD CVEs (recommended for thesis; ~30–60 min with API key)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Rerun all steps even if output files already exist",
    )
    parser.add_argument(
        "--skip-bert", action="store_true",
        help="Skip BERT fine-tuning (use on CPU-only machines)",
    )
    parser.add_argument(
        "--skip-cwe", action="store_true",
        help="Skip CWE classifier fine-tuning (Hướng 3)",
    )
    parser.add_argument(
        "--skip-cpe", action="store_true",
        help="Skip CPE index rebuild",
    )
    parser.add_argument(
        "--skip-eval", action="store_true",
        help="Skip model evaluation step",
    )
    parser.add_argument(
        "--skip-zeroshot", action="store_true",
        help="Skip zero-shot in evaluation (saves time on CPU)",
    )
    parser.add_argument(
        "--bert-model", default="jackaduma/SecBERT",
        help="HuggingFace model ID for BERT fine-tuning (default: jackaduma/SecBERT)",
    )
    parser.add_argument(
        "--bert-epochs", type=int, default=3,
        help="Number of fine-tuning epochs (default: 3)",
    )
    parser.add_argument(
        "--bert-batch", type=int, default=16,
        help="Batch size for fine-tuning (default: 16; reduce to 8 for CPU)",
    )
    parser.add_argument(
        "--api-key", default="",
        help="NVD API key for faster data collection (or set NVD_API_KEY env var)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  SOFTWARE VULNERABILITY ASSESSMENT — TRAINING PIPELINE")
    print("  Thesis: AI + CVE Database Vulnerability Assessment Tool")
    print("=" * 60)

    import os
    api_key = args.api_key or os.getenv("NVD_API_KEY", "")

    t_total = time.time()
    results: dict[str, bool] = {}

    # ── Step 1: Dataset ──
    ok = step_build_dataset(
        bulk    = args.bulk_data,
        force   = args.force,
        api_key = api_key,
    )
    results["dataset"] = ok
    if not ok:
        print("\n[FATAL] Cannot continue without training data.")
        print_summary(results)
        sys.exit(1)

    # ── Step 2: TF-IDF ──
    ok = step_train_tfidf(force=args.force)
    results["tfidf"] = ok

    # ── Step 3: BERT ──
    if args.skip_bert:
        print("\n[SKIP] BERT fine-tuning (--skip-bert)")
        results["bert"] = None
    else:
        ok = step_finetune_bert(
            force      = args.force,
            bert_model = args.bert_model,
            epochs     = args.bert_epochs,
            batch      = args.bert_batch,
        )
        results["bert"] = ok

    # ── Step 3.5: CWE classifier (Hướng 3) ──
    if args.skip_bert or args.skip_cwe:
        print("\n[SKIP] CWE classifier (--skip-bert or --skip-cwe)")
        results["cwe"] = None
    else:
        ok = step_train_cwe(
            force      = args.force,
            bert_model = args.bert_model,
            epochs     = args.bert_epochs,
            batch      = args.bert_batch,
        )
        results["cwe"] = ok

    # ── Step 4: CPE index ──
    if args.skip_cpe:
        print("\n[SKIP] CPE index (--skip-cpe)")
        results["cpe_index"] = None
    else:
        ok = step_build_cpe_index(force=args.force)
        results["cpe_index"] = ok

    # ── Step 5: Evaluate ──
    if args.skip_eval:
        print("\n[SKIP] Evaluation (--skip-eval)")
        results["evaluate"] = None
    else:
        ok = step_evaluate(skip_zeroshot=args.skip_zeroshot)
        results["evaluate"] = ok

    total_elapsed = time.time() - t_total
    print(f"\n[Total time] {total_elapsed:.0f}s ({total_elapsed/60:.1f} min)")

    print_summary(results)


if __name__ == "__main__":
    main()
