#!/usr/bin/env python3
# untils/train_cwe_classifier.py

"""
Fine-tune SecBERT for CWE Category Classification (Hướng 3)
============================================================

Task   : Multi-class text classification
Input  : CVE description text (hoặc PE behavior profile text)
Output : CWE category (CWE-78, CWE-94, CWE-119, ...)

Tại sao cần model này?
  Hướng 3 cần dự đoán CWE từ behavior text của PE file.
  Pipeline:
    PE static analysis → build_profile_text() → [model này] → CWE → NVD query

Cách hoạt động:
  1. Train trên CVE descriptions → CWE labels (NVD ground truth)
  2. Lúc inference: feed PE behavior text vào model → predict CWE
  3. Assumption: behavior text của PE giống ngôn ngữ CVE descriptions
     (cùng domain cybersecurity → SecBERT handle được)

Dataset: data/training/cve_cwe_train.csv
  - Được tạo tự động bởi build_training_data.py
  - Columns: cve_id, description, cwe_ids, severity
  - cwe_ids: pipe-separated, e.g. "CWE-94|CWE-78"
  - Dùng CWE đầu tiên (primary CWE) làm class label

Output:
  - models/bert_cwe/          — fine-tuned model + tokenizer
  - models/bert_cwe_meta.json — label map + evaluation metrics

Usage
-----
    # Recommended
    python untils/train_cwe_classifier.py

    # CPU-only (chậm hơn, giảm epochs)
    python untils/train_cwe_classifier.py --model distilbert-base-uncased --epochs 2 --batch 8

    # Top-30 CWEs thay vì top-20
    python untils/train_cwe_classifier.py --top-cwes 30

Academic References
-------------------
    Devlin et al. (2019). BERT: Pre-training of Deep Bidirectional Transformers.
    NAACL 2019. https://arxiv.org/abs/1810.04805

    Aghaei et al. (2022). SecureBERT: A Domain-Specific Language Model for
    Cybersecurity. arXiv:2204.02685.

    NVD CWE Data: https://nvd.nist.gov/vuln/categories
"""

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_MODEL   = "jackaduma/SecBERT"
FALLBACK_MODEL  = "distilbert-base-uncased"

DEFAULT_DATASET = ROOT / "data"  / "training" / "cve_cwe_train.csv"
DEFAULT_OUT_DIR = ROOT / "models" / "bert_cwe"
DEFAULT_META    = ROOT / "models" / "bert_cwe_meta.json"

# Số CWE classes tối đa để train
# Dùng top-N CWE phổ biến nhất từ NVD để tránh long-tail noise
DEFAULT_TOP_CWES = 20


# ── Dataset loading ────────────────────────────────────────────────────────────

def load_dataset(path: Path, top_n: int = DEFAULT_TOP_CWES) -> tuple[list, dict, dict, int]:
    """
    Load cve_cwe_train.csv, chọn top-N CWE phổ biến nhất.

    Returns
    -------
    records   : list of (text, label_id)
    label2id  : {"CWE-94": 0, "CWE-78": 1, ...}
    id2label  : {0: "CWE-94", 1: "CWE-78", ...}
    skipped   : số records bị bỏ qua
    """
    rows: list[tuple[str, str]] = []  # (description, primary_cwe)
    skipped = 0

    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            desc    = (row.get("description") or "").strip()
            cwe_raw = (row.get("cwe_ids")     or "").strip()

            if not desc or not cwe_raw:
                skipped += 1
                continue

            # Lấy primary CWE (đầu tiên trong danh sách)
            primary_cwe = cwe_raw.split("|")[0].strip()
            if not primary_cwe.startswith("CWE-"):
                skipped += 1
                continue

            rows.append((desc, primary_cwe))

    if not rows:
        return [], {}, {}, skipped

    # ── Chọn top-N CWE phổ biến nhất ──
    cwe_counts = Counter(cwe for _, cwe in rows)
    top_cwes   = [cwe for cwe, _ in cwe_counts.most_common(top_n)]

    print(f"\n  Top-{top_n} CWE distribution (selected for training):")
    for cwe, count in cwe_counts.most_common(top_n):
        pct = count / len(rows) * 100
        print(f"    {cwe:<12} {count:>6,}  ({pct:4.1f}%)")

    # ── Build label maps ──
    label2id = {cwe: idx for idx, cwe in enumerate(top_cwes)}
    id2label = {idx: cwe for cwe, idx in label2id.items()}

    # ── Filter records to top-N CWEs ──
    records: list[tuple[str, int]] = []
    for desc, cwe in rows:
        if cwe in label2id:
            records.append((desc, label2id[cwe]))
        else:
            skipped += 1

    return records, label2id, id2label, skipped


# ── Stratified split (same as finetune_bert_severity.py) ──────────────────────

def stratified_split(
    records:   list,
    test_size: float = 0.15,
    val_size:  float = 0.10,
    seed:      int   = 42,
) -> tuple[list, list, list]:
    """Split into train/val/test preserving per-class ratio."""
    import random
    random.seed(seed)

    by_label: dict[int, list] = {}
    for item in records:
        by_label.setdefault(item[1], []).append(item)

    train, val, test = [], [], []
    for lbl, items in by_label.items():
        random.shuffle(items)
        n      = len(items)
        n_test = max(1, int(n * test_size))
        n_val  = max(1, int(n * val_size))
        test  += items[:n_test]
        val   += items[n_test: n_test + n_val]
        train += items[n_test + n_val:]

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)
    return train, val, test


# ── Class weights ──────────────────────────────────────────────────────────────

def compute_class_weights(records: list, n_classes: int) -> list:
    from sklearn.utils.class_weight import compute_class_weight
    import numpy as np

    labels  = [lbl for _, lbl in records]
    classes = list(range(n_classes))
    weights = compute_class_weight("balanced", classes=np.array(classes), y=np.array(labels))
    return list(weights)


# ── PyTorch Dataset (same pattern as finetune_bert_severity.py) ───────────────

class CWEDataset:
    def __init__(self, records: list, tokenizer, max_len: int):
        self.records   = records
        self.tokenizer = tokenizer
        self.max_len   = max_len

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx: int):
        import torch
        text, label = self.records[idx]
        enc = self.tokenizer(
            text,
            max_length=self.max_len,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels":         torch.tensor(label, dtype=torch.long),
        }


# ── Compute metrics ────────────────────────────────────────────────────────────

def make_compute_metrics():
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        acc   = accuracy_score(labels, preds)
        f1    = f1_score(labels, preds, average="macro", zero_division=0)
        return {"accuracy": acc, "macro_f1": f1}

    return compute_metrics


# ── Weighted loss Trainer (same pattern) ──────────────────────────────────────

def make_weighted_trainer(class_weights_list: list):
    import torch
    import torch.nn as nn
    from transformers import Trainer

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels  = inputs.pop("labels")
            outputs = model(**inputs)
            logits  = outputs.logits
            weights = torch.tensor(
                class_weights_list, dtype=torch.float, device=logits.device
            )
            loss = nn.CrossEntropyLoss(weight=weights)(logits, labels)
            return (loss, outputs) if return_outputs else loss

    return WeightedTrainer


# ── Main training function ─────────────────────────────────────────────────────

def train(
    records:    list,
    label2id:   dict,
    id2label:   dict,
    model_name: str,
    out_dir:    Path,
    meta_path:  Path,
    max_len:    int   = 256,
    batch_size: int   = 16,
    epochs:     int   = 3,
    lr:         float = 2e-5,
    weight_decay: float = 0.01,
    use_class_weights: bool = True,
) -> tuple[float, float]:
    """Full fine-tuning pipeline. Returns (test_accuracy, test_macro_f1)."""
    import torch
    import numpy as np
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        EarlyStoppingCallback,
    )
    from sklearn.metrics import classification_report, accuracy_score, f1_score

    n_classes = len(label2id)

    device = (
        "cuda" if torch.cuda.is_available()
        else "mps" if torch.backends.mps.is_available()
        else "cpu"
    )
    print(f"\n[Device] {device.upper()}")
    print(f"[Model]  {model_name}")
    print(f"[Task]   CWE classification — {n_classes} classes")

    if device == "cpu":
        print("[WARN]  CPU-only training is slow. Consider --epochs 2 --batch 8.")
        if batch_size > 8:
            batch_size = 8
            print(f"[INFO]  Reduced batch_size to {batch_size} for CPU.")

    # ── Split ──
    train_data, val_data, test_data = stratified_split(records)
    print(f"[Split] train={len(train_data):,}  val={len(val_data):,}  test={len(test_data):,}")

    # ── Class weights ──
    class_weights_list = None
    if use_class_weights:
        class_weights_list = compute_class_weights(train_data, n_classes)
        print(f"[Class weights] computed for {n_classes} CWE classes")

    # ── Tokenizer + model ──
    print("\n[Loading] tokenizer …")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
    except Exception as e:
        print(f"[WARN] Could not load {model_name}: {e}")
        print(f"       Falling back to {FALLBACK_MODEL}")
        model_name = FALLBACK_MODEL
        tokenizer  = AutoTokenizer.from_pretrained(model_name)

    # Convert id2label keys to int for HuggingFace config
    id2label_int = {int(k): v for k, v in id2label.items()}
    label2id_str = {v: int(k) for k, v in id2label.items()}

    print("[Loading] model …")
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=n_classes,
        id2label=id2label_int,
        label2id=label2id_str,
        ignore_mismatched_sizes=True,
    )

    # ── Datasets ──
    train_ds = CWEDataset(train_data, tokenizer, max_len)
    val_ds   = CWEDataset(val_data,   tokenizer, max_len)
    test_ds  = CWEDataset(test_data,  tokenizer, max_len)

    # ── Training arguments ──
    out_dir.mkdir(parents=True, exist_ok=True)
    training_args = TrainingArguments(
        output_dir                  = str(out_dir),
        num_train_epochs            = epochs,
        per_device_train_batch_size = batch_size,
        per_device_eval_batch_size  = batch_size * 2,
        learning_rate               = lr,
        weight_decay                = weight_decay,
        warmup_ratio                = 0.1,
        eval_strategy               = "epoch",
        save_strategy               = "epoch",
        load_best_model_at_end      = True,
        metric_for_best_model       = "macro_f1",
        greater_is_better           = True,
        logging_steps               = 50,
        report_to                   = "none",
        seed                        = 42,
        fp16                        = torch.cuda.is_available(),
    )

    # ── Trainer ──
    if use_class_weights and class_weights_list:
        TrainerClass = make_weighted_trainer(class_weights_list)
    else:
        from transformers import Trainer as TrainerClass

    trainer = TrainerClass(
        model           = model,
        args            = training_args,
        train_dataset   = train_ds,
        eval_dataset    = val_ds,
        compute_metrics = make_compute_metrics(),
        callbacks       = [EarlyStoppingCallback(early_stopping_patience=2)],
    )

    # ── Train ──
    print(f"\n{'='*60}")
    print(f"  Fine-tuning {model_name} for CWE Classification")
    print(f"  Classes={n_classes}  Epochs={epochs}  LR={lr}  Batch={batch_size}")
    print(f"{'='*60}")
    t0 = time.time()
    trainer.train()
    elapsed = time.time() - t0
    print(f"\n[Done] Training: {elapsed:.0f}s ({elapsed/60:.1f} min)")

    # ── Evaluate ──
    print("\n[Eval] Held-out test set …")
    pred_out = trainer.predict(test_ds)
    preds    = np.argmax(pred_out.predictions, axis=-1)
    labels   = pred_out.label_ids

    target_names = [id2label_int[i] for i in range(n_classes)]
    report_str   = classification_report(
        labels, preds, target_names=target_names, digits=4, zero_division=0
    )
    print("\n" + report_str)

    acc = float(accuracy_score(labels, preds))
    f1  = float(f1_score(labels, preds, average="macro", zero_division=0))

    # ── Save ──
    trainer.save_model(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))
    print(f"[Saved] Model → {out_dir}")

    meta = {
        "base_model":    model_name,
        "task":          "cwe_classification",
        "num_labels":    n_classes,
        "label2id":      label2id_str,
        "id2label":      {str(k): v for k, v in id2label_int.items()},
        "max_length":    max_len,
        "train_samples": len(train_data),
        "val_samples":   len(val_data),
        "test_samples":  len(test_data),
        "test_accuracy": round(acc, 4),
        "test_macro_f1": round(f1, 4),
        "epochs":        epochs,
        "learning_rate": lr,
        "batch_size":    batch_size,
        "device":        device,
        "training_time_s": round(elapsed, 1),
        "classification_report": report_str,
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[Saved] Metadata → {meta_path}")

    print(f"\n{'='*60}")
    print(f"  Test Accuracy : {acc*100:.2f}%")
    print(f"  Test Macro-F1 : {f1*100:.2f}%")
    print(f"{'='*60}")

    return acc, f1


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune SecBERT for CWE category classification (Hướng 3)"
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"HuggingFace model ID (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--dataset", default=str(DEFAULT_DATASET),
        help="Path to cve_cwe_train.csv",
    )
    parser.add_argument(
        "--top-cwes", type=int, default=DEFAULT_TOP_CWES,
        help=f"Number of top CWE classes to use (default: {DEFAULT_TOP_CWES})",
    )
    parser.add_argument("--epochs",  type=int,   default=3,    help="Training epochs (default 3)")
    parser.add_argument("--batch",   type=int,   default=16,   help="Batch size (default 16)")
    parser.add_argument("--lr",      type=float, default=2e-5, help="Learning rate (default 2e-5)")
    parser.add_argument("--max-len", type=int,   default=256,  help="Max token length (default 256)")
    parser.add_argument(
        "--no-class-weights", action="store_true",
        help="Disable class-weighted loss",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  CWE Classification — SecBERT Fine-tuning (Hướng 3)")
    print("=" * 60)

    # ── Dependency check ──
    try:
        import torch
        import transformers
        from sklearn.utils.class_weight import compute_class_weight
        print(f"[OK] PyTorch        {torch.__version__}")
        print(f"[OK] Transformers   {transformers.__version__}")
    except ImportError as e:
        print(f"\n[ERR] Missing package: {e}")
        print("      pip install torch transformers scikit-learn accelerate")
        sys.exit(1)

    # ── Dataset ──
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"\n[ERR] Dataset not found: {dataset_path}")
        print("      Run first: python untils/build_training_data.py")
        sys.exit(1)

    print(f"\n[1/3] Loading CWE dataset: {dataset_path}")
    records, label2id, id2label, skipped = load_dataset(dataset_path, top_n=args.top_cwes)

    if not records:
        print("\n[ERR] No records loaded. Run build_training_data.py first.")
        sys.exit(1)

    print(f"\n      Loaded:  {len(records):,} records")
    print(f"      Skipped: {skipped:,}")
    print(f"      Classes: {len(label2id)} CWE categories")

    if len(records) < 200:
        print("\n[WARN] Very small dataset — run build_training_data.py with --bulk for better results.")

    # ── Fine-tune ──
    print(f"\n[2/3] Fine-tuning {args.model} …")
    acc, f1 = train(
        records           = records,
        label2id          = label2id,
        id2label          = id2label,
        model_name        = args.model,
        out_dir           = DEFAULT_OUT_DIR,
        meta_path         = DEFAULT_META,
        max_len           = args.max_len,
        batch_size        = args.batch,
        epochs            = args.epochs,
        lr                = args.lr,
        use_class_weights = not args.no_class_weights,
    )

    print(f"\n[3/3] Done!")
    print(f"      Model: {DEFAULT_OUT_DIR}/")
    print(f"      CWE predictor will load this model automatically on next app start.")
    print(f"      Start app: python backend/app.py")


if __name__ == "__main__":
    main()
