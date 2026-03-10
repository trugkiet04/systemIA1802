#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).parent.parent
sys.path.append(str(ROOT))

from folder_static_analyzer import FolderStaticAnalyzer
from folder_feature_builder import build_folder_features


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples-root", required=True, help="Root folder chứa các sample folders")
    ap.add_argument("--labels-csv", required=True, help="CSV gồm: folder,label")
    ap.add_argument("--out", default=str(ROOT / "data" / "training" / "folder_static_train.csv"))
    args = ap.parse_args()

    labels_df = pd.read_csv(args.labels_csv)
    analyzer = FolderStaticAnalyzer()

    rows = []
    for _, row in labels_df.iterrows():
        folder_name = str(row["folder"]).strip()
        label = str(row["label"]).strip()

        folder_path = Path(args.samples_root) / folder_name
        result = analyzer.analyze(folder_path)
        if not result.get("success"):
            print(f"[WARN] Skip {folder_name}: {result.get('error')}")
            continue

        feat = build_folder_features(result)
        feat["folder"] = folder_name
        feat["label"] = label
        rows.append(feat)
        print(f"[OK] {folder_name} -> {label}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out, index=False)
    print(f"\nSaved dataset -> {out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()