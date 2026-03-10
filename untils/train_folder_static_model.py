#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.ensemble import RandomForestClassifier

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False

ROOT = Path(__file__).parent.parent
TRAIN_CSV = ROOT / "data" / "training" / "folder_static_train.csv"
MODEL_PATH = ROOT / "models" / "folder_static_clf.pkl"
REPORT_PATH = ROOT / "models" / "folder_static_report.txt"

LABELS = ["benign", "suspicious", "malicious"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(TRAIN_CSV))
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    df = df[df["label"].isin(LABELS)].copy()

    non_feature_cols = {"folder", "label"}
    feature_cols = [c for c in df.columns if c not in non_feature_cols]

    X = df[feature_cols].fillna(0)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    if HAS_XGB:
        clf = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=42,
        )
    else:
        clf = RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    report = classification_report(y_test, y_pred, labels=LABELS, zero_division=0)

    print(f"Accuracy : {acc:.4f}")
    print(f"Macro F1 : {macro_f1:.4f}")
    print(report)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": clf,
            "feature_cols": feature_cols,
            "labels": LABELS,
        },
        MODEL_PATH,
    )

    REPORT_PATH.write_text(
        f"Folder Static Classifier\n"
        f"========================\n"
        f"Rows       : {len(df)}\n"
        f"Features   : {len(feature_cols)}\n"
        f"Accuracy   : {acc:.4f}\n"
        f"Macro F1   : {macro_f1:.4f}\n\n"
        f"{report}\n",
        encoding="utf-8",
    )

    print(f"Saved model  -> {MODEL_PATH}")
    print(f"Saved report -> {REPORT_PATH}")


if __name__ == "__main__":
    main()