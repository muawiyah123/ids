import os
import json
import glob
import random
import logging
import argparse
import datetime as dt

import numpy as np
import pandas as pd
import joblib

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
)

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer

from ids_common import InfinityAndOutlierSanitizer

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
)
log = logging.getLogger("ids_train")

# Destination Port correlates with label in this specific capture in a way
# that doesn't generalize (Engelen et al., 2021 — "Troubleshooting an IDS
# dataset"). Off by default so you can compare both regimes.
LEAKY_FEATURES = ["Destination Port"]

# Classes this rare can't be split 3 ways (train/val/test) and stratified —
# they get folded into train only, never into val/test, so they don't
# silently break the split or produce a meaningless single-sample recall.
MIN_ROWS_PER_CLASS_FOR_SPLIT = 20


# --------------------------------------------------------------------------
# 1. LOAD
# --------------------------------------------------------------------------
def load_data(data_dir: str) -> pd.DataFrame:
    csv_files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    log.info("Found %d CSV files", len(csv_files))
    dfs = []
    for f in csv_files:
        df = pd.read_csv(f, low_memory=False, encoding="latin1")
        df.columns = df.columns.str.strip()
        dfs.append(df)
        log.info("  %-55s %s", os.path.basename(f), df.shape)

    full_df = pd.concat(dfs, ignore_index=True)
    log.info("Combined shape: %s", full_df.shape)
    return full_df


# --------------------------------------------------------------------------
# 2. CLEAN
# --------------------------------------------------------------------------
def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.drop_duplicates()
    log.info("Dropped %d exact duplicate rows", before - len(df))

    df = df.loc[:, ~df.columns.duplicated()]
    df = df.dropna(subset=["Label"])
    df["Label"] = df["Label"].astype(str).str.strip()

    nunique = df.nunique()
    const_cols = [c for c in nunique[nunique <= 1].index if c != "Label"]
    if const_cols:
        log.info("Dropping constant columns: %s", const_cols)
        df = df.drop(columns=const_cols)

    return df


# --------------------------------------------------------------------------
# 3. CORRELATED FEATURE PRUNING (fit on train only)
# --------------------------------------------------------------------------
def find_correlated_features(X_train: pd.DataFrame, threshold: float = 0.95):
    corr = X_train.corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    return [c for c in upper.columns if any(upper[c] > threshold)]


# --------------------------------------------------------------------------
# 4. SPLIT — stratified train/val/test, with ultra-rare classes routed to
# train only so they can't break stratification or produce a 1-sample recall.
# --------------------------------------------------------------------------
def split_data(X: pd.DataFrame, y_raw: pd.Series):
    counts = y_raw.value_counts()
    rare_classes = counts[counts < MIN_ROWS_PER_CLASS_FOR_SPLIT].index.tolist()
    if rare_classes:
        log.warning(
            "Classes with <%d rows go to TRAIN only (too few to stratify "
            "into val/test): %s", MIN_ROWS_PER_CLASS_FOR_SPLIT, rare_classes,
        )

    is_rare = y_raw.isin(rare_classes)
    X_rare, y_rare = X[is_rare], y_raw[is_rare]
    X_common, y_common = X[~is_rare], y_raw[~is_rare]

    X_train, X_temp, y_train, y_temp = train_test_split(
        X_common, y_common, test_size=0.3, stratify=y_common, random_state=SEED
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=SEED
    )

    X_train = pd.concat([X_train, X_rare])
    y_train = pd.concat([y_train, y_rare])

    log.info("Split sizes -> train: %d, val: %d, test: %d",
              len(X_train), len(X_val), len(X_test))
    return X_train, X_val, X_test, y_train, y_val, y_test


# --------------------------------------------------------------------------
# 5. TRAIN (early stopping on validation split)
# --------------------------------------------------------------------------
def train_model(X_train, y_train, X_val, y_val, num_classes: int, use_xgb: bool):
    sample_weight = compute_sample_weight(class_weight="balanced", y=y_train)

    if use_xgb and HAS_XGB:
        log.info("Training XGBoost (multiclass, no scaling, native NaN handling)...")
        model = XGBClassifier(
            n_estimators=800,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            reg_lambda=1.0,
            objective="multi:softprob",
            num_class=num_classes,
            eval_metric="mlogloss",
            tree_method="hist",
            early_stopping_rounds=30,
            n_jobs=-1,
            random_state=SEED,
        )
        model.fit(
            X_train, y_train,
            sample_weight=sample_weight,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )
        log.info("Best iteration: %s", model.best_iteration)
        return model, None

    log.info("Training RandomForest (XGBoost unavailable) — needs imputed input...")
    imputer = SimpleImputer(strategy="median")
    X_train_imp = imputer.fit_transform(X_train)

    model = RandomForestClassifier(
        n_estimators=500,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=SEED,
    )
    model.fit(X_train_imp, y_train, sample_weight=sample_weight)
    return model, imputer


# --------------------------------------------------------------------------
# 6. EVALUATE
# --------------------------------------------------------------------------
def evaluate(model, X_test, y_test, label_encoder):
    y_pred = model.predict(X_test)

    present_classes = sorted(set(y_test) | set(y_pred))
    target_names = [label_encoder.classes_[i] for i in present_classes]

    report = classification_report(
        y_test, y_pred, labels=present_classes, target_names=target_names,
        output_dict=True, zero_division=0,
    )
    log.info("\n%s", classification_report(
        y_test, y_pred, labels=present_classes, target_names=target_names, zero_division=0,
    ))
    log.info("Confusion matrix (rows=true, cols=pred):\n%s",
              confusion_matrix(y_test, y_pred, labels=present_classes))

    macro_f1 = f1_score(y_test, y_pred, average="macro")
    weighted_f1 = f1_score(y_test, y_pred, average="weighted")
    log.info("Macro F1: %.4f (treats every class equally — the one to watch "
              "given how imbalanced this dataset is)", macro_f1)
    log.info("Weighted F1: %.4f", weighted_f1)

    return report, macro_f1, weighted_f1


# --------------------------------------------------------------------------
# 7. FEATURE IMPORTANCE
# --------------------------------------------------------------------------
def log_top_features(model, feature_names, top_n=20):
    importances = model.feature_importances_
    idx = np.argsort(importances)[::-1][:top_n]
    lines = [f"  {feature_names[i]:35s} {importances[i]:.4f}" for i in idx]
    log.info("Top %d features:\n%s", top_n, "\n".join(lines))


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", required=True)
    parser.add_argument("--out_dir", default="./artifacts")
    parser.add_argument("--corr_threshold", type=float, default=0.95)
    parser.add_argument("--no_xgb", action="store_true")
    parser.add_argument("--drop_leaky_features", action="store_true")
    args = parser.parse_args()

    run_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.out_dir, f"run_{run_id}")
    os.makedirs(run_dir, exist_ok=True)

    # 1-2. Load + clean
    df = load_data(args.data_dir)
    df = clean_data(df)

    if args.drop_leaky_features:
        present = [c for c in LEAKY_FEATURES if c in df.columns]
        if present:
            log.info("Dropping leaky features: %s", present)
            df = df.drop(columns=present)

    # 3. Labels — full multiclass, every attack type kept distinct
    y_raw = df["Label"]
    le = LabelEncoder()
    y_all = pd.Series(le.fit_transform(y_raw), index=y_raw.index)
    log.info("Classes (%d): %s", len(le.classes_),
              dict(zip(le.classes_, range(len(le.classes_)))))
    log.info("Distribution:\n%s", y_raw.value_counts().to_string())

    X_all = df.drop(columns=["Label"]).select_dtypes(include=[np.number])

    # 4. Split (rare classes routed to train only, see split_data docstring)
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X_all, y_all)

    # 5. Correlated feature pruning (fit on train only)
    corr_drop = find_correlated_features(X_train, threshold=args.corr_threshold)
    log.info("Dropping %d correlated features (>%.2f): %s",
              len(corr_drop), args.corr_threshold, corr_drop)
    X_train = X_train.drop(columns=corr_drop)
    X_val = X_val.drop(columns=corr_drop)
    X_test = X_test.drop(columns=corr_drop)
    feature_names = X_train.columns.tolist()

    # 6. Sanitize only — no imputation, no scaling
    sanitizer = InfinityAndOutlierSanitizer(clip_quantile=0.999)
    X_train_s = sanitizer.fit_transform(X_train)
    X_val_s = sanitizer.transform(X_val)
    X_test_s = sanitizer.transform(X_test)

    # 7. Train
    model, fallback_imputer = train_model(
        X_train_s, y_train, X_val_s, y_val,
        num_classes=len(le.classes_), use_xgb=not args.no_xgb,
    )
    if fallback_imputer is not None:
        X_test_s = fallback_imputer.transform(X_test_s)

    # 8. Evaluate on untouched test set
    report, macro_f1, weighted_f1 = evaluate(model, X_test_s, y_test, le)
    log_top_features(model, feature_names)

    # 9. Bundle into one servable pipeline
    steps = [("sanitize", sanitizer)]
    if fallback_imputer is not None:
        steps.append(("impute", fallback_imputer))
    steps.append(("model", model))
    full_pipeline = Pipeline(steps=steps)

    joblib.dump(full_pipeline, os.path.join(run_dir, "ids_pipeline.pkl"))
    joblib.dump(le, os.path.join(run_dir, "label_encoder.pkl"))

    metadata = {
        "run_id": run_id,
        "mode": "multiclass",
        "feature_names_in_order": feature_names,
        "dropped_correlated_features": corr_drop,
        "dropped_leaky_features": LEAKY_FEATURES if args.drop_leaky_features else [],
        "classes": le.classes_.tolist(),
        "rare_classes_train_only": [
            c for c in le.classes_
            if (y_raw == c).sum() < MIN_ROWS_PER_CLASS_FOR_SPLIT
        ],
        "macro_f1_test": macro_f1,
        "weighted_f1_test": weighted_f1,
        "classification_report_test": report,
        "model_type": "xgboost" if (HAS_XGB and not args.no_xgb) else "random_forest",
        "scaling_used": False,
        "seed": SEED,
    }
    with open(os.path.join(run_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    log.info("Saved full pipeline + metadata to %s", run_dir)


if __name__ == "__main__":
    main()