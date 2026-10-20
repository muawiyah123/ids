"""Evaluate the saved IDS model on labeled CICIDS2017 CSV flow records.

By default, the input directory is treated as the original dataset used to
train the model. The script recreates train.py's deterministic held-out test
split and scores only that split. Use --already-held-out for CSV files that
were kept separate from model training.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score labeled CICIDS2017 CSV flows with the saved IDS model."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=MODEL_DIR / "data" / "cicids2017",
        help="Folder containing labeled CICIDS2017 CSV files.",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=MODEL_DIR / "artifacts",
        help="Folder containing ids_pipeline.pkl, label_encoder.pkl, and metadata.json.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=MODEL_DIR / "artifacts" / "dataset_demo",
        help="Folder for the report and prediction sample CSV.",
    )
    parser.add_argument(
        "--already-held-out",
        action="store_true",
        help="Evaluate every row as an independently held-out test row; do not recreate a split.",
    )
    parser.add_argument(
        "--sample-rows",
        type=int,
        default=1000,
        help="Maximum predictions to save in the review CSV (metrics use every test row).",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = parse_args()

    try:
        import joblib
        import numpy as np
        import pandas as pd
        from sklearn.metrics import (
            accuracy_score,
            classification_report,
            confusion_matrix,
            f1_score,
        )
        from sklearn.preprocessing import LabelEncoder
        from ids_common import InfinityAndOutlierSanitizer
        from train import clean_data, load_data, split_data
    except ImportError as exc:
        raise SystemExit(
            "Model evaluation dependencies are missing. Install them with "
            "`python -m pip install -r model/requirements.txt`. "
            f"Details: {exc}"
        ) from exc

    # Some existing pipeline artifacts were pickled with this class recorded
    # under __main__. Match the backend loader's compatibility alias before
    # deserializing them.
    import sys
    setattr(sys.modules["__main__"], "InfinityAndOutlierSanitizer", InfinityAndOutlierSanitizer)

    csv_files = sorted(args.data_dir.glob("*.csv"))
    if not csv_files:
        raise SystemExit(
            f"No CSV files found in {args.data_dir}. Put the labeled CICIDS2017 CSV files there."
        )

    required_artifacts = [
        args.artifact_dir / "ids_pipeline.pkl",
        args.artifact_dir / "label_encoder.pkl",
        args.artifact_dir / "metadata.json",
    ]
    missing_artifacts = [str(path) for path in required_artifacts if not path.is_file()]
    if missing_artifacts:
        raise SystemExit("Missing model artifact(s): " + ", ".join(missing_artifacts))

    with (args.artifact_dir / "metadata.json").open(encoding="utf-8") as f:
        metadata = json.load(f)
    feature_names = metadata.get("feature_names_in_order", [])
    if not feature_names:
        raise SystemExit("Model metadata has no feature_names_in_order list.")

    pipeline = joblib.load(args.artifact_dir / "ids_pipeline.pkl")
    model_encoder = joblib.load(args.artifact_dir / "label_encoder.pkl")

    print(f"Reading {len(csv_files)} CSV file(s) from {args.data_dir} ...")
    df = clean_data(load_data(str(args.data_dir)))
    if "Label" not in df.columns:
        raise SystemExit("CSV files must include a 'Label' column with the true class.")

    missing_features = [name for name in feature_names if name not in df.columns]
    if missing_features:
        raise SystemExit(
            "These model feature columns are missing from the CSV files: "
            + ", ".join(missing_features)
            + ". Use CICIDS2017 CICFlowMeter CSV files."
        )

    labels = df["Label"].astype(str).str.strip()
    if args.already_held_out:
        X_test = df[feature_names].apply(pd.to_numeric, errors="coerce")
        y_true = labels.to_numpy()
        evaluation_mode = "provided held-out rows"
    else:
        dataset_encoder = LabelEncoder()
        y_encoded = pd.Series(dataset_encoder.fit_transform(labels), index=df.index)
        model_classes = list(model_encoder.classes_)
        if list(dataset_encoder.classes_) != model_classes:
            raise SystemExit(
                "The CSV label classes do not exactly match this model's training classes. "
                "For a separate test-only CSV, use --already-held-out."
            )

        numeric_features = df.drop(columns=["Label"]).select_dtypes(include=[np.number])
        X_train, X_val, X_test, y_train, y_val, y_test = split_data(
            numeric_features, y_encoded
        )
        del X_train, X_val, y_train, y_val
        X_test = X_test[feature_names]
        y_true = dataset_encoder.inverse_transform(y_test.to_numpy())
        evaluation_mode = "recreated stratified held-out test split (seed 42)"

    X_test = X_test.apply(pd.to_numeric, errors="coerce")
    known_classes = set(model_encoder.classes_)
    unknown_labels = sorted(set(y_true) - known_classes)
    if unknown_labels:
        raise SystemExit(
            "The test data contains labels not supported by this model: "
            + ", ".join(unknown_labels)
        )
    if len(X_test) == 0:
        raise SystemExit("No test rows to evaluate.")

    print(f"Running model predictions on {len(X_test):,} labeled test row(s) ...")
    predicted_ids = pipeline.predict(X_test)
    y_pred = model_encoder.inverse_transform(np.asarray(predicted_ids, dtype=int))
    probabilities = pipeline.predict_proba(X_test)
    confidence = probabilities.max(axis=1)

    class_names = list(model_encoder.classes_)
    scored_classes = sorted(set(y_true) | set(y_pred))
    report = classification_report(
        y_true,
        y_pred,
        labels=scored_classes,
        target_names=scored_classes,
        output_dict=True,
        zero_division=0,
    )
    accuracy = float(accuracy_score(y_true, y_pred))
    # Match model/train.py: macro F1 averages classes present in the true or
    # predicted labels, so a class with no held-out examples is not counted as
    # a zero-score class.
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    sample_count = min(max(args.sample_rows, 0), len(X_test))
    predictions_path = args.output_dir / "predictions_sample.csv"
    pd.DataFrame(
        {
            "actual_label": y_true[:sample_count],
            "predicted_label": y_pred[:sample_count],
            "confidence": confidence[:sample_count],
            "correct": y_true[:sample_count] == y_pred[:sample_count],
        }
    ).to_csv(predictions_path, index=False)

    matrix = confusion_matrix(y_true, y_pred, labels=class_names)
    report_payload = {
        "evaluation_mode": evaluation_mode,
        "rows_evaluated": int(len(X_test)),
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "classification_report": report,
        "classes_scored": scored_classes,
        "classes_without_test_or_prediction_rows": sorted(set(class_names) - set(scored_classes)),
        "confusion_matrix_labels": class_names,
        "confusion_matrix": matrix.tolist(),
        "saved_prediction_sample_rows": int(sample_count),
        "predictions_sample_csv": str(predictions_path.resolve()),
        "source_csv_files": [path.name for path in csv_files],
        "model_run_id": metadata.get("run_id"),
    }
    report_path = args.output_dir / "evaluation_report.json"
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2, ensure_ascii=False)

    print(f"Evaluation mode: {evaluation_mode}")
    print(f"Accuracy:        {accuracy:.4f}")
    print(f"Macro F1:        {macro_f1:.4f}")
    print(f"Weighted F1:     {weighted_f1:.4f}")
    print("\nPer-class results:")
    print(classification_report(
        y_true, y_pred, labels=scored_classes, target_names=scored_classes, zero_division=0
    ))
    print(f"Prediction examples: {predictions_path.resolve()}")
    print(f"Full metrics report: {report_path.resolve()}")


if __name__ == "__main__":
    main()
