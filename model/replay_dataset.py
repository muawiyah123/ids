"""Replay a small number of labeled CICIDS2017 test flows into the IDS API.

The ground-truth Label is used only to choose the requested test class and is
never sent to the API. The backend receives feature data and performs its own
model inference, detection, and alert creation as it does for a live agent.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import math
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


MODEL_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send a few held-out CICIDS2017 samples through the live IDS alert pipeline."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=MODEL_DIR / "data" / "cicids2017",
        help="Folder containing the full labeled CICIDS2017 CSV set.",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=MODEL_DIR / "artifacts",
        help="Folder containing the saved model metadata.",
    )
    parser.add_argument(
        "--event-url",
        default="http://localhost:8000/api/v1/events",
        help="Backend event endpoint.",
    )
    parser.add_argument(
        "--label",
        default="DoS Hulk",
        help="Ground-truth test class to select (default: DoS Hulk). This label is not sent to the API.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of flows to replay (1-100; default: 10).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=MODEL_DIR / "artifacts" / "dataset_demo" / "replay_results.csv",
        help="Where to save actual-vs-predicted replay results.",
    )
    return parser.parse_args()


def _json_feature_value(value: object) -> float | None:
    import pandas as pd

    if pd.isna(value):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def _optional_int(value: object) -> int | None:
    import pandas as pd

    if pd.isna(value):
        return None
    try:
        result = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return max(0, min(65535, result))


def _protocol(value: object) -> str | None:
    import pandas as pd

    if pd.isna(value):
        return None
    try:
        protocol_number = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return str(value).upper()[:10]
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol_number, str(protocol_number))


def _timestamp(value: object) -> str | None:
    import pandas as pd

    if pd.isna(value):
        return None
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(parsed):
        return None
    return parsed.to_pydatetime().astimezone(timezone.utc).isoformat()


def main() -> None:
    args = parse_args()
    if not 1 <= args.limit <= 100:
        raise SystemExit("--limit must be between 1 and 100.")

    try:
        import joblib
        import numpy as np
        import pandas as pd
        from ids_common import InfinityAndOutlierSanitizer
        from sklearn.preprocessing import LabelEncoder
        from train import clean_data, load_data, split_data
    except ImportError as exc:
        raise SystemExit(
            "Replay dependencies are missing. Install them with "
            "`python -m pip install -r model/requirements.txt`. "
            f"Details: {exc}"
        ) from exc

    # Retain compatibility with model artifacts serialized with the
    # pre-refactor class path `__main__.InfinityAndOutlierSanitizer`.
    setattr(sys.modules["__main__"], "InfinityAndOutlierSanitizer", InfinityAndOutlierSanitizer)

    metadata_path = args.artifact_dir / "metadata.json"
    encoder_path = args.artifact_dir / "label_encoder.pkl"
    if not metadata_path.is_file() or not encoder_path.is_file():
        raise SystemExit(f"Model metadata or label encoder missing under {args.artifact_dir}.")

    csv_files = sorted(args.data_dir.glob("*.csv"))
    if not csv_files:
        raise SystemExit(f"No CICIDS2017 CSV files found in {args.data_dir}.")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    feature_names = metadata.get("feature_names_in_order", [])
    if not feature_names:
        raise SystemExit("Model metadata has no feature_names_in_order list.")
    model_encoder = joblib.load(encoder_path)

    print(f"Loading {len(csv_files)} CICIDS2017 CSV files and preparing the held-out split...")
    df = clean_data(load_data(str(args.data_dir)))
    labels = df["Label"].astype(str).str.strip()
    dataset_encoder = LabelEncoder()
    encoded_labels = pd.Series(dataset_encoder.fit_transform(labels), index=df.index)
    if list(dataset_encoder.classes_) != list(model_encoder.classes_):
        raise SystemExit(
            "The dataset label classes do not match the saved model. "
            "Use the same full CICIDS2017 CSV set used to train this model."
        )

    missing_features = [name for name in feature_names if name not in df.columns]
    if missing_features:
        raise SystemExit("Missing model feature columns: " + ", ".join(missing_features))

    numeric_features = df.drop(columns=["Label"]).select_dtypes(include=[np.number])
    _, _, X_test, _, _, y_test = split_data(numeric_features, encoded_labels)
    y_test_labels = dataset_encoder.inverse_transform(y_test.to_numpy())
    matching_positions = np.flatnonzero(y_test_labels == args.label)
    if not len(matching_positions):
        available = ", ".join(sorted(set(y_test_labels)))
        raise SystemExit(
            f"No '{args.label}' rows were found in the held-out test split. "
            f"Classes available: {available}"
        )

    chosen_positions = matching_positions[: args.limit]
    test_indices = X_test.index.to_numpy()[chosen_positions]
    context_rows = df.loc[test_indices]
    selected_features = X_test.iloc[chosen_positions][feature_names]
    selected_labels = y_test_labels[chosen_positions]

    event_url = args.event_url.strip()
    token = getpass.getpass("Agent token (input hidden): ").strip()
    if not token:
        raise SystemExit("Agent token is required.")

    print(
        f"Replaying {len(chosen_positions)} held-out {args.label} flow(s) to {event_url}. "
        "The dataset Label is not included in the events."
    )

    results: list[dict[str, object]] = []
    for index, (position, feature_row, context) in enumerate(
        zip(chosen_positions, selected_features.to_dict(orient="records"),
            (context_rows.iloc[i] for i in range(len(context_rows)))),
        start=1,
    ):
        features = {name: _json_feature_value(feature_row[name]) for name in feature_names}
        event = {
            "event_id": f"cicids-replay-{uuid4()}",
            # Treat the replay as happening now so the dashboard sorts it as
            # a fresh event; retain the original capture time as provenance.
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": str(context.get("Source IP", "")) or None,
            "destination_ip": str(context.get("Destination IP", "")) or None,
            "source_port": _optional_int(context.get("Source Port")),
            "destination_port": _optional_int(context.get("Destination Port")),
            "protocol": _protocol(context.get("Protocol")),
            "features": features,
            "metadata": {
                "demo_source": "CICIDS2017 held-out dataset replay",
                "source_timestamp": _timestamp(context.get("Timestamp")),
            },
        }
        request = urllib.request.Request(
            event_url,
            data=json.dumps(event, allow_nan=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise SystemExit(
                f"Backend rejected sample {index} (HTTP {exc.code}): {detail[:500]}\n"
                "Check that the backend is running and the token belongs to an enabled agent."
            ) from exc
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"Could not connect to {event_url}: {exc.reason}. "
                "Start the project backend and retry."
            ) from exc

        try:
            result = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Backend returned an unexpected response: {response_body[:300]}") from exc

        row_result: dict[str, object] = {
            "actual_dataset_label": str(selected_labels[index - 1]),
            "predicted_label": result.get("prediction", ""),
            "confidence": result.get("confidence", ""),
            "severity": result.get("severity", ""),
            "alert_id": result.get("alert_id", "") or "",
            "status": result.get("status", ""),
        }
        results.append(row_result)
        print(
            f"{index}/{len(chosen_positions)}: actual={row_result['actual_dataset_label']} | "
            f"predicted={row_result['predicted_label']} | "
            f"confidence={float(row_result['confidence'] or 0):.1%} | "
            f"alert={'created/updated' if row_result['alert_id'] else 'none'}"
        )
        time.sleep(0.1)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"Replay results saved to {args.output.resolve()}")
    print("Open the Alerts page to see any generated or updated alerts.")


if __name__ == "__main__":
    main()
