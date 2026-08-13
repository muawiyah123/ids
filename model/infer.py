  """
  Real-Time Inference — score live flow records against the trained IDS pipeline.

  Loads exactly what train_ids_model.py saved: one Pipeline object (sanitize ->
  impute -> scale -> model), the label encoder, and metadata.json (feature
  order + decision threshold). Because preprocessing is baked into the
  pipeline, this file has almost no logic of its own — that's the point.

  Usage as a library (e.g. inside your flow-capture loop / Kafka consumer):

      from infer import IDSPredictor
      predictor = IDSPredictor("./artifacts/run_20260101_120000")
      result = predictor.predict(flow_record_dict)
      # result -> {"label": "ATTACK", "confidence": 0.94}

  Usage from CLI on a CSV of flows:

      python infer.py --run_dir ./artifacts/run_20260101_120000 --csv new_flows.csv
  """

  import os
  import json
  import argparse

  import joblib
  import numpy as np
  import pandas as pd


  class IDSPredictor:
      def __init__(self, run_dir: str):
          self.pipeline = joblib.load(os.path.join(run_dir, "ids_pipeline.pkl"))
          self.label_encoder = joblib.load(os.path.join(run_dir, "label_encoder.pkl"))
          with open(os.path.join(run_dir, "metadata.json")) as f:
              self.metadata = json.load(f)

          self.feature_names = self.metadata["feature_names_in_order"]
          self.threshold = self.metadata["decision_threshold"]
          self.mode = self.metadata["mode"]

      def _align_features(self, record: dict) -> pd.DataFrame:
          """Build a single-row DataFrame with exactly the columns the model
          expects, in the right order. Missing keys become NaN and are
          handled by the pipeline's imputer; extra keys are dropped."""
          row = {name: record.get(name, np.nan) for name in self.feature_names}
          return pd.DataFrame([row], columns=self.feature_names)

      def predict(self, record: dict) -> dict:
          X = self._align_features(record)

          if self.mode == "binary":
              proba = self.pipeline.predict_proba(X)[0, 1]
              pred_idx = int(proba >= self.threshold)
              label = self.label_encoder.inverse_transform([pred_idx])[0]
              return {"label": label, "confidence": float(proba)}
          else:
              proba = self.pipeline.predict_proba(X)[0]
              pred_idx = int(np.argmax(proba))
              label = self.label_encoder.inverse_transform([pred_idx])[0]
              return {
                  "label": label,
                  "confidence": float(proba[pred_idx]),
                  "class_probabilities": dict(zip(self.label_encoder.classes_, proba.tolist())),
              }

      def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
          for name in self.feature_names:
              if name not in df.columns:
                  df[name] = np.nan
          X = df[self.feature_names]

          if self.mode == "binary":
              proba = self.pipeline.predict_proba(X)[:, 1]
              pred_idx = (proba >= self.threshold).astype(int)
              labels = self.label_encoder.inverse_transform(pred_idx)
              return pd.DataFrame({"label": labels, "confidence": proba})
          else:
              proba = self.pipeline.predict_proba(X)
              pred_idx = np.argmax(proba, axis=1)
              labels = self.label_encoder.inverse_transform(pred_idx)
              confidence = proba[np.arange(len(proba)), pred_idx]
              return pd.DataFrame({"label": labels, "confidence": confidence})


  def main():
      parser = argparse.ArgumentParser()
      parser.add_argument("--run_dir", required=True)
      parser.add_argument("--csv", required=True, help="CSV of new flow records to score")
      parser.add_argument("--out_csv", default="predictions.csv")
      args = parser.parse_args()

      predictor = IDSPredictor(args.run_dir)
      df = pd.read_csv(args.csv, low_memory=False)
      df.columns = df.columns.str.strip()

      results = predictor.predict_batch(df)
      results.to_csv(args.out_csv, index=False)
      print(f"Wrote {len(results)} predictions to {args.out_csv}")
      print(results["label"].value_counts())


  if __name__ == "__main__":
      main()