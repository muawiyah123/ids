import joblib
import pandas as pd
from ids_common import InfinityAndOutlierSanitizer  # needed for unpickling, even though unused directly

run_dir = "./artifacts"

pipeline = joblib.load(f"{run_dir}/ids_pipeline.pkl")
label_encoder = joblib.load(f"{run_dir}/label_encoder.pkl")

df = pd.read_csv("data_clean.csv")
df.columns = df.columns.str.strip()

# must match the exact feature list/order used in training
import json
with open(f"{run_dir}/metadata.json") as f:
    feature_names = json.load(f)["feature_names_in_order"]

X = df[feature_names]
pred_idx = pipeline.predict(X)
pred_labels = label_encoder.inverse_transform(pred_idx)

print(pd.Series(pred_labels).value_counts())