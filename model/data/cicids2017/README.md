# CICIDS2017 labeled dataset files

Put the labeled CICIDS2017 CICFlowMeter `.csv` file(s) in this folder. Keep the
`Label` column and the original feature column names. The dataset can be large;
these CSV files are excluded from Git so they are not accidentally committed.

From the `ids` project folder, run:

```powershell
python model/evaluate_dataset.py
```

By default, the evaluator recreates the project's seeded train/validation/test
split and scores only the held-out test portion. This is appropriate when the
CSV files are the same complete dataset used to train the saved model. If you
have a separate test-only CSV that was never used in training, pass
`--already-held-out` so every row is scored as test data.

The script writes `predictions_sample.csv` and `evaluation_report.json` under
`model/artifacts/dataset_demo/`. It does not send records to the live dashboard
or create database alerts.

## Show dataset predictions as dashboard alerts

With the backend and frontend running, and an enabled agent already registered,
run this from the `ids` project folder:

```powershell
python model/replay_dataset.py --label "DoS Hulk" --limit 10
```

Enter the existing agent token when prompted (the input is hidden). The replay
sends only the selected test rows' network features to the event API; it does not send their
`Label` values. The backend model makes the prediction and creates an alert
when its normal alert conditions are met. Results are written to
`model/artifacts/dataset_demo/replay_results.csv`. This adds detection records
to the local project database; repeated rows may be grouped into one alert.
