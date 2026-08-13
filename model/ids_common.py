"""
Shared preprocessing components used by BOTH train_ids_model.py and infer.py.

This must live in its own importable module (not inside a script run as
__main__), or joblib/pickle can't locate the class when unpickling in a
different entry-point script — that's the
`AttributeError: Can't get attribute 'InfinityAndOutlierSanitizer' on
<module '__main__' ...>` error.
"""

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin


class InfinityAndOutlierSanitizer(BaseEstimator, TransformerMixin):
    """Replace Inf with NaN and clip extreme outliers to training-time
    quantile bounds. No imputation, no scaling — XGBoost consumes NaN
    directly. Runs at both train and inference time since it lives inside
    the saved Pipeline."""

    def __init__(self, clip_quantile: float = 0.999):
        self.clip_quantile = clip_quantile

    def fit(self, X: pd.DataFrame, y=None):
        X = X.replace([np.inf, -np.inf], np.nan)
        self.upper_bounds_ = X.quantile(self.clip_quantile)
        self.lower_bounds_ = X.quantile(1 - self.clip_quantile)
        return self

    def transform(self, X: pd.DataFrame):
        X = X.copy()
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.clip(lower=self.lower_bounds_, upper=self.upper_bounds_, axis=1)
        return X