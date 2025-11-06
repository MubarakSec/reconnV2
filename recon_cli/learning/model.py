from __future__ import annotations

import math
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from recon_cli.learning.collector import DatasetStore, HostFeatures
from recon_cli.utils import time as time_utils


MODEL_FILENAME = "model_logreg.npz"


def _feature_vector(record: Dict[str, object], feature_keys: List[str]) -> np.ndarray:
    features = record.get("features", {})
    return np.array([float(features.get(key, 0.0)) for key in feature_keys], dtype=float)


class LearningModel:
    def __init__(self, learning_root: Path, feature_keys: List[str]) -> None:
        self.learning_root = learning_root
        self.model_path = self.learning_root / MODEL_FILENAME
        self.feature_keys = feature_keys
        self.scaler: StandardScaler | None = None
        self.model: LogisticRegression | None = None

    def train(self, labeled_records: List[Dict[str, object]]) -> bool:
        positives = [rec for rec in labeled_records if rec.get("label") == 1]
        negatives = [rec for rec in labeled_records if rec.get("label") == 0]
        if len(positives) < 5 or len(negatives) < 5:
            return False
        X = np.vstack([
            _feature_vector(rec, self.feature_keys) for rec in positives + negatives
        ])
        y = np.array([1] * len(positives) + [0] * len(negatives))
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = LogisticRegression(max_iter=1000)
        self.model.fit(X_scaled, y)
        self._persist()
        return True

    def _persist(self) -> None:
        if self.model is None or self.scaler is None:
            return
        self.learning_root.mkdir(parents=True, exist_ok=True)
        np.savez(
            self.model_path,
            coef_=self.model.coef_,
            intercept_=self.model.intercept_,
            classes_=self.model.classes_,
            scaler_mean_=self.scaler.mean_,
            scaler_scale_=self.scaler.scale_,
            feature_keys=np.array(self.feature_keys),
            trained_at=time_utils.iso_now(),
        )

    def load(self) -> bool:
        if not self.model_path.exists():
            return False
        data = np.load(self.model_path, allow_pickle=True)
        self.feature_keys = list(data["feature_keys"].tolist())
        self.scaler = StandardScaler()
        self.scaler.mean_ = data["scaler_mean_"]
        self.scaler.scale_ = data["scaler_scale_"]
        coef = data["coef_"]
        intercept = data["intercept_"]
        classes = data["classes_"]
        self.model = LogisticRegression()
        self.model.coef_ = coef
        self.model.intercept_ = intercept
        self.model.classes_ = classes
        return True

    def predict(self, hosts: Iterable[HostFeatures]) -> Dict[str, float]:
        if self.model is None or self.scaler is None:
            if not self.load():
                return {}
        predictions: Dict[str, float] = {}
        for host in hosts:
            vector = _feature_vector(host.to_record(""), self.feature_keys)
            X = vector.reshape(1, -1)
            X_scaled = self.scaler.transform(X)
            prob = float(self.model.predict_proba(X_scaled)[0, 1])
            predictions[host.host] = prob
        return predictions
