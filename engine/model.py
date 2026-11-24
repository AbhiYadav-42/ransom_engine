"""
engine/model.py -- Stage 6: load the trained forest and score FeatureRows.

SECURITY: .joblib files are pickles; loading one can run arbitrary code.
Only load model files you made yourself or fully trust.
"""

import json
import warnings
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import sklearn

from engine.features_schema import FEATURE_NAMES, SCHEMA_VERSION, schema_fingerprint, to_vector

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "rf.joblib"
DEFAULT_META_PATH = PROJECT_ROOT / "models" / "rf_meta.json"


class ModelError(Exception):
    """Raised when the model cannot be loaded or does not match the current schema."""


@dataclass(frozen=True)
class Prediction:
    is_ransomware: bool
    probability: float
    ok: bool = True          # False = the input was bad; is_ransomware is False, probability 0.0
    error: str = ""


class FastForest:
    """Plain-Python walk over a fitted RandomForest's trees (skips sklearn's per-call overhead).
    Same maths as predict_proba: mean over trees of the leaf's class-1 share."""

    def __init__(self, forest, positive_index):
        self._trees = []
        for estimator in forest.estimators_:
            tree = estimator.tree_
            values = tree.value[:, 0, :]
            positive = (values[:, positive_index] / values.sum(axis=1)).tolist()
            self._trees.append((tree.children_left.tolist(), tree.children_right.tolist(),
                                tree.feature.tolist(), tree.threshold.tolist(), positive))

    def predict_proba_positive(self, x):
        """x = list of floats already rounded to float32 (sklearn compares float32 values)."""
        total = 0.0
        for left, right, feature, threshold, positive in self._trees:
            node = 0
            while left[node] != -1:                       # -1 marks a leaf
                node = left[node] if x[feature[node]] <= threshold[node] else right[node]
            total += positive[node]
        return total / len(self._trees)


class Predictor:
    def __init__(self, model_path=DEFAULT_MODEL_PATH, meta_path=DEFAULT_META_PATH, use_fast_path=True):
        self.warnings = []
        self.stats = {"predictions": 0, "bad_inputs": 0}
        self.last_error = ""
        meta = self._read_meta(meta_path)
        self._check_schema(meta)
        self.meta = meta
        try:
            self.threshold = float(meta["threshold"])
        except (KeyError, TypeError, ValueError):
            raise ModelError("rf_meta.json has no valid 'threshold'")
        self._check_versions(meta)

        try:
            model = joblib.load(model_path)     # trusted files only (see the security note above)
        except Exception as error:
            raise ModelError("cannot load model file %s: %r" % (model_path, error))
        self._n_features = len(FEATURE_NAMES)
        if getattr(model, "n_features_in_", None) != self._n_features:
            raise ModelError("model expects %s features, schema has %d. Retrain."
                             % (getattr(model, "n_features_in_", "?"), self._n_features))
        if 1 not in list(model.classes_):
            raise ModelError("model was trained without positive (ransomware) examples")
        self._model = model
        self._positive_index = list(model.classes_).index(1)
        self._fast = self._build_fast_path(model) if use_fast_path else None
        self.using_fast_path = self._fast is not None

    # ---- loading checks ----
    def _read_meta(self, meta_path):
        try:
            with open(meta_path) as handle:
                return json.load(handle)
        except Exception as error:
            raise ModelError("cannot read %s: %r" % (meta_path, error))

    def _check_schema(self, meta):
        problems = []
        if meta.get("schema_version") != SCHEMA_VERSION:
            problems.append("schema version %s != %s" % (meta.get("schema_version"), SCHEMA_VERSION))
        if meta.get("schema_fingerprint") != schema_fingerprint():
            problems.append("schema fingerprint differs")
        if list(meta.get("feature_names", [])) != list(FEATURE_NAMES):
            problems.append("feature names/order differ")
        if problems:
            raise ModelError("Refusing to load the model: " + "; ".join(problems)
                             + ". Retrain with the current schema.")

    def _check_versions(self, meta):
        trained = (meta.get("versions") or {}).get("scikit_learn")
        if trained and trained != sklearn.__version__:
            message = ("model was trained with scikit-learn %s, this is %s: results may differ"
                       % (trained, sklearn.__version__))
            self.warnings.append(message)
            warnings.warn(message, RuntimeWarning)

    def _build_fast_path(self, model):
        """Use the fast walk only if it matches sklearn on random inputs."""
        try:
            fast = FastForest(model, self._positive_index)
            rng = np.random.default_rng(0)
            samples = rng.normal(0.0, 50.0, size=(20, self._n_features))
            expected = model.predict_proba(samples)[:, self._positive_index]
            for sample, want in zip(samples, expected):
                got = fast.predict_proba_positive(sample.astype(np.float32).tolist())
                if abs(got - want) > 1e-9:
                    raise ValueError("fast path differs from sklearn")
            return fast
        except Exception as error:
            self.warnings.append("fast path disabled: %r" % (error,))
            return None

    # ---- prediction ----
    def predict_detailed(self, row):
        """Never raises. Bad input -> Prediction(False, 0.0, ok=False, error=...)."""
        try:
            vector = self._to_vector(row)
        except Exception as error:
            return self._bad_input(str(error))
        try:
            probability = self._probability(vector)
        except Exception as error:
            return self._bad_input("prediction failed: %r" % (error,))
        self.stats["predictions"] += 1
        return Prediction(is_ransomware=probability >= self.threshold, probability=probability)

    def predict(self, row):
        """row = FeatureRow, dict {name: value}, list/tuple or numpy vector in schema order.
        Returns (is_ransomware, probability)."""
        result = self.predict_detailed(row)
        return result.is_ransomware, result.probability

    def _to_vector(self, row):
        if row is None:
            raise ValueError("input is None")
        if isinstance(row, dict):
            values = to_vector(row)                       # checks names; orders by the schema
        elif hasattr(row, "to_vector"):
            values = row.to_vector()                      # a FeatureRow
        else:
            values = list(row)
        array = np.asarray(values, dtype=float)
        if array.ndim != 1 or array.shape[0] != self._n_features:
            raise ValueError("wrong feature count: got %s, expected %d" % (array.shape, self._n_features))
        if not np.all(np.isfinite(array)):
            raise ValueError("feature vector contains NaN or infinity")
        return array

    def _probability(self, vector):
        if self._fast is not None:
            value = self._fast.predict_proba_positive(vector.astype(np.float32).tolist())
        else:
            value = self._model.predict_proba(vector.reshape(1, -1))[0, self._positive_index]
        return min(1.0, max(0.0, float(value)))

    def _bad_input(self, message):
        self.stats["bad_inputs"] += 1
        self.last_error = message
        return Prediction(is_ransomware=False, probability=0.0, ok=False, error=message)