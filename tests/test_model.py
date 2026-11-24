"""Stage 6 tests: Predictor safety, training helpers on synthetic data, generator safety. No desktop."""

import json

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from engine.aggregator import FeatureRow
from engine.features_schema import FEATURE_NAMES, SCHEMA_VERSION, schema_fingerprint
from engine.model import FastForest, ModelError, Predictor
from ml.train import (evaluate, make_model, make_synthetic_dataset, positive_proba, select_model,
                      split_by_run, tune_threshold)
from sim.sandbox_common import ensure_inside, require_marker
from tools.collect_dataset import label_for


def build_model_files(folder, X, y, threshold=0.5, meta_overrides=None):
    model = RandomForestClassifier(n_estimators=10, max_depth=4, random_state=0, n_jobs=1).fit(X, y)
    joblib.dump(model, folder / "rf.joblib", compress=3)
    meta = {"schema_version": SCHEMA_VERSION, "schema_fingerprint": schema_fingerprint(),
            "feature_names": list(FEATURE_NAMES), "threshold": threshold}
    meta.update(meta_overrides or {})
    (folder / "rf_meta.json").write_text(json.dumps(meta))
    return folder / "rf.joblib", folder / "rf_meta.json"


def load_predictor(tmp_path, threshold=0.5, meta_overrides=None, X=None, y=None):
    data = make_synthetic_dataset(0)
    X = data.X if X is None else X
    y = data.y if y is None else y
    model_path, meta_path = build_model_files(tmp_path, X, y, threshold, meta_overrides)
    return Predictor(model_path, meta_path), data


# ----- Predictor ------------------------------------------------------------
def test_predictor_separates_attack_from_benign_rows(tmp_path):
    predictor, data = load_predictor(tmp_path)
    attack_row = data.X[data.y == 1][0]
    benign_row = data.X[data.y == 0][0]
    flagged, probability = predictor.predict(attack_row)
    assert flagged is True and probability > 0.5
    flagged, probability = predictor.predict(benign_row)
    assert flagged is False and probability < 0.5


def test_threshold_is_applied(tmp_path):
    low, data = load_predictor(tmp_path, threshold=0.0)
    assert low.predict(data.X[0])[0] is True                 # probability >= 0.0 always
    high, _ = load_predictor(tmp_path, threshold=1.5)
    assert high.predict(data.X[data.y == 1][0])[0] is False  # nothing reaches 1.5


def test_schema_version_mismatch_is_refused(tmp_path):
    with pytest.raises(ModelError):
        load_predictor(tmp_path, meta_overrides={"schema_version": "0.9"})


def test_fingerprint_mismatch_is_refused(tmp_path):
    with pytest.raises(ModelError):
        load_predictor(tmp_path, meta_overrides={"schema_fingerprint": "deadbeef"})


def test_feature_order_mismatch_is_refused(tmp_path):
    swapped = list(FEATURE_NAMES)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    with pytest.raises(ModelError):
        load_predictor(tmp_path, meta_overrides={"feature_names": swapped})


def test_model_with_wrong_feature_count_is_refused(tmp_path):
    data = make_synthetic_dataset(0)
    with pytest.raises(ModelError):
        load_predictor(tmp_path, X=data.X[:, :5], y=data.y)


def test_missing_files_are_refused(tmp_path):
    with pytest.raises(ModelError):
        Predictor(tmp_path / "nope.joblib", tmp_path / "nope.json")


def test_bad_input_returns_a_clear_result_and_never_raises(tmp_path):
    predictor, _ = load_predictor(tmp_path)
    bad_inputs = [None, "abc", [1, 2, 3], [float("nan")] * len(FEATURE_NAMES), {"events_per_sec_1s": 1.0}]
    for bad in bad_inputs:
        result = predictor.predict_detailed(bad)
        assert result.ok is False and result.error != ""
        assert predictor.predict(bad) == (False, 0.0)
    assert predictor.stats["bad_inputs"] >= len(bad_inputs)


def test_wrong_feature_count_is_reported(tmp_path):
    predictor, _ = load_predictor(tmp_path)
    result = predictor.predict_detailed([0.0] * (len(FEATURE_NAMES) - 1))
    assert result.ok is False
    assert "wrong feature count" in result.error
    assert str(len(FEATURE_NAMES)) in result.error


def test_accepts_feature_row_dict_list_and_array(tmp_path):
    predictor, data = load_predictor(tmp_path)
    vector = data.X[data.y == 1][0]
    row = FeatureRow(timestamp=1.0, source_key="global", values=tuple(float(v) for v in vector))
    by_name = dict(zip(FEATURE_NAMES, [float(v) for v in vector]))
    results = [predictor.predict(item) for item in (row, by_name, list(vector), vector)]
    assert all(result == results[0] for result in results)


def test_fast_path_matches_sklearn(tmp_path):
    predictor, data = load_predictor(tmp_path)
    assert predictor.using_fast_path is True
    for vector in data.X[::17]:
        want = predictor._model.predict_proba(vector.reshape(1, -1))[0, predictor._positive_index]
        assert predictor.predict_detailed(vector).probability == pytest.approx(want, abs=1e-9)


def test_sklearn_version_mismatch_warns(tmp_path):
    with pytest.warns(RuntimeWarning):
        load_predictor(tmp_path, meta_overrides={"versions": {"scikit_learn": "0.0.1"}})


# ----- training helpers on synthetic data ----------------------------------
def test_tune_threshold_picks_the_lowest_threshold_within_the_fpr_limit():
    y = np.array([0, 0, 0, 0, 1, 1])
    proba = np.array([0.1, 0.2, 0.3, 0.4, 0.35, 0.9])
    threshold = tune_threshold(y, proba, max_fpr=0.25)       # one false positive in four is allowed
    assert threshold == pytest.approx(0.35)
    assert evaluate(y, proba, threshold)["recall"] == 1.0


def test_split_by_run_never_shares_a_run():
    data = make_synthetic_dataset(0)
    train_idx, test_idx = split_by_run(data.y, data.groups, seed=1)
    assert set(data.groups[train_idx]).isdisjoint(set(data.groups[test_idx]))
    assert set(data.y[train_idx]) == {0, 1} and set(data.y[test_idx]) == {0, 1}


def test_tiny_training_run_on_synthetic_data_is_sane_and_fast():
    data = make_synthetic_dataset(1)
    train_idx, test_idx = split_by_run(data.y, data.groups, seed=1)
    chosen, _results, _met = select_model(
        data.X[train_idx], data.y[train_idx], data.groups[train_idx],
        n_estimators_list=(10,), depth_list=(4,), max_fpr=0.01, target_recall=0.8, seed=0)
    model = make_model(chosen["n_estimators"], chosen["max_depth"], 0).fit(data.X[train_idx], data.y[train_idx])
    ev = evaluate(data.y[test_idx], positive_proba(model, data.X[test_idx]), chosen["threshold"])
    assert ev["recall"] >= 0.8
    assert ev["fpr"] <= 0.05
    canary = FEATURE_NAMES.index("canary_touched")             # constant column: ignored, no crash
    assert model.feature_importances_[canary] == 0.0


# ----- collector label rule and generator safety ---------------------------
def test_label_rule():
    assert label_for(5.0, 5.0, 8.0, 5.0) == 1
    assert label_for(4.99, 5.0, 8.0, 5.0) == 0
    assert label_for(13.0, 5.0, 8.0, 5.0) == 1
    assert label_for(13.01, 5.0, 8.0, 5.0) == 0
    assert label_for(9.0, None, None, 5.0) == 0


def test_generators_refuse_a_folder_without_the_marker(tmp_path):
    with pytest.raises(SystemExit):
        require_marker(tmp_path)
    (tmp_path / ".ransom_sandbox").write_text("ok")
    assert require_marker(tmp_path) == tmp_path.resolve()


def test_generators_cannot_touch_paths_outside_their_work_folder(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    with pytest.raises(RuntimeError):
        ensure_inside(work, outside)
    with pytest.raises(RuntimeError):
        ensure_inside(work, work)
    ensure_inside(work, work / "inside.txt")                   # allowed