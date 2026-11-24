"""ml/train.py -- train the RandomForest, tune the threshold, export models/rf.joblib + rf_meta.json.

    python ml/train.py --csv data/features_linux.csv [data/features_windows.csv ...]
The split is BY run_id (no run in both train and test). Model choice and threshold use
out-of-fold predictions on the TRAIN runs only; the test runs are scored once at the end.
"""

import argparse
import csv
import json
import platform
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, GroupShuffleSplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.features_schema import FEATURE_NAMES, SCHEMA_VERSION, schema_fingerprint  # noqa: E402

EXTRA_COLUMNS = ("label", "run_id", "os")        # an optional 4th column "variant" may follow
VELOCITY_ONLY = FEATURE_NAMES[:7]                # Stage 3 event features (no placeholders, no inspector)
LABEL_RULE = "ticks from attack_start to attack_end + 5 s = 1, everything else = 0"


@dataclass
class Dataset:
    X: np.ndarray
    y: np.ndarray
    groups: np.ndarray
    os_tags: np.ndarray
    variants: np.ndarray


def load_datasets(paths):
    n = len(FEATURE_NAMES)
    expected = list(FEATURE_NAMES) + list(EXTRA_COLUMNS)
    features, labels, groups, os_tags, variants = [], [], [], [], []
    for path in paths:
        with open(path, newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
            if header[:len(expected)] != expected:
                raise SystemExit("%s: header does not match schema %s. Regenerate this dataset."
                                 % (path, SCHEMA_VERSION))
            has_variant = len(header) > len(expected) and header[len(expected)] == "variant"
            for line in reader:
                if not line:
                    continue
                features.append([float(v) for v in line[:n]])
                labels.append(int(line[n]))
                groups.append(line[n + 1])
                os_tags.append(line[n + 2])
                variants.append(line[n + 3] if has_variant and len(line) > n + 3 else "")
    if not features:
        raise SystemExit("no rows loaded")
    return Dataset(np.array(features), np.array(labels), np.array(groups),
                   np.array(os_tags), np.array(variants))


def make_synthetic_dataset(seed=0, n_attack_runs=8, n_benign_runs=8, ticks=30):
    """Small separable fake data (for tests and the benchmark). Not real behaviour."""
    rng = np.random.default_rng(seed)
    rows, labels, groups = [], [], []

    def benign_tick():
        return {"events_per_sec_1s": rng.exponential(3), "events_per_sec_5s": rng.exponential(2),
                "distinct_files_modified": rng.poisson(3), "distinct_dirs_touched": rng.poisson(1),
                "rename_count": rng.poisson(0.3), "extension_change_count": 0,
                "modify_ratio": rng.uniform(0, 0.6), "files_inspected": rng.poisson(1),
                "max_entropy": rng.uniform(3, 7.2), "mean_entropy": rng.uniform(3, 7),
                "fraction_high_entropy": rng.uniform(0, 0.3), "mean_chi_square": rng.uniform(2000, 10000),
                "max_null_fraction": rng.uniform(0, 0.1), "header_mismatch_count": rng.poisson(0.1)}

    def attack_tick():
        return {"events_per_sec_1s": 100 + rng.exponential(80), "events_per_sec_5s": 60 + rng.exponential(40),
                "distinct_files_modified": 40 + rng.poisson(30), "distinct_dirs_touched": rng.integers(1, 3),
                "rename_count": rng.poisson(20), "extension_change_count": rng.poisson(15),
                "modify_ratio": rng.uniform(0.3, 0.6), "files_inspected": 20 + rng.poisson(20),
                "max_entropy": rng.uniform(7.6, 8.0), "mean_entropy": rng.uniform(7.2, 8.0),
                "fraction_high_entropy": rng.uniform(0.7, 1.0), "mean_chi_square": rng.uniform(200, 400),
                "max_null_fraction": rng.uniform(0, 0.02), "header_mismatch_count": rng.poisson(10),
                "entropy_jump_count": rng.poisson(5)}

    for run in range(n_attack_runs + n_benign_runs):
        is_attack_run = run < n_attack_runs
        for tick in range(ticks):
            attacking = is_attack_run and 10 <= tick < 20
            values = attack_tick() if attacking else benign_tick()
            rows.append([float(values.get(name, 0.0)) for name in FEATURE_NAMES])
            labels.append(1 if attacking else 0)
            groups.append("synthetic_run_%02d" % run)
    n = len(rows)
    return Dataset(np.array(rows), np.array(labels), np.array(groups),
                   np.array(["synthetic"] * n), np.array(["synthetic"] * n))


def split_by_run(y, groups, seed=42, test_size=0.3):
    """Group-aware split. Attack runs and benign runs are split separately so both sets get both kinds."""
    attack_runs = set(groups[y == 1])
    is_attack_run = np.array([g in attack_runs for g in groups])
    train_idx, test_idx = [], []
    for mask in (is_attack_run, ~is_attack_run):
        idx = np.where(mask)[0]
        if len(set(groups[idx])) < 2:
            raise ValueError("need at least 2 attack runs and 2 benign runs: collect more runs")
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        train_part, test_part = next(splitter.split(idx, groups=groups[idx]))
        train_idx.extend(idx[train_part])
        test_idx.extend(idx[test_part])
    return np.array(sorted(train_idx)), np.array(sorted(test_idx))


def make_model(n_estimators, max_depth, seed):
    return RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth,
                                  class_weight="balanced", random_state=seed, n_jobs=1)


def positive_proba(model, X):
    classes = list(model.classes_)
    if 1 not in classes:
        return np.zeros(len(X))
    return model.predict_proba(X)[:, classes.index(1)]


def oof_probabilities(X, y, groups, n_estimators, max_depth, seed, n_splits=5):
    """Out-of-fold probabilities (GroupKFold: runs never straddle folds)."""
    proba = np.zeros(len(y))
    splits = min(n_splits, len(set(groups)))
    for train_part, valid_part in GroupKFold(n_splits=splits).split(X, y, groups):
        model = make_model(n_estimators, max_depth, seed)
        model.fit(X[train_part], y[train_part])
        proba[valid_part] = positive_proba(model, X[valid_part])
    return proba


def evaluate(y_true, proba, threshold):
    predicted = proba >= threshold
    tp = int((predicted & (y_true == 1)).sum())
    fp = int((predicted & (y_true == 0)).sum())
    tn = int((~predicted & (y_true == 0)).sum())
    fn = int((~predicted & (y_true == 1)).sum())
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0}


def tune_threshold(y_true, proba, max_fpr):
    """Lowest threshold whose false-positive rate is <= max_fpr (so recall is as high as possible)."""
    candidates = np.unique(np.concatenate([proba, [0.0, np.nextafter(1.0, 2.0)]]))   # ascending
    for threshold in candidates:
        if evaluate(y_true, proba, threshold)["fpr"] <= max_fpr:
            return float(threshold)
    return float(candidates[-1])


def select_model(X, y, groups, n_estimators_list=(10, 25, 50), depth_list=(4, 6, 8),
                 max_fpr=0.01, target_recall=0.90, seed=42):
    """Sweep sizes (smallest first). Returns (chosen, all_results, target_met)."""
    results = []
    for n_estimators in n_estimators_list:
        for max_depth in depth_list:
            proba = oof_probabilities(X, y, groups, n_estimators, max_depth, seed)
            threshold = tune_threshold(y, proba, max_fpr)
            ev = evaluate(y, proba, threshold)
            results.append({"n_estimators": n_estimators, "max_depth": max_depth,
                            "threshold": threshold, "oof_recall": ev["recall"], "oof_fpr": ev["fpr"]})
    meeting = [r for r in results if r["oof_recall"] >= target_recall]
    chosen = meeting[0] if meeting else max(results, key=lambda r: r["oof_recall"])
    return chosen, results, bool(meeting)


def dataset_sizes(data):
    sizes = {}
    for tag in sorted(set(data.os_tags)):
        mask = data.os_tags == tag
        sizes[tag] = {"rows": int(mask.sum()), "runs": len(set(data.groups[mask])),
                      "positive_rows": int(data.y[mask].sum())}
    return sizes


def print_eval(title, ev, fpr_active=None):
    print("\n%s" % title)
    print("              pred 0   pred 1")
    print("  actual 0  %7d  %7d   (TN, FP)" % (ev["tn"], ev["fp"]))
    print("  actual 1  %7d  %7d   (FN, TP)" % (ev["fn"], ev["tp"]))
    print("  precision %.3f   recall %.3f   FPR %.4f" % (ev["precision"], ev["recall"], ev["fpr"]))
    if fpr_active is not None:
        print("  FPR on ACTIVE negatives (rows with any non-zero feature): %.4f" % fpr_active)


def parse_args():
    parser = argparse.ArgumentParser(description="Train the ransomware RandomForest")
    parser.add_argument("--csv", nargs="+", required=True)
    parser.add_argument("--out-dir", default=str(PROJECT_ROOT / "models"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--target-recall", type=float, default=0.90)
    parser.add_argument("--refit-all", action="store_true",
                        help="export a model refit on ALL runs (reported metrics then belong to the train-only model)")
    return parser.parse_args()


def main():
    args = parse_args()
    data = load_datasets(args.csv)
    sizes = dataset_sizes(data)
    print("rows per os:", sizes)
    constant = [FEATURE_NAMES[i] for i in np.where(data.X.std(axis=0) == 0)[0]]
    if constant:
        print("constant columns (kept in place; the forest never splits on them):", constant)

    train_idx, test_idx = split_by_run(data.y, data.groups, args.seed, args.test_size)
    X_train, y_train, g_train = data.X[train_idx], data.y[train_idx], data.groups[train_idx]
    X_test, y_test = data.X[test_idx], data.y[test_idx]
    print("train: %d rows / %d runs   test: %d rows / %d runs" % (
        len(train_idx), len(set(g_train)), len(test_idx), len(set(data.groups[test_idx]))))

    chosen, results, met = select_model(X_train, y_train, g_train, max_fpr=args.max_fpr,
                                        target_recall=args.target_recall, seed=args.seed)
    print("\nsweep (out-of-fold on train runs, FPR <= %.2f%%):" % (args.max_fpr * 100))
    for r in results:
        print("  n_estimators=%-3d max_depth=%d  threshold=%.3f  recall=%.3f  fpr=%.4f" % (
            r["n_estimators"], r["max_depth"], r["threshold"], r["oof_recall"], r["oof_fpr"]))
    print("chosen: %s  (target recall >= %.2f %s)" % (
        {k: chosen[k] for k in ("n_estimators", "max_depth", "threshold")}, args.target_recall,
        "MET" if met else "NOT MET: showing the best available"))

    model = make_model(chosen["n_estimators"], chosen["max_depth"], args.seed).fit(X_train, y_train)
    threshold = chosen["threshold"]
    proba = positive_proba(model, X_test)
    ev = evaluate(y_test, proba, threshold)
    active = (X_test != 0).any(axis=1)
    negatives_active = (y_test == 0) & active
    predicted = proba >= threshold
    fpr_active = float((predicted & negatives_active).sum() / max(1, negatives_active.sum()))
    print_eval("TEST (unseen runs), threshold %.3f" % threshold, ev, fpr_active)

    variants_test = data.variants[test_idx]
    print("\nrecall per variant (test positives):")
    for variant in sorted(set(variants_test[y_test == 1])):
        if variant:
            mask = (variants_test == variant) & (y_test == 1)
            print("  %-22s %.3f  (%d ticks)" % (variant, predicted[mask].mean(), int(mask.sum())))

    print("\nfeature importances:")
    for importance, name in sorted(zip(model.feature_importances_, FEATURE_NAMES), reverse=True):
        print("  %-26s %.4f" % (name, importance))

    # Ablation: velocity-only (Stage 3 event features) vs the full set.
    columns = [FEATURE_NAMES.index(name) for name in VELOCITY_ONLY]
    oof_v = oof_probabilities(X_train[:, columns], y_train, g_train, chosen["n_estimators"],
                              chosen["max_depth"], args.seed)
    threshold_v = tune_threshold(y_train, oof_v, args.max_fpr)
    model_v = make_model(chosen["n_estimators"], chosen["max_depth"], args.seed)
    model_v.fit(X_train[:, columns], y_train)
    ev_v = evaluate(y_test, positive_proba(model_v, X_test[:, columns]), threshold_v)
    print("\nABLATION (test): velocity-only  recall %.3f  FPR %.4f   |   full  recall %.3f  FPR %.4f" % (
        ev_v["recall"], ev_v["fpr"], ev["recall"], ev["fpr"]))

    final_model = model
    if args.refit_all:
        final_model = make_model(chosen["n_estimators"], chosen["max_depth"], args.seed).fit(data.X, data.y)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, out_dir / "rf.joblib", compress=3)
    meta = {
        "model_file": "rf.joblib",
        "feature_names": list(FEATURE_NAMES),
        "schema_version": SCHEMA_VERSION,
        "schema_fingerprint": schema_fingerprint(),
        "versions": {"python": platform.python_version(), "numpy": np.__version__,
                     "scikit_learn": sklearn.__version__, "joblib": joblib.__version__},
        "threshold": float(threshold),
        "n_estimators": chosen["n_estimators"], "max_depth": chosen["max_depth"],
        "targets": {"max_fpr": args.max_fpr, "target_recall": args.target_recall, "met": met},
        "metrics": {key: (float(v) if isinstance(v, float) else v) for key, v in ev.items()},
        "fpr_active_negatives": fpr_active,
        "ablation_velocity_only": {"recall": ev_v["recall"], "fpr": ev_v["fpr"]},
        "metrics_apply_to_deployed_model": not args.refit_all,
        "constant_columns": constant,
        "label_rule": LABEL_RULE,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_sizes": sizes,
        "train_rows": int(len(train_idx)), "test_rows": int(len(test_idx)),
    }
    with open(out_dir / "rf_meta.json", "w") as handle:
        json.dump(meta, handle, indent=2)
    print("\nwrote %s and %s" % (out_dir / "rf.joblib", out_dir / "rf_meta.json"))


if __name__ == "__main__":
    main()