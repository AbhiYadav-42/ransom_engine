"""ml/benchmark_latency.py -- time 1000 single-row predictions per forest size.

    python ml/benchmark_latency.py [--csv data/features_linux.csv] [--depth 8] [--target-ms 0.5]
Compares plain sklearn predict_proba with the plain-Python FastForest used by engine/model.py.
"""

import argparse
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.model import DEFAULT_META_PATH, DEFAULT_MODEL_PATH, FastForest, ModelError, Predictor  # noqa: E402
from ml.train import load_datasets, make_synthetic_dataset  # noqa: E402


def time_calls(func, vectors):
    """Returns (mean_ms, p99_ms) over the vectors, after a short warm-up."""
    for vector in vectors[:20]:
        func(vector)
    times = []
    for vector in vectors:
        start = time.perf_counter()
        func(vector)
        times.append((time.perf_counter() - start) * 1000.0)
    return float(np.mean(times)), float(np.percentile(times, 99))


def verdict(mean_ms, p99_ms, target):
    if p99_ms <= target:
        return "OK"
    return "mean ok, p99 over" if mean_ms <= target else "MISS"


def main():
    parser = argparse.ArgumentParser(description="Prediction latency benchmark")
    parser.add_argument("--csv", nargs="*", default=[])
    parser.add_argument("--sizes", type=int, nargs="+", default=[10, 25, 50])
    parser.add_argument("--depth", type=int, default=8)
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--target-ms", type=float, default=0.5)
    args = parser.parse_args()

    data = load_datasets(args.csv) if args.csv else make_synthetic_dataset(0)
    print("data: %s (%d rows)\n" % ("your CSVs" if args.csv else "synthetic", len(data.y)))
    rng = np.random.default_rng(0)
    vectors = data.X[rng.integers(0, len(data.X), args.runs)]

    print("%-6s %-6s %-9s %9s %9s   vs %.2f ms" % ("trees", "depth", "path", "mean_ms", "p99_ms", args.target_ms))
    sklearn_missed = []
    for size in args.sizes:
        model = RandomForestClassifier(n_estimators=size, max_depth=args.depth, class_weight="balanced",
                                       random_state=0, n_jobs=1).fit(data.X, data.y)
        positive_index = list(model.classes_).index(1)
        fast = FastForest(model, positive_index)

        def sklearn_call(vector):
            model.predict_proba(vector.reshape(1, -1))

        def fast_call(vector):
            fast.predict_proba_positive(vector.astype(np.float32).tolist())

        for label, func in (("sklearn", sklearn_call), ("fast", fast_call)):
            mean_ms, p99_ms = time_calls(func, vectors)
            print("%-6d %-6d %-9s %9.4f %9.4f   %s" % (size, args.depth, label, mean_ms, p99_ms,
                                                       verdict(mean_ms, p99_ms, args.target_ms)))
            if label == "sklearn" and mean_ms > args.target_ms:
                sklearn_missed.append(size)

    try:                                                  # the real exported model, if there is one
        predictor = Predictor(DEFAULT_MODEL_PATH, DEFAULT_META_PATH)
        mean_ms, p99_ms = time_calls(predictor.predict, [list(v) for v in vectors])
        print("\nexported model via Predictor.predict (fast path: %s): mean %.4f ms, p99 %.4f ms  %s" % (
            predictor.using_fast_path, mean_ms, p99_ms, verdict(mean_ms, p99_ms, args.target_ms)))
    except ModelError as error:
        print("\n(no usable exported model to benchmark: %s)" % error)

    if sklearn_missed:
        print("\nHONEST NOTE: plain sklearn predict_proba MISSES the %.2f ms target for sizes %s: its "
              "per-call overhead dominates, not the trees. The Predictor therefore uses the "
              "plain-Python FastForest walk when it matches sklearn." % (args.target_ms, sklearn_missed))


if __name__ == "__main__":
    main()