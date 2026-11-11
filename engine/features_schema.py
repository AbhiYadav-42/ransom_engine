"""
engine/features_schema.py -- the ONE shared contract for feature columns.

The trained Random Forest trusts COLUMN POSITION, not column names. If the
order or meaning of FEATURE_NAMES changes, an old model silently reads the
wrong numbers. So:
    * Nobody reorders / renames / inserts into FEATURE_NAMES without telling
      the other partner.
    * New features go at the END, and SCHEMA_VERSION changes.
    * Both Windows and Linux import this file, so they cannot disagree.

Version history
    1.0  9 columns (Stage 3: velocity / rename features + 2 placeholders).
    1.1  +8 columns at the END (Stage 4: binary inspection features).
         The first 9 columns are unchanged: same positions, same meaning.
         A model trained on 1.0 cannot read 1.1 rows (17 values instead of 9)
         unless you slice the first 9; a model trained on 1.1 needs 1.1 rows.
"""

import hashlib
import math

SCHEMA_VERSION = "1.1"

FEATURE_NAMES = (
    "events_per_sec_1s",
    "events_per_sec_5s",
    "distinct_files_modified",
    "distinct_dirs_touched",
    "rename_count",
    "extension_change_count",
    "modify_ratio",
    "canary_touched",     # placeholder: always 0 until a later stage fills it
    "backup_kill_cmd",    # placeholder: always 0 until a later stage fills it
    # --- added in schema 1.1 (Stage 4), 5-second window over inspected files ---
    "files_inspected",
    "max_entropy",
    "mean_entropy",
    "fraction_high_entropy",
    "mean_chi_square",
    "max_null_fraction",
    "header_mismatch_count",
    "entropy_jump_count",
)


class FeatureSchemaError(ValueError):
    """Raised when feature data does not match the schema."""


def to_vector(feature_dict):
    """Turn {name: number} into a list of floats in EXACTLY FEATURE_NAMES order.
    Raises FeatureSchemaError for missing names, unknown names, or bad numbers."""
    missing = [name for name in FEATURE_NAMES if name not in feature_dict]
    unknown = [name for name in feature_dict if name not in FEATURE_NAMES]
    if missing or unknown:
        raise FeatureSchemaError(
            "Feature dict does not match schema version %s. Missing: %s. Unknown: %s."
            % (SCHEMA_VERSION, missing, unknown))

    vector = []
    for name in FEATURE_NAMES:
        raw = feature_dict[name]
        if isinstance(raw, (str, bytes)):
            raise FeatureSchemaError("Feature %r must be a number, got %r" % (name, raw))
        try:
            value = float(raw)
        except (TypeError, ValueError):
            raise FeatureSchemaError("Feature %r must be a number, got %r" % (name, raw))
        if not math.isfinite(value):
            raise FeatureSchemaError("Feature %r is not finite: %r" % (name, raw))
        vector.append(value)
    return vector


def schema_fingerprint(names=FEATURE_NAMES):
    """Short code that changes if names are added, removed, renamed or reordered.
    Both partners can print it and compare."""
    text = ",".join(names)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]