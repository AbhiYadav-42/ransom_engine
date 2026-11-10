"""Tests for the shared feature contract."""

import pytest

from engine.features_schema import (
    FEATURE_NAMES,
    SCHEMA_VERSION,
    FeatureSchemaError,
    schema_fingerprint,
    to_vector,
)


def test_feature_names_are_in_the_agreed_order():
    # GOLDEN TEST. If this fails you changed the column order or names.
    # Do NOT just edit the test: bump SCHEMA_VERSION, tell your partner, retrain.
    assert FEATURE_NAMES == (
        "events_per_sec_1s",
        "events_per_sec_5s",
        "distinct_files_modified",
        "distinct_dirs_touched",
        "rename_count",
        "extension_change_count",
        "modify_ratio",
        "canary_touched",
        "backup_kill_cmd",
    )


def test_feature_names_have_no_duplicates():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_schema_version_is_a_non_empty_string():
    assert isinstance(SCHEMA_VERSION, str) and SCHEMA_VERSION != ""


def test_to_vector_returns_floats_in_schema_order():
    # Build the dict in REVERSE order to prove the output order comes from the schema.
    values = {name: float(index) for index, name in enumerate(FEATURE_NAMES)}
    reversed_dict = dict(reversed(list(values.items())))
    vector = to_vector(reversed_dict)
    assert vector == [float(i) for i in range(len(FEATURE_NAMES))]
    assert all(isinstance(v, float) for v in vector)


def test_to_vector_missing_name_raises():
    values = {name: 0 for name in FEATURE_NAMES}
    del values["rename_count"]
    with pytest.raises(FeatureSchemaError) as error:
        to_vector(values)
    assert "rename_count" in str(error.value)


def test_to_vector_unknown_name_raises():
    values = {name: 0 for name in FEATURE_NAMES}
    values["surprise_feature"] = 1
    with pytest.raises(FeatureSchemaError) as error:
        to_vector(values)
    assert "surprise_feature" in str(error.value)


def test_to_vector_rejects_nan_and_infinity():
    for bad in (float("nan"), float("inf")):
        values = {name: 0 for name in FEATURE_NAMES}
        values["modify_ratio"] = bad
        with pytest.raises(FeatureSchemaError):
            to_vector(values)


def test_to_vector_rejects_non_numbers():
    for bad in ("abc", None):
        values = {name: 0 for name in FEATURE_NAMES}
        values["rename_count"] = bad
        with pytest.raises(FeatureSchemaError):
            to_vector(values)


def test_fingerprint_is_short_stable_and_order_sensitive():
    first = schema_fingerprint()
    assert first == schema_fingerprint()
    assert len(first) == 8
    swapped = (FEATURE_NAMES[1], FEATURE_NAMES[0]) + FEATURE_NAMES[2:]
    assert schema_fingerprint(swapped) != first