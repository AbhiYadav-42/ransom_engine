"""Unit tests for Stage 4: math, magic headers, read_sample, Inspector and its cache."""

import os
from unittest import mock

import pytest

from engine.inspector import (
    FileInspection,
    Inspector,
    SampleResult,
    block_entropy_stats,
    chi_square,
    magic_header_info,
    null_fraction,
    read_sample,
    shannon_entropy,
)
from engine.inspector_windows import open_binary_with_retry


def fixed_clock():
    return 42.0


# ----- entropy --------------------------------------------------------------
def test_entropy_of_empty_data_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_entropy_of_zeros_is_zero():
    assert shannon_entropy(bytes(65536)) == 0.0


def test_entropy_of_two_equal_halves_is_one_bit():
    assert shannon_entropy(b"\x00" * 512 + b"\xff" * 512) == pytest.approx(1.0)


def test_entropy_of_uniform_cycle_is_eight():
    assert shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)


def test_entropy_of_random_bytes_is_close_to_eight():
    assert shannon_entropy(os.urandom(65536)) > 7.98


def test_entropy_of_repeated_english_is_in_the_middle():
    text = ("The quick brown fox jumps over the lazy dog. " * 200).encode("ascii")
    assert 3.0 < shannon_entropy(text) < 5.5


# ----- chi-square -----------------------------------------------------------
def test_chi_square_of_empty_data_is_zero():
    assert chi_square(b"") == 0.0


def test_chi_square_of_uniform_cycle_is_zero():
    assert chi_square(bytes(range(256)) * 16) == pytest.approx(0.0)


def test_chi_square_of_zeros_matches_the_formula():
    # n * (256 * sum(p^2) - 1) = 65536 * 255 for all-identical bytes
    assert chi_square(bytes(65536)) == pytest.approx(16711680.0)


def test_chi_square_of_random_bytes_is_roughly_255():
    assert 100.0 < chi_square(os.urandom(65536)) < 500.0     # generous: mean 255, spread ~23


# ----- null fraction --------------------------------------------------------
def test_null_fraction_values():
    assert null_fraction(b"") == 0.0
    assert null_fraction(bytes(100)) == 1.0
    assert null_fraction(b"\x00" * 50 + b"\x01" * 50) == pytest.approx(0.5)
    assert 0.002 < null_fraction(os.urandom(65536)) < 0.0065   # about 1/256


# ----- per-block entropy ----------------------------------------------------
def test_block_stats_random_plus_zero_file():
    data = os.urandom(32768) + bytes(32768)
    block_max, block_min, block_std = block_entropy_stats(data)
    assert block_max > 7.8
    assert block_min == pytest.approx(0.0)
    assert block_std > 3.0


def test_block_stats_uniform_blocks_have_no_spread():
    block_max, block_min, block_std = block_entropy_stats(bytes(range(256)) * 64)
    assert block_max == pytest.approx(8.0)
    assert block_min == pytest.approx(8.0)
    assert block_std == pytest.approx(0.0, abs=1e-9)


def test_block_stats_short_data_and_ignored_tail():
    assert block_entropy_stats(bytes(100)) == (0.0, 0.0, 0.0)       # one short block
    block_max, block_min, _ = block_entropy_stats(os.urandom(4096) + bytes(100))
    assert block_min > 7.8          # the 100-byte tail is ignored, only the full block counts
    assert block_max == pytest.approx(block_min)


def test_block_stats_empty_data():
    assert block_entropy_stats(b"") == (0.0, 0.0, 0.0)


# ----- magic headers --------------------------------------------------------
def test_magic_known_headers_match_their_extensions():
    cases = [
        (b"PK\x03\x04" + b"x" * 20, ".zip"),
        (b"PK\x03\x04" + b"x" * 20, ".docx"),
        (b"%PDF-1.7", ".pdf"),
        (b"\xff\xd8\xff\xe0", ".jpg"),
        (b"\xff\xd8\xff\xe0", ".jpeg"),
        (b"\x89PNG\r\n", ".png"),
        (b"\xd0\xcf\x11\xe0\xa1", ".doc"),
    ]
    for data, extension in cases:
        assert magic_header_info(data, extension) == {"has_known_header": 1, "ext_matches_header": 1}


def test_magic_header_with_wrong_or_odd_extension_is_a_mismatch():
    zip_bytes = b"PK\x03\x04" + b"x" * 20
    for extension in (".jpg", ".locked", ""):
        assert magic_header_info(zip_bytes, extension) == {"has_known_header": 1, "ext_matches_header": 0}


def test_magic_known_extension_without_header_is_a_mismatch():
    for extension in (".pdf", ".docx"):
        assert magic_header_info(os.urandom(100), extension) == {
            "has_known_header": 0, "ext_matches_header": 0}


def test_magic_unknown_extension_without_header_is_neutral():
    text = b"just some plain text"
    for extension in (".txt", "", ".locked"):
        assert magic_header_info(text, extension) == {"has_known_header": 0, "ext_matches_header": 1}


def test_magic_extension_is_case_insensitive_and_dot_optional():
    zip_bytes = b"PK\x03\x04" + b"x" * 20
    assert magic_header_info(zip_bytes, ".DOCX")["ext_matches_header"] == 1
    assert magic_header_info(zip_bytes, "docx")["ext_matches_header"] == 1


def test_magic_short_data_has_no_header():
    assert magic_header_info(b"PK", ".zip")["has_known_header"] == 0


# ----- read_sample ----------------------------------------------------------
def test_read_sample_reads_only_max_bytes(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(os.urandom(200000))
    result = read_sample(str(path), max_bytes=65536, min_bytes=1024)
    assert result.status == "ok"
    assert len(result.data) == 65536


def test_read_sample_small_file_is_too_small(tmp_path):
    path = tmp_path / "tiny.bin"
    path.write_bytes(os.urandom(100))
    assert read_sample(str(path)).status == "too_small"


def test_read_sample_minimum_size_boundary(tmp_path):
    exact = tmp_path / "exact.bin"
    exact.write_bytes(os.urandom(1024))
    short = tmp_path / "short.bin"
    short.write_bytes(os.urandom(1023))
    assert read_sample(str(exact), min_bytes=1024).status == "ok"
    assert read_sample(str(short), min_bytes=1024).status == "too_small"


def test_read_sample_missing_file(tmp_path):
    assert read_sample(str(tmp_path / "nope.bin")).status == "missing"


def test_read_sample_directory(tmp_path):
    assert read_sample(str(tmp_path)).status == "not_a_file"


def test_read_sample_locked_file_with_a_mock():
    with mock.patch("engine.inspector.open_binary_with_retry",
                    side_effect=PermissionError("locked")):
        result = read_sample("/sb/a.bin")
    assert result.status == "locked"
    assert result.data == b""


def test_read_sample_unexpected_error_never_raises():
    with mock.patch("engine.inspector.open_binary_with_retry",
                    side_effect=RuntimeError("boom")):
        result = read_sample("/sb/a.bin")
    assert result.status == "error"
    assert "boom" in result.detail


# ----- Windows retry helper (logic only; UNTESTED on real Windows) ---------
class FlakyOpener:
    def __init__(self, failures):
        self.failures = failures
        self.calls = 0

    def __call__(self, path, mode):
        self.calls += 1
        if self.calls <= self.failures:
            raise PermissionError("busy")
        return "FILE-HANDLE"


def test_retry_helper_retries_once_on_windows():
    opener = FlakyOpener(failures=1)
    sleeps = []
    result = open_binary_with_retry("x", opener=opener, is_windows=True,
                                    retry_delay=0.05, sleep=sleeps.append)
    assert result == "FILE-HANDLE"
    assert opener.calls == 2
    assert sleeps == [0.05]


def test_retry_helper_does_not_retry_elsewhere():
    opener = FlakyOpener(failures=5)
    with pytest.raises(PermissionError):
        open_binary_with_retry("x", opener=opener, is_windows=False, sleep=lambda s: None)
    assert opener.calls == 1


def test_retry_helper_second_failure_reaches_the_caller():
    opener = FlakyOpener(failures=5)
    with pytest.raises(PermissionError):
        open_binary_with_retry("x", opener=opener, is_windows=True, sleep=lambda s: None)
    assert opener.calls == 2


# ----- Inspector and its cache ---------------------------------------------
def test_inspect_bytes_fills_all_fields():
    inspector = Inspector(clock=fixed_clock, windows_style=False)
    result = inspector.inspect_bytes("/sb/a.bin", os.urandom(65536))
    assert result.status == "ok"
    assert result.timestamp == 42.0
    assert result.bytes_sampled == 65536
    assert result.entropy > 7.98
    assert 100.0 < result.chi_square < 500.0
    assert 0.002 < result.null_fraction < 0.0065
    assert result.block_entropy_min > 7.8
    assert result.has_known_header == 0
    assert result.ext_matches_header == 1          # ".bin" is unknown: neutral
    assert result.entropy_delta == 0.0
    assert result.had_previous_entropy is False


def test_entropy_delta_is_after_minus_before():
    inspector = Inspector(windows_style=False)
    text = ("hello world, this is plain text. " * 300).encode("ascii")
    first = inspector.inspect_bytes("/sb/doc.txt", text)
    second = inspector.inspect_bytes("/sb/doc.txt", os.urandom(65536))   # "encrypted" in place
    assert second.had_previous_entropy is True
    assert second.entropy_delta == pytest.approx(second.entropy - first.entropy)
    assert second.entropy_delta > 3.0


def test_cache_is_bounded_and_evicts_least_recently_used():
    inspector = Inspector(max_cache_entries=3, windows_style=False)
    data = os.urandom(2048)
    for name in ("a", "b", "c"):
        inspector.inspect_bytes("/sb/%s.bin" % name, data)
    assert inspector.cache_size() == 3
    assert inspector.inspect_bytes("/sb/a.bin", data).had_previous_entropy is True   # refreshes a
    inspector.inspect_bytes("/sb/d.bin", data)                                       # evicts b
    assert inspector.cache_size() == 3
    assert inspector.inspect_bytes("/sb/b.bin", data).had_previous_entropy is False  # b was evicted
    assert inspector.inspect_bytes("/sb/a.bin", data).had_previous_entropy is True   # a survived
    assert inspector.cache_size() == 3


def test_forget_and_move_manage_the_cache():
    inspector = Inspector(windows_style=False)
    text = ("hello world " * 200).encode("ascii")
    noise = os.urandom(4096)
    inspector.inspect_bytes("/sb/a.txt", text)
    inspector.move("/sb/a.txt", "/sb/a.txt.locked")
    moved = inspector.inspect_bytes("/sb/a.txt.locked", noise)
    assert moved.had_previous_entropy is True          # history followed the rename
    assert moved.entropy_delta > 3.0
    inspector.forget("/sb/a.txt.locked")
    assert inspector.cache_size() == 0
    assert inspector.inspect_bytes("/sb/a.txt.locked", noise).had_previous_entropy is False


def test_inspect_reports_reader_statuses_with_zero_numbers():
    def locked_reader(path, max_bytes, min_bytes):
        return SampleResult("locked", b"", "busy")

    inspector = Inspector(reader=locked_reader, clock=fixed_clock)
    result = inspector.inspect("/sb/a.bin")
    assert result.status == "locked"
    assert result.entropy == 0.0
    assert result.ext_matches_header == 1
    assert result.had_previous_entropy is False
    assert result.detail == "busy"


def test_inspect_never_raises_when_the_reader_explodes():
    def exploding_reader(path, max_bytes, min_bytes):
        raise RuntimeError("boom")

    result = Inspector(reader=exploding_reader).inspect("/sb/a.bin")
    assert result.status == "error"
    assert "boom" in result.detail


def test_inspect_a_real_file(tmp_path):
    path = tmp_path / "random.bin"
    path.write_bytes(os.urandom(65536))
    result = Inspector(windows_style=False).inspect(str(path))
    assert result.status == "ok"
    assert result.entropy > 7.98


def test_cache_keys_are_case_insensitive_for_windows_style():
    inspector = Inspector(windows_style=True)
    data = os.urandom(2048)
    inspector.inspect_bytes("C:/Sb/A.bin", data)
    assert inspector.inspect_bytes("c:\\sb\\a.BIN", data).had_previous_entropy is True


def test_inspector_rejects_bad_settings():
    with pytest.raises(ValueError):
        Inspector(max_cache_entries=0)
    with pytest.raises(ValueError):
        Inspector(sample_bytes=100, min_bytes=200)
    with pytest.raises(ValueError):
        Inspector(block_size=0)