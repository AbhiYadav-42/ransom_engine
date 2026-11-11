"""
engine/inspector.py -- Stage 4: the binary inspection engine.

WHAT THIS FILE DOES
    Opens a file in binary mode, reads a SAMPLE (the first 64 KB), and measures
    how random or tampered the bytes look. The math functions are pure: bytes in,
    numbers out, no file access.

WHAT IT DELIBERATELY DOES NOT DO
    No watching folders, no killing processes, no alerts, no ML.

HONEST LIMITATIONS (also in the README)
    1. Entropy and chi-square both look "near random" for zip, jpg, png, docx,
       pdf streams AND for encrypted data. Alone they CANNOT tell compressed from
       encrypted. What reduces false positives is the header/extension check plus
       fusion with the velocity features (Stage 3) inside the ML stage.
    2. Entropy (and chi-square) on tiny files is unreliable. Below about 1 KB the
       statistics are too noisy, so we report status "too_small" and no numbers.
       (Chi-square rules of thumb want an expected count >= 5 per byte value, i.e.
       about 1.3 KB; 1 KB is a compromise.)
    3. We read only the first sample_bytes. Tampering later in a big file is missed.
    4. A locked or deleted-mid-scan file gives no measurement at all.
"""

import os
import time
from collections import OrderedDict
from dataclasses import dataclass

import numpy as np

from engine.aggregator_windows import split_for_counting
from engine.inspector_windows import open_binary_with_retry

DEFAULT_SAMPLE_BYTES = 65536
DEFAULT_MIN_BYTES = 1024
DEFAULT_BLOCK_SIZE = 4096
DEFAULT_MAX_CACHE_ENTRIES = 5000


# ---------------------------------------------------------------------------
# 1. Pure math: bytes in, numbers out
# ---------------------------------------------------------------------------
def _byte_counts(data):
    """How many times each of the 256 possible byte values appears (length-256 array)."""
    values = np.frombuffer(data, dtype=np.uint8)
    return np.bincount(values, minlength=256)


def shannon_entropy(data):
    """H = -sum(p * log2(p)) over byte values with p > 0.
    0.0 = every byte identical, 8.0 = perfectly uniform bytes. Empty data -> 0.0."""
    if not data:
        return 0.0
    counts = _byte_counts(data)
    probabilities = counts[counts > 0] / len(data)     # only values that occur (p > 0)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return max(0.0, float(entropy))                    # max() turns -0.0 into 0.0


def chi_square(data):
    """chi2 = sum((observed - E)^2 / E) over all 256 byte values, E = n / 256.
    255 degrees of freedom, so truly random data gives about 255 (give or take ~23).
    Far above that = not uniform (text, zeros). Empty data -> 0.0."""
    if not data:
        return 0.0
    counts = _byte_counts(data)
    expected = len(data) / 256.0
    return float(np.sum((counts - expected) ** 2 / expected))


def null_fraction(data):
    """Share of 0x00 bytes (zero padding / wiped content). Empty data -> 0.0."""
    if not data:
        return 0.0
    return float(_byte_counts(data)[0] / len(data))


def block_entropy_stats(data, block_size=DEFAULT_BLOCK_SIZE):
    """(max, min, standard deviation) of the entropy of each block.
    Exposes files that mix a random block with zero padding: one overall number
    would hide it. Only FULL blocks are used (a short tail has low entropy just
    because it is short). Data shorter than one block counts as a single block."""
    if not data:
        return (0.0, 0.0, 0.0)
    if len(data) < block_size:
        blocks = [data]
    else:
        full_blocks = len(data) // block_size
        blocks = [data[i * block_size:(i + 1) * block_size] for i in range(full_blocks)]
    entropies = [shannon_entropy(block) for block in blocks]
    return (max(entropies), min(entropies), float(np.std(entropies)))


# ---------------------------------------------------------------------------
# 2. Magic header check
# ---------------------------------------------------------------------------
# (signature bytes, extensions that normally go with it)
KNOWN_SIGNATURES = (
    (b"PK\x03\x04", (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".jar", ".apk")),
    (b"%PDF", (".pdf",)),
    (b"\xff\xd8\xff", (".jpg", ".jpeg")),
    (b"\x89PNG", (".png",)),
    (b"\xd0\xcf\x11\xe0", (".doc", ".xls", ".ppt")),
    (b"GIF8", (".gif",)),
    (b"\x1f\x8b", (".gz",)),
)
KNOWN_EXTENSIONS = set()
for _signature, _extensions in KNOWN_SIGNATURES:
    KNOWN_EXTENSIONS.update(_extensions)


def _normalize_extension(extension):
    extension = extension.lower()
    if extension and not extension.startswith("."):
        extension = "." + extension
    return extension


def magic_header_info(data, extension):
    """Returns {"has_known_header": 0/1, "ext_matches_header": 0/1}.

    ext_matches_header is 0 ONLY when there is evidence of a mismatch:
      * known header, but the extension is not one of that format's extensions
        (this includes unknown ones like ".locked" or no extension at all), or
      * the extension is a known typed one (.pdf, .docx ...) but the header is missing.
    Unknown extension (.txt, .csv, ...) and no known header -> 1 (neutral):
    plain text has no magic bytes, so we cannot judge it here."""
    extension = _normalize_extension(extension)
    allowed = None
    for signature, extensions in KNOWN_SIGNATURES:
        if data.startswith(signature):
            allowed = extensions
            break

    has_known_header = 1 if allowed is not None else 0
    if allowed is not None:
        ext_matches = 1 if extension in allowed else 0
    elif extension in KNOWN_EXTENSIONS:
        ext_matches = 0          # claims to be a typed file, but the header is gone
    else:
        ext_matches = 1          # no evidence either way
    return {"has_known_header": has_known_header, "ext_matches_header": ext_matches}


# ---------------------------------------------------------------------------
# 3. read_sample: never raises, always returns a clear status
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SampleResult:
    status: str            # ok / too_small / locked / missing / not_a_file / error
    data: bytes = b""
    detail: str = ""


def read_sample(path, max_bytes=DEFAULT_SAMPLE_BYTES, min_bytes=DEFAULT_MIN_BYTES):
    """Read at most max_bytes from the START of the file. Never raises.
    (read(n) returns fewer than n bytes only at the end of a regular file, so
    getting fewer than min_bytes means the file itself is smaller than that.)"""
    try:
        if os.path.isdir(path):           # checked first: opening a folder on Windows
            return SampleResult("not_a_file", b"", "path is a directory")   # says PermissionError
        with open_binary_with_retry(path) as handle:
            data = handle.read(max_bytes)
    except FileNotFoundError:
        return SampleResult("missing", b"", "file not found (deleted?)")
    except PermissionError as error:      # Windows: file in use. Linux: no permission.
        return SampleResult("locked", b"", "permission denied or file in use: %r" % (error,))
    except IsADirectoryError:
        return SampleResult("not_a_file", b"", "path is a directory")
    except OSError as error:
        return SampleResult("error", b"", "OS error: %r" % (error,))
    except Exception as error:            # last safety net: the caller must never see an exception
        return SampleResult("error", b"", "unexpected error: %r" % (error,))

    if len(data) < min_bytes:
        return SampleResult("too_small", b"", "only %d bytes (minimum %d)" % (len(data), min_bytes))
    return SampleResult("ok", data, "")


# ---------------------------------------------------------------------------
# 4. FileInspection: everything we know about one file
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FileInspection:
    path: str
    status: str                       # ok / too_small / locked / missing / not_a_file / error
    timestamp: float = 0.0            # time.monotonic() when the inspection finished
    bytes_sampled: int = 0
    entropy: float = 0.0
    chi_square: float = 0.0
    null_fraction: float = 0.0
    block_entropy_max: float = 0.0
    block_entropy_min: float = 0.0
    block_entropy_std: float = 0.0
    has_known_header: int = 0
    ext_matches_header: int = 1       # 1 = no evidence of mismatch (also the value for failed reads)
    entropy_delta: float = 0.0        # entropy now MINUS entropy last time (0.0 if no last time)
    had_previous_entropy: bool = False
    detail: str = ""


# ---------------------------------------------------------------------------
# 5. Inspector: measures files, remembers the last entropy per path
# ---------------------------------------------------------------------------
class Inspector:
    """Use from ONE thread (the worker), so the cache needs no lock.

    CACHE BOUND: an OrderedDict path -> last entropy, limited to max_cache_entries
    (default 5000, well under 1 MB). When it is full, the LEAST RECENTLY USED path is
    evicted. Effect of eviction: that file's next inspection has no "before" value, so a
    jump can be MISSED (it can never be invented)."""

    def __init__(self, sample_bytes=DEFAULT_SAMPLE_BYTES, min_bytes=DEFAULT_MIN_BYTES,
                 block_size=DEFAULT_BLOCK_SIZE, max_cache_entries=DEFAULT_MAX_CACHE_ENTRIES,
                 windows_style=None, clock=time.monotonic, reader=read_sample):
        if max_cache_entries < 1:
            raise ValueError("max_cache_entries must be at least 1")
        if block_size < 1:
            raise ValueError("block_size must be at least 1")
        if min_bytes > sample_bytes:
            raise ValueError("min_bytes cannot be larger than sample_bytes")
        self._sample_bytes = sample_bytes
        self._min_bytes = min_bytes
        self._block_size = block_size
        self._max_cache_entries = max_cache_entries
        self._windows_style = windows_style
        self._clock = clock
        self._reader = reader
        self._cache = OrderedDict()

    def inspect(self, path):
        """Read and measure one file. Never raises: failures become a status."""
        try:
            sample = self._reader(path, self._sample_bytes, self._min_bytes)
            if sample.status != "ok":
                return FileInspection(path=path, status=sample.status,
                                      timestamp=self._clock(), detail=sample.detail)
            return self.inspect_bytes(path, sample.data)
        except Exception as error:
            return FileInspection(path=path, status="error",
                                  timestamp=self._clock(), detail=repr(error))

    def inspect_bytes(self, path, data, timestamp=None):
        """Measure bytes you already have (no file access). Updates the entropy cache."""
        if timestamp is None:
            timestamp = self._clock()
        entropy = shannon_entropy(data)
        block_max, block_min, block_std = block_entropy_stats(data, self._block_size)
        header = magic_header_info(data, os.path.splitext(path)[1])
        previous = self._remember(path, entropy)
        had_previous = previous is not None
        return FileInspection(
            path=path, status="ok", timestamp=timestamp, bytes_sampled=len(data),
            entropy=entropy, chi_square=chi_square(data), null_fraction=null_fraction(data),
            block_entropy_max=block_max, block_entropy_min=block_min, block_entropy_std=block_std,
            has_known_header=header["has_known_header"],
            ext_matches_header=header["ext_matches_header"],
            entropy_delta=(entropy - previous) if had_previous else 0.0,
            had_previous_entropy=had_previous)

    def forget(self, path):
        """Call when a file is deleted: its history must not leak into a new file of that name."""
        key, _parent = split_for_counting(path, self._windows_style)
        self._cache.pop(key, None)

    def move(self, src_path, dest_path):
        """Call when a file is renamed: its entropy history follows it."""
        src_key, _ = split_for_counting(src_path, self._windows_style)
        dest_key, _ = split_for_counting(dest_path, self._windows_style)
        if src_key in self._cache:
            self._cache[dest_key] = self._cache.pop(src_key)
            self._cache.move_to_end(dest_key)
            self._trim()

    def cache_size(self):
        return len(self._cache)

    def _remember(self, path, entropy):
        """Store the new entropy; return the previous one (or None)."""
        key, _parent = split_for_counting(path, self._windows_style)
        previous = self._cache.get(key)
        self._cache[key] = entropy
        self._cache.move_to_end(key)      # most recently used goes to the end
        self._trim()
        return previous

    def _trim(self):
        while len(self._cache) > self._max_cache_entries:
            self._cache.popitem(last=False)    # evict the least recently used (the front)