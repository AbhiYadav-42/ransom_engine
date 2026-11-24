"""sim/sandbox_common.py -- safety helpers shared by both generators (sandbox only)."""

import os
import uuid
import zipfile
from pathlib import Path

MARKER_NAME = ".ransom_sandbox"

WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november "
         "oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee zulu report budget "
         "invoice meeting draft summary project schedule review minutes total").split()

EXTENSIONS = [".txt"] * 4 + [".csv"] * 2 + [".docx"] * 2 + [".pdf", ".jpg", ".zip"]


def require_marker(folder):
    """Refuse to run unless the folder holds the marker file. Returns the resolved folder."""
    folder = Path(folder).resolve()
    if folder == Path(folder.anchor) or folder == Path.home().resolve():
        raise SystemExit("REFUSING TO RUN: %s is a root or home folder." % folder)
    if not (folder / MARKER_NAME).is_file():
        raise SystemExit("REFUSING TO RUN: %s has no '%s' marker file. Create it yourself in a "
                         "folder that holds only dummy data." % (folder, MARKER_NAME))
    return folder


def new_workdir(sandbox, prefix):
    """Each run works ONLY inside its own fresh sub-folder."""
    workdir = Path(sandbox) / ("%s_%s" % (prefix, uuid.uuid4().hex[:8]))
    workdir.mkdir()
    return workdir.resolve()


def ensure_inside(workdir, *paths):
    """Raise if any path is the work folder itself, outside it, or a symlink."""
    root = Path(workdir).resolve()
    for path in paths:
        path = Path(path)
        if path.is_symlink() or root not in path.resolve().parents:
            raise RuntimeError("refusing to touch a path outside the work folder: %s" % path)


def safe_write(workdir, path, data):
    ensure_inside(workdir, path)
    Path(path).write_bytes(data)


def safe_rename(workdir, source, dest):
    ensure_inside(workdir, source, dest)
    Path(source).rename(dest)


def safe_unlink(workdir, path):
    ensure_inside(workdir, path)
    Path(path).unlink()


def fake_text(rng, size):
    """Readable-looking text (low entropy, about 4 bits per byte)."""
    pieces, total = [], 0
    while total < size:
        word = rng.choice(WORDS)
        pieces.append(word)
        total += len(word) + 1
    return " ".join(pieces).encode("ascii")[:size]


def write_dummy(path, extension, size, rng):
    """Dummy content whose header matches its extension, like real files."""
    if extension in (".txt", ".csv"):
        path.write_bytes(fake_text(rng, size))
    elif extension == ".docx":                    # a real zip container, like a real .docx
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", fake_text(rng, size))
    elif extension == ".pdf":
        path.write_bytes(b"%PDF-1.4\n" + fake_text(rng, size // 2) + os.urandom(size // 2))
    elif extension == ".jpg":                     # compressed-looking: high entropy but a valid header
        path.write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(size))
    else:                                         # .zip
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("data.bin", os.urandom(size))


def make_dummy_files(workdir, count, rng):
    """Create `count` dummy files (4-40 KB each) in workdir. Returns their paths."""
    files = []
    for index in range(count):
        extension = rng.choice(EXTENSIONS)
        path = Path(workdir) / ("file_%03d%s" % (index, extension))
        ensure_inside(workdir, path)
        write_dummy(path, extension, rng.randint(4000, 40000), rng)
        files.append(path)
    return files