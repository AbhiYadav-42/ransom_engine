"""sim/gen_benign.py -- harmless NORMAL-behaviour generator. Sandbox only.
Needs a '.ransom_sandbox' marker file in --sandbox; works only inside its own sub-folder.
    python sim/gen_benign.py --sandbox PATH --variant edit_text|copy_folder|zip_create|zip_extract|
                             bulk_copy|large_write|rename_few|idle|mixed|encrypted_archive|
                             photo_import|backup_rsync|random --seed 1"""

import argparse
import os
import random
import shutil
import sys
import time
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sim.sandbox_common import (  # noqa: E402
    ensure_inside, fake_text, make_dummy_files, new_workdir, require_marker, safe_rename, safe_unlink)

VARIANTS = ["edit_text", "copy_folder", "zip_create", "zip_extract", "bulk_copy",
            "large_write", "rename_few", "idle", "mixed",
            "encrypted_archive", "photo_import", "backup_rsync"]


def edit_text(workdir, docs, rng):
    texts = [p for p in docs if p.suffix in (".txt", ".csv")]
    for _ in range(rng.randint(10, 15) if texts else 0):
        target = rng.choice(texts)
        ensure_inside(workdir, target)
        with open(target, "ab") as handle:
            handle.write(b"\n" + fake_text(rng, rng.randint(100, 600)))
        time.sleep(rng.uniform(0.3, 1.0))


def copy_folder(workdir, docs, rng):
    destination = workdir / "docs_copy"
    ensure_inside(workdir, destination)
    shutil.copytree(workdir / "docs", destination)
    time.sleep(2.0)


def zip_create(workdir, docs, rng):          # hard negative: new high-entropy archives
    for number in range(rng.randint(3, 5)):
        archive_path = workdir / ("archive_%d.zip" % number)
        ensure_inside(workdir, archive_path)
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for member in rng.sample(docs, min(len(docs), rng.randint(8, 20))):
                archive.write(member, member.name)
        time.sleep(rng.uniform(0.5, 1.5))


def zip_extract(workdir, docs, rng):
    archive_path = workdir / "bundle.zip"
    ensure_inside(workdir, archive_path)
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for member in docs[:40]:
            archive.write(member, member.name)
    time.sleep(1.0)
    target = workdir / "extracted"
    ensure_inside(workdir, target)
    target.mkdir()
    with zipfile.ZipFile(archive_path) as archive:      # our own archive, safe to extract
        archive.extractall(target)
    time.sleep(2.0)


def bulk_copy(workdir, docs, rng):            # hard negative: a burst of new files
    destination = workdir / "bulk"
    ensure_inside(workdir, destination)
    destination.mkdir()
    for index in range(rng.randint(100, 250)):
        source = rng.choice(docs)
        shutil.copy2(source, destination / ("%d_%s" % (index, source.name)))
    time.sleep(2.0)


def large_write(workdir, docs, rng):          # hard negative: big sequential random-looking writes
    for number in range(2):
        path = workdir / ("big_%d.bin" % number)
        ensure_inside(workdir, path)
        with open(path, "wb") as handle:
            for _ in range(64):                          # 64 x 256 KB = 16 MB
                handle.write(os.urandom(256 * 1024))
                time.sleep(0.02)
        time.sleep(1.0)
        safe_unlink(workdir, path)


def rename_few(workdir, docs, rng):
    candidates = [p for p in docs if p.suffix == ".txt" and p.exists()]
    chosen = rng.sample(candidates, min(3, len(candidates)))
    for source in chosen[:2]:                            # same extension
        safe_rename(workdir, source, source.with_name("renamed_" + source.name))
        time.sleep(0.7)
    for source in chosen[2:]:                            # one extension change (.txt -> .bak)
        safe_rename(workdir, source, source.with_suffix(".bak"))
        time.sleep(0.7)


def idle(workdir, docs, rng):
    time.sleep(rng.uniform(5, 8))
    edit_text_once = [p for p in docs if p.suffix == ".txt"]
    if edit_text_once:
        with open(edit_text_once[0], "ab") as handle:
            handle.write(b"\nsmall note")
    time.sleep(rng.uniform(5, 8))


def mixed(workdir, docs, rng):
    edit_text(workdir, docs, rng)
    time.sleep(2.0)
    rename_few(workdir, docs, rng)
    copy_folder(workdir, docs, rng)
    time.sleep(3.0)


def encrypted_archive(workdir, docs, rng):     # hard negative: high entropy but legit
    for number in range(rng.randint(5, 10)):
        path = workdir / ("secret_backup_%d.gpg" % number)
        ensure_inside(workdir, path)
        path.write_bytes(b"Salted__" + os.urandom(rng.randint(100000, 500000)))
        time.sleep(rng.uniform(0.3, 1.0))


def photo_import(workdir, docs, rng):          # hard negative: burst of new .jpg files
    folder = workdir / "import"
    ensure_inside(workdir, folder)
    folder.mkdir()
    for number in range(rng.randint(80, 150)):
        path = folder / ("IMG_%04d.jpg" % number)
        ensure_inside(workdir, path)
        path.write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(rng.randint(20000, 60000)))
        time.sleep(0.02)
    time.sleep(2.0)


def backup_rsync(workdir, docs, rng):          # hard negative: copy, edit, rename old to .bak, copy new in
    backup = workdir / "backup"
    ensure_inside(workdir, backup)
    shutil.copytree(workdir / "docs", backup)
    time.sleep(1.5)
    changed = rng.sample(docs, min(len(docs), rng.randint(10, 20)))
    for source in changed:                              # edit the originals
        if source.suffix in (".txt", ".csv"):
            with open(source, "ab") as handle:
                handle.write(b"\n" + fake_text(rng, 200))
    for source in changed:                              # sync: old copy -> .bak, new copy in
        dest = backup / source.name
        safe_rename(workdir, dest, dest.with_name(dest.name + ".bak"))
        ensure_inside(workdir, dest)
        shutil.copy2(source, dest)
        time.sleep(rng.uniform(0.05, 0.2))
    time.sleep(1.0)


FUNCTIONS = {"edit_text": edit_text, "copy_folder": copy_folder, "zip_create": zip_create,
             "zip_extract": zip_extract, "bulk_copy": bulk_copy, "large_write": large_write,
             "rename_few": rename_few, "idle": idle, "mixed": mixed,
             "encrypted_archive": encrypted_archive, "photo_import": photo_import,
             "backup_rsync": backup_rsync}


def run(workdir, variant, rng):
    docs_dir = workdir / "docs"
    docs_dir.mkdir()
    docs = make_dummy_files(docs_dir, rng.randint(30, 80), rng)
    time.sleep(2.0)                                      # quiet period after setup
    FUNCTIONS[variant](workdir, docs, rng)
    time.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(description="Harmless benign-activity generator")
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--variant", default="random", choices=VARIANTS + ["random"])
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    sandbox = require_marker(args.sandbox)
    rng = random.Random(args.seed)
    variant = rng.choice(VARIANTS) if args.variant == "random" else args.variant
    workdir = new_workdir(sandbox, "benign")
    print("variant=%s workdir=%s" % (variant, workdir), flush=True)
    run(workdir, variant, rng)
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())