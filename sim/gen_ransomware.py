"""sim/gen_ransomware.py -- HARMLESS ransomware SIMULATOR. Sandbox only.
It only overwrites / renames / deletes dummy files it created itself inside its own sub-folder.
No network, no real malware behaviour. Needs a '.ransom_sandbox' marker file in --sandbox.
    python sim/gen_ransomware.py --sandbox PATH --variant fast_urandom|fast_urandom_rename|fast_fernet|
        copy_encrypt_delete|slow_urandom|slow_fernet_rename|zero_padding|rename_only|with_decoy|
        partial_encrypt|threaded_random_order|ransom_note_drop|low_and_slow|random
It prints 'PHASE attack_start' / 'PHASE attack_end' so the collector can label ticks."""

import argparse
import os
import random
import subprocess
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sim.sandbox_common import (  # noqa: E402
    ensure_inside, make_dummy_files, new_workdir, require_marker, safe_rename, safe_unlink,
    safe_write)

DECOY = Path(__file__).resolve().parent / "decoy_vss.py"

# variant: (how to change content, rename to .locked?, pause per file in s, (min, max) files hit)
CONFIG = {
    "fast_urandom":        ("urandom", False, 0.0, (40, 120)),
    "fast_urandom_rename": ("urandom", True, 0.0, (40, 120)),
    "fast_fernet":         ("fernet", False, 0.0, (40, 120)),
    "copy_encrypt_delete": ("copy_delete", False, 0.0, (40, 100)),
    "slow_urandom":        ("urandom", False, 1.0, (12, 20)),
    "slow_fernet_rename":  ("fernet", True, 1.0, (12, 20)),
    "zero_padding":        ("zero_pad", False, 0.01, (40, 100)),
    "rename_only":         ("none", True, 0.0, (40, 120)),
    "with_decoy":          ("urandom", False, 0.0, (40, 120)),
    "partial_encrypt":     ("partial", False, 0.0, (40, 120)),
    "threaded_random_order": ("urandom", False, 0.0, (40, 120)),
    "ransom_note_drop":    ("urandom", True, 0.0, (40, 120)),
    "low_and_slow":        ("urandom", False, 4.0, (6, 8)),
}
VARIANTS = list(CONFIG)

NOTE = (b"SIMULATED NOTE from a student test project. Harmless dummy file. No real ransom.\n" * 20)


def make_encryptor():
    """Fernet if the cryptography package is installed, else random bytes of the same length."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        def fake_encrypt(data):
            return os.urandom(len(data))
        return fake_encrypt, "urandom (cryptography not installed)"
    return Fernet(Fernet.generate_key()).encrypt, "fernet"


def hit_file(workdir, path, how, rename, encrypt):
    """Change ONE dummy file (all writes are checked to stay inside workdir)."""
    size = path.stat().st_size
    if how == "urandom":
        safe_write(workdir, path, os.urandom(size))
    elif how == "fernet":
        safe_write(workdir, path, encrypt(path.read_bytes()))
    elif how == "zero_pad":                                # one random block, then zeros
        safe_write(workdir, path, os.urandom(min(4096, size)) + bytes(max(0, size - 4096)))
    elif how == "partial":
        partial_write(workdir, path)
    elif how == "copy_delete":                             # write encrypted copy, delete original
        safe_write(workdir, path.with_name(path.name + ".locked"), encrypt(path.read_bytes()))
        safe_unlink(workdir, path)
        return
    if rename:
        safe_rename(workdir, path, path.with_name(path.name + ".locked"))


def run(workdir, variant, rng):
    how, rename, pace, (low, high) = CONFIG[variant]
    docs_dir = workdir / "docs"
    docs_dir.mkdir()
    if variant == "threaded_random_order":
        files = []
        for number in range(5):                            # 5 sub-folders
            sub = docs_dir / ("dir_%d" % number)
            sub.mkdir()
            files += make_dummy_files(sub, rng.randint(26, 34), rng)
    else:
        files = make_dummy_files(docs_dir, rng.randint(130, 170), rng)
    targets = rng.sample(files, rng.randint(low, high))
    encrypt, mode = make_encryptor()
    print("encryption mode: %s" % mode, flush=True)

    time.sleep(2.0)                                        # quiet period: normal-looking start
    decoy = None
    print("PHASE attack_start", flush=True)
    try:
        if variant == "with_decoy":                        # harmless: only sleeps, words are just text
            decoy = subprocess.Popen(
                [sys.executable, str(DECOY), "vssadmin", "delete", "shadows", "/all", "/quiet"],
                stdout=subprocess.DEVNULL)
            time.sleep(1.5)                                # let the detector see it
        if variant == "threaded_random_order":
            run_threaded(workdir, targets, how, rename, encrypt, rng)
        else:
            for path in targets:
                hit_file(workdir, path, how, rename, encrypt)
                if pace:
                    time.sleep(rng.uniform(0.5 * pace, 1.5 * pace))
        if variant == "ransom_note_drop":
            drop_notes(workdir, docs_dir)
        if decoy is not None:
            time.sleep(1.5)
    finally:
        if decoy is not None:
            decoy.terminate()
            try:
                decoy.wait(timeout=5)
            except Exception:
                decoy.kill()
        print("PHASE attack_end", flush=True)
    time.sleep(1.0)


def partial_write(workdir, path):
    """Overwrite 25% of the file with random bytes, but keep the first 512 bytes (header)."""
    ensure_inside(workdir, path)
    size = path.stat().st_size
    chunk = max(1024, size // 4)
    with open(path, "r+b") as handle:
        handle.seek(512)
        handle.write(os.urandom(chunk))


def thread_worker(workdir, part, how, rename, encrypt, seed):
    """One thread: hit its share of files with tiny random pauses."""
    local = random.Random(seed)
    for path in part:
        hit_file(workdir, path, how, rename, encrypt)
        time.sleep(local.uniform(0, 0.05))


def run_threaded(workdir, targets, how, rename, encrypt, rng):
    """Split targets over 4 threads and wait for all of them."""
    threads = []
    for number in range(4):
        args = (workdir, targets[number::4], how, rename, encrypt, rng.random())
        threads.append(threading.Thread(target=thread_worker, args=args))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def drop_notes(workdir, docs_dir):
    """Write 8 harmless text notes, like ransomware leaves a 'how to pay' file."""
    for number in range(8):
        safe_write(workdir, docs_dir / ("HOW_TO_RECOVER_%d.txt" % number), NOTE)
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description="Harmless ransomware simulator")
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--variant", default="random", choices=VARIANTS + ["random"])
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    sandbox = require_marker(args.sandbox)
    rng = random.Random(args.seed)
    variant = rng.choice(VARIANTS) if args.variant == "random" else args.variant
    workdir = new_workdir(sandbox, "ransom")
    print("variant=%s workdir=%s" % (variant, workdir), flush=True)
    run(workdir, variant, rng)
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())