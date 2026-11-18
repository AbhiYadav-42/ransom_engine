"""Harmless decoy: only sleeps 60 s. The words on the command line are just text; nothing is run.
Run: python sim/decoy_vss.py vssadmin delete shadows /all /quiet"""

import sys
import time

print("decoy started, args:", " ".join(sys.argv[1:]), flush=True)
time.sleep(60)
