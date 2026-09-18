#!/usr/bin/env python3
import os

from orchestration import main


# The local Docker tiny topology's prepopulated marketplace account uses this development-only
# password. Preserve an explicit caller-provided value for a different local database.
os.environ.setdefault("HUMMBWTESTER_MARKETPLACE_PASSWORD", "1234")

if __name__ == "__main__":
    raise SystemExit(main("run"))
