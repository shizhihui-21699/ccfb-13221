"""Test package: put the repo root on sys.path so imports work under
`python -I -m unittest` (isolated mode ignores PYTHONPATH)."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
