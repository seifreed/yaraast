from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
root_str = str(ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)
