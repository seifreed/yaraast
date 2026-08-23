"""Execute every Python block documented in README.md."""

import os
from pathlib import Path
import re
import tempfile


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    readme = (project_root / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```python\n(.*?)```", readme, re.DOTALL)
    if not blocks:
        msg = "README.md must contain at least one Python block"
        raise RuntimeError(msg)
    with tempfile.TemporaryDirectory() as temp_dir:
        os.chdir(temp_dir)
        for block in blocks:
            exec(compile(block, "README.md", "exec"), {})


if __name__ == "__main__":
    main()
