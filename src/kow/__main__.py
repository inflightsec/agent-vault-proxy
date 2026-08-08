from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    from mitmproxy.tools.main import mitmdump

    addon_path = Path(__file__).parent / "addon.py"
    args = [
        "-s",
        str(addon_path),
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        "14322",
        *sys.argv[1:],
    ]
    return mitmdump(args) or 0


if __name__ == "__main__":
    sys.exit(main())
