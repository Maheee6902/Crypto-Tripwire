"""Root entry point for Crypto-Tripwire (import-safe; delegates to crypto_tripwire.cli)."""

from __future__ import annotations

import sys
from typing import List, Optional

from crypto_tripwire.cli import main as cli_main


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        # Default behavior when invoked as `python main.py` with no subcommands:
        # start the configured 4-phase monitor using default config if present.
        default_cfg = "configs/default_config.json"
        import os

        if os.path.exists(default_cfg):
            args = ["monitor", "--config", default_cfg]
        else:
            args = ["monitor"]
    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
