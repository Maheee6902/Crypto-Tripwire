"""Allow `python -m crypto_tripwire` invocation."""

from crypto_tripwire.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
