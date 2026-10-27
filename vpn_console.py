"""Run the console from an unpacked source directory."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent/"src"))
from pyl2tpvpn.console import main

if __name__ == "__main__":
    raise SystemExit(main())
