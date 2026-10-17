"""Simulate a tap from a tag, for local development without hardware.

    python -m scripts.gen_test_tap 04AABBCCDDEEFF 1
    python -m scripts.gen_test_tap 04AABBCCDDEEFF 2 --json

Uses QUBE_MASTER_KEY, so the result verifies against a server with the same key.
"""

import argparse
import json

from app.config import get_settings
from app.sun import make_tap


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("uid")
    p.add_argument("counter", type=int)
    p.add_argument("--base-url", default="http://localhost:8000/t")
    p.add_argument("--json", action="store_true", help="print the tap object for /taps/verify")
    args = p.parse_args()

    tap = make_tap(get_settings().master_key_bytes, args.uid, args.counter)
    if args.json:
        print(json.dumps(tap))
    else:
        print(f"{args.base_url}?picc_data={tap['picc_data']}&cmac={tap['cmac']}")


if __name__ == "__main__":
    main()
