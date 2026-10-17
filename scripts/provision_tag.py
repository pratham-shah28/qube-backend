"""Print the keys and SDM settings to write onto one NTAG 424 DNA tag.

    python -m scripts.provision_tag 04DE5F1EACC040 --base-url https://qube.example.com/t

Read the tag's UID first with any NFC tool (it's printed on the TagXplorer main screen, or
use NFC Tools on a phone). Write the output with NXP TagXplorer or another NTAG 424 writer,
then register the UID through POST /admin/tags.

This runs locally and needs QUBE_MASTER_KEY. The master key never goes through the API.

TODO(M5): drive a USB reader (ACR1252U via pyscard) to write keys and settings directly,
so nobody has to copy keys by hand.
"""

import argparse

from app.config import get_settings
from app.sun import app_master_key, file_read_key, meta_read_key


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("uid", help="7-byte tag UID in hex")
    p.add_argument("--base-url", default="https://qube.example.com/t")
    args = p.parse_args()

    uid = bytes.fromhex(args.uid.replace(":", "").replace(" ", ""))
    if len(uid) != 7:
        raise SystemExit("UID must be 7 bytes")
    master = get_settings().master_key_bytes

    print(f"Tag UID: {uid.hex().upper()}\n")
    print("Application keys (AES-128) - change each from the all-zero factory default:")
    print(f"  Key 0  app master       {app_master_key(master, uid).hex().upper()}")
    print(f"  Key 1  SDM meta read    {meta_read_key(master).hex().upper()}   (same on every tag)")
    print(f"  Key 2  SDM file read    {file_read_key(master, uid).hex().upper()}")
    print()
    print("NDEF file (file 02) URL record:")
    print(f"  {args.base_url}?picc_data=00000000000000000000000000000000&cmac=0000000000000000")
    print()
    print("File 02 SDM settings:")
    print("  SDM enabled, ASCII encoding")
    print("  UID mirroring + SDMReadCtr mirroring ON")
    print(
        "  SDMMetaRead key = 1  (PICC data encrypted)  -> PICCDataOffset = start of picc_data value"
    )
    print("  SDMFileRead key = 2                         -> SDMMACOffset   = start of cmac value")
    print("  SDMMACInputOffset = SDMMACOffset            (MAC over empty input)")
    print("  SDMCtrRet = key 0; no encrypted file data")
    print("  Read access free, write access key 0, change access key 0")


if __name__ == "__main__":
    main()
