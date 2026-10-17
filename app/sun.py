"""NTAG 424 DNA Secure Unique NFC (SUN) message verification.

Tags are configured to mirror two things into their URL on every tap:
  picc_data  16 bytes, AES-CBC (IV=0) under the meta-read key:
             [PICCDataTag][UID 7][SDMReadCtr 3, little-endian][padding]
  cmac       8 bytes, truncated CMAC under a session key derived from the file-read key.

The meta-read key must be the same for every tag: we have to decrypt picc_data before we know
which tag it is. Only the file-read (MAC) key is diversified per UID. References: NXP AN12196,
and the open-source sdm-backend project.

This module is pure: no DB, no settings. Callers pass the master key.
"""

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

UID_LEN = 7
# PICCDataTag: bit7 = UID mirrored, bit6 = counter mirrored, low nibble = UID length.
PICC_DATA_TAG = 0x80 | 0x40 | UID_LEN


class SunError(ValueError):
    """The tap payload is malformed or its signature doesn't verify."""


@dataclass(frozen=True)
class SunTap:
    uid: str  # 14 uppercase hex chars
    counter: int


@dataclass(frozen=True)
class TagKeys:
    meta_read: bytes  # shared across tags
    file_read: bytes  # per tag


# --- key derivation ------------------------------------------------------------------------


def _kdf(master_key: bytes, label: bytes) -> bytes:
    return hmac.new(master_key, b"qube/sdm/v1/" + label, hashlib.sha256).digest()[:16]


def app_master_key(master_key: bytes, uid: bytes) -> bytes:
    """Key 0 on the tag. Only needed to reconfigure the tag; never used to verify taps."""
    return _kdf(master_key, b"app-master/" + uid)


def meta_read_key(master_key: bytes) -> bytes:
    return _kdf(master_key, b"meta-read")


def file_read_key(master_key: bytes, uid: bytes) -> bytes:
    return _kdf(master_key, b"file-read/" + uid)


def derive_tag_keys(master_key: bytes, uid: bytes) -> TagKeys:
    return TagKeys(meta_read=meta_read_key(master_key), file_read=file_read_key(master_key, uid))


# --- primitives ----------------------------------------------------------------------------


def _aes_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
    return d.update(data) + d.finalize()


def _aes_cbc_encrypt(key: bytes, data: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).encryptor()
    return e.update(data) + e.finalize()


def _cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def _session_mac_key(file_read: bytes, uid: bytes, counter: bytes) -> bytes:
    # SV2 = 3CC3 0001 0080 || UID || SDMReadCtr (AN12196 section 3.3)
    sv2 = b"\x3c\xc3\x00\x01\x00\x80" + uid + counter
    return _cmac(file_read, sv2)


def _sdm_mac(file_read: bytes, uid: bytes, counter: bytes, mac_input: bytes = b"") -> bytes:
    full = _cmac(_session_mac_key(file_read, uid, counter), mac_input)
    # MACt: the odd-indexed bytes of the 16-byte CMAC.
    return full[1::2]


def _hex(value: str, length: int, name: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except (ValueError, TypeError) as e:
        raise SunError(f"{name} is not hex") from e
    if len(raw) != length:
        raise SunError(f"{name} must be {length} bytes")
    return raw


# --- public API ----------------------------------------------------------------------------


def decrypt_picc_data(meta_key: bytes, picc_data_hex: str) -> tuple[bytes, bytes]:
    """Return (uid, counter_le_bytes). Raises SunError if the plaintext isn't well formed."""
    plain = _aes_cbc_decrypt(meta_key, _hex(picc_data_hex, 16, "picc_data"))
    if plain[0] != PICC_DATA_TAG:
        raise SunError("picc_data did not decrypt to a valid header")
    uid = plain[1 : 1 + UID_LEN]
    counter = plain[1 + UID_LEN : 1 + UID_LEN + 3]
    return uid, counter


def verify_tap(master_key: bytes, picc_data_hex: str, cmac_hex: str) -> SunTap:
    """Decrypt and verify a tap. Raises SunError on any failure."""
    return verify_tap_with_keys(
        meta_read_key(master_key),
        lambda uid: file_read_key(master_key, uid),
        picc_data_hex,
        cmac_hex,
    )


def verify_tap_with_keys(meta_key, file_key_for_uid, picc_data_hex: str, cmac_hex: str) -> SunTap:
    expected_mac = _hex(cmac_hex, 8, "cmac")
    uid, counter = decrypt_picc_data(meta_key, picc_data_hex)
    mac = _sdm_mac(file_key_for_uid(uid), uid, counter)
    if not hmac.compare_digest(mac, expected_mac):
        raise SunError("cmac mismatch")
    return SunTap(uid=uid.hex().upper(), counter=int.from_bytes(counter, "little"))


def make_tap(master_key: bytes, uid_hex: str, counter: int) -> dict[str, str]:
    """Simulate a tag: build the picc_data/cmac a real tag would mirror. For tests and local dev."""
    uid = _hex(uid_hex, UID_LEN, "uid")
    ctr = counter.to_bytes(3, "little")
    plain = bytes([PICC_DATA_TAG]) + uid + ctr + os.urandom(16 - 1 - UID_LEN - 3)
    picc = _aes_cbc_encrypt(meta_read_key(master_key), plain)
    mac = _sdm_mac(file_read_key(master_key, uid), uid, ctr)
    return {"picc_data": picc.hex().upper(), "cmac": mac.hex().upper()}
