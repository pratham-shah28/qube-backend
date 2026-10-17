import pytest

from app.sun import SunError, make_tap, verify_tap, verify_tap_with_keys

ZERO = bytes(16)
MASTER = bytes.fromhex("000102030405060708090A0B0C0D0E0F")


def test_an12196_vector():
    # NXP AN12196 example (all-zero keys), also used by the sdm-backend test suite.
    tap = verify_tap_with_keys(
        ZERO, lambda _uid: ZERO, "EF963FF7828658A599F3041510671E88", "94EED9EE65337086"
    )
    assert tap.uid == "04DE5F1EACC040"
    assert tap.counter == 61


def test_an12196_vector_rejects_wrong_cmac():
    with pytest.raises(SunError):
        verify_tap_with_keys(
            ZERO, lambda _uid: ZERO, "EF963FF7828658A599F3041510671E88", "94EED9EE65337087"
        )


def test_roundtrip():
    payload = make_tap(MASTER, "04AABBCCDDEEFF", 1234)
    tap = verify_tap(MASTER, payload["picc_data"], payload["cmac"])
    assert tap.uid == "04AABBCCDDEEFF"
    assert tap.counter == 1234


def test_counter_is_three_bytes_little_endian():
    payload = make_tap(MASTER, "04AABBCCDDEEFF", 0xFFFFFE)
    assert verify_tap(MASTER, payload["picc_data"], payload["cmac"]).counter == 0xFFFFFE


def test_wrong_master_key():
    payload = make_tap(MASTER, "04AABBCCDDEEFF", 1)
    with pytest.raises(SunError):
        verify_tap(bytes(16), payload["picc_data"], payload["cmac"])


def test_tampered_picc_data():
    payload = make_tap(MASTER, "04AABBCCDDEEFF", 1)
    flipped = payload["picc_data"][:-1] + ("0" if payload["picc_data"][-1] != "0" else "1")
    with pytest.raises(SunError):
        verify_tap(MASTER, flipped, payload["cmac"])


def test_cmac_from_another_tap_does_not_verify():
    a = make_tap(MASTER, "04AABBCCDDEEFF", 1)
    b = make_tap(MASTER, "04AABBCCDDEEFF", 2)
    with pytest.raises(SunError):
        verify_tap(MASTER, b["picc_data"], a["cmac"])


@pytest.mark.parametrize(
    "picc,cmac",
    [("zz" * 16, "00" * 8), ("00" * 15, "00" * 8), ("00" * 16, "00" * 7), ("00" * 16, "xx" * 8)],
)
def test_malformed_input(picc, cmac):
    with pytest.raises(SunError):
        verify_tap(MASTER, picc, cmac)
