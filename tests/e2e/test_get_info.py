"""authenticatorGetInfo, as seen through the real CTAPHID transport."""

from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY

import ctap as client


def test_ctaphid_init_reports_cbor_and_no_msg(device):
    assert device.version == 2
    assert device.capabilities & CAPABILITY.CBOR
    assert device.capabilities & CAPABILITY.NMSG
    # The default IDs: pid.codes' open source vendor ID and its first test
    # product ID.
    assert device.descriptor.vid == 0x1209
    assert device.descriptor.pid == 0x0001
    assert device.descriptor.report_size_in == 64
    assert device.descriptor.report_size_out == 64


def test_get_info(ctap: Ctap2):
    info = ctap.send_cbor(Ctap2.CMD.GET_INFO)

    assert "FIDO_2_3" in info[1] and "FIDO_2_1" in info[1] and "FIDO_2_0" in info[1], info[1]
    assert "FIDO_2_2" not in info[1], "CTAP 2.3 6.4: FIDO_2_2 MUST not be present"
    assert set(info[2]) >= {"credProtect", "hmac-secret"}, info[2]
    assert info[3] == client.DEFAULT_AAGUID

    options = info[4]
    for option in ("rk", "up", "pinUvAuthToken", "credMgmt", "makeCredUvNotRqd"):
        assert options.get(option) is True, f"{option}: {options}"
    # CTAP 2.3 6.4: clientPin is false while no PIN is set (the fixture has just
    # reset the authenticator), and uv is absent without built-in user
    # verification.
    assert options.get("clientPin") is False, f"clientPin: {options}"
    assert "uv" not in options, f"uv: {options}"

    assert info[5] >= 1024, "maxMsgSize"
    assert sorted(info[6]) == [1, 2], f"pinUvAuthProtocols {info[6]}"
    assert info[9] == ["usb"]
    assert info[10] == [
        {"type": "public-key", "alg": client.ES256},
        {"type": "public-key", "alg": client.ML_DSA_44},
        {"type": "public-key", "alg": client.ML_DSA_65},
        {"type": "public-key", "alg": client.ML_DSA_87},
    ]
