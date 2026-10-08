"""authenticatorGetInfo, as seen through the real CTAPHID transport."""

from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY

import ctap as client


def test_ctaphid_init_reports_cbor_and_no_msg(device, ctap):
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
    assert set(info[2]) >= {
        "credBlob", "credProtect", "hmac-secret", "hmac-secret-mc",
        "largeBlobKey", "minPinLength",
    }, info[2]
    assert "largeBlob" not in info[2]
    assert "pinComplexityPolicy" not in info[2]
    assert info[3] == client.DEFAULT_AAGUID

    options = info[4]
    for option in (
        "rk", "up", "pinUvAuthToken", "credMgmt", "makeCredUvNotRqd",
        "authnrCfg", "setMinPINLength", "largeBlobs",
    ):
        assert options.get(option) is True, f"{option}: {options}"
    # CTAP 2.3 6.4: clientPin is false while no PIN is set (the fixture has just
    # reset the authenticator), and uv is absent without built-in user
    # verification.
    assert options.get("clientPin") is False, f"clientPin: {options}"
    assert options.get("alwaysUv") is False, f"alwaysUv: {options}"
    assert "uv" not in options, f"uv: {options}"
    assert "uvAcfg" not in options, f"uvAcfg: {options}"

    assert info[0x0C] is False, "forcePINChange"
    assert info[0x0D] == 4, "minPINLength"
    assert info[0x10] == 8, "maxRPIDsForSetMinPINLength"
    assert info[0x1F] == [2, 3], "authenticatorConfigCommands"
    assert 0x1B not in info, "pinComplexityPolicy"
    assert ctap.info.force_pin_change is False
    assert ctap.info.min_pin_length == 4
    assert ctap.info.max_rpids_for_min_pin == 8
    assert ctap.info.authenticator_config_commands == [2, 3]

    assert info[0x0F] == 32, "maxCredBlobLength"
    assert ctap.info.max_cred_blob_length == 32
    assert info[0x0B] == 16_384, "maxSerializedLargeBlobArray"
    assert ctap.info.max_large_blob == 16_384
    assert info[5] == 1768, "maxMsgSize"
    assert sorted(info[6]) == [1, 2], f"pinUvAuthProtocols {info[6]}"
    assert info[9] == ["usb"]
    assert info[10] == [
        {"type": "public-key", "alg": client.ES256},
        {"type": "public-key", "alg": client.ML_DSA_44},
        {"type": "public-key", "alg": client.ML_DSA_65},
        {"type": "public-key", "alg": client.ML_DSA_87},
        {"type": "public-key", "alg": client.ESP256},
        {"type": "public-key", "alg": client.ES384},
        {"type": "public-key", "alg": client.ESP384},
        {"type": "public-key", "alg": client.ES512},
        {"type": "public-key", "alg": client.ESP512},
        {"type": "public-key", "alg": client.ES256K},
        {"type": "public-key", "alg": client.EDDSA},
        {"type": "public-key", "alg": client.ED25519},
        {"type": "public-key", "alg": client.ED448},
        {"type": "public-key", "alg": client.RS256},
        {"type": "public-key", "alg": client.RS384},
        {"type": "public-key", "alg": client.RS512},
        {"type": "public-key", "alg": client.PS256},
        {"type": "public-key", "alg": client.PS384},
        {"type": "public-key", "alg": client.PS512},
    ]
