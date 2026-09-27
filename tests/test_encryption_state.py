"""Tests for DTU encryption state handling."""

from unittest.mock import Mock

from homeassistant.core import HomeAssistant
from hoymiles_wifi.dtu import DTU
from hoymiles_wifi.protobuf.APPInfomationData_pb2 import APPDtuInfoMO
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.hoymiles_wifi import _decode_stored_enc_rand
from custom_components.hoymiles_wifi.const import (
    CONF_ENC_RAND,
    CONF_IS_ENCRYPTED,
    DOMAIN,
    ENC_RAND_LENGTH,
)
from custom_components.hoymiles_wifi.util import async_sync_encryption_state


# Bit 25 is the encryption flag used by hoymiles-wifi.
DFS_ENCRYPTED = 1 << 25
RAND = bytes.fromhex("f5480938516c557e347bc49c672b6af1")
ROTATED_RAND = bytes.fromhex("00112233445566778899aabbccddeeff")


def _dtu_info(dfs: int, enc_rand: bytes = b"") -> APPDtuInfoMO:
    """Build an app-info response containing encryption state."""
    info = APPDtuInfoMO()
    info.dfs = dfs
    info.enc_rand = enc_rand
    return info


def test_decode_stored_enc_rand_rejects_invalid_values() -> None:
    """Invalid persisted values must not abort integration setup."""
    assert _decode_stored_enc_rand("dtu", True, None) is None
    assert _decode_stored_enc_rand("dtu", True, 123) is None
    assert _decode_stored_enc_rand("dtu", True, "not-hex") is None
    assert _decode_stored_enc_rand("dtu", True, "00" * (ENC_RAND_LENGTH - 1)) is None
    assert _decode_stored_enc_rand("dtu", False, None) is None


def test_decode_stored_enc_rand_accepts_valid_value() -> None:
    """A valid persisted value creates the expected key bytes."""
    assert _decode_stored_enc_rand("dtu", True, RAND.hex()) == RAND


async def test_sync_encryption_state_persists_both_values(
    hass: HomeAssistant,
) -> None:
    """A firmware switch to encrypted traffic is persisted atomically."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_IS_ENCRYPTED: False, CONF_ENC_RAND: ""},
    )
    entry.add_to_hass(hass)
    dtu = DTU("dtu")

    async_sync_encryption_state(hass, entry, dtu, _dtu_info(DFS_ENCRYPTED, RAND))

    assert dtu.is_encrypted is True
    assert dtu.enc_rand == RAND
    assert entry.data[CONF_IS_ENCRYPTED] is True
    assert entry.data[CONF_ENC_RAND] == RAND.hex()


async def test_sync_encryption_state_supports_downgrade(
    hass: HomeAssistant,
) -> None:
    """A plaintext app-info response clears stale encrypted state."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_IS_ENCRYPTED: True, CONF_ENC_RAND: RAND.hex()},
    )
    entry.add_to_hass(hass)
    dtu = DTU("dtu", is_encrypted=True, enc_rand=RAND)

    async_sync_encryption_state(hass, entry, dtu, _dtu_info(0))

    assert dtu.is_encrypted is False
    assert dtu.enc_rand == b""
    assert entry.data[CONF_IS_ENCRYPTED] is False
    assert entry.data[CONF_ENC_RAND] == ""


async def test_sync_encryption_state_rejects_unusable_announced_key(
    hass: HomeAssistant,
) -> None:
    """An unusable announced key falls back to plaintext safely."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_IS_ENCRYPTED: True, CONF_ENC_RAND: RAND.hex()},
    )
    entry.add_to_hass(hass)
    dtu = DTU("dtu", is_encrypted=True, enc_rand=RAND)

    async_sync_encryption_state(
        hass, entry, dtu, _dtu_info(DFS_ENCRYPTED, b"too-short")
    )

    assert dtu.is_encrypted is False
    assert dtu.enc_rand == b""
    assert entry.data[CONF_IS_ENCRYPTED] is False
    assert entry.data[CONF_ENC_RAND] == ""


async def test_sync_encryption_state_does_not_write_steady_state(
    hass: HomeAssistant,
) -> None:
    """A steady state does not rewrite the config entry."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_IS_ENCRYPTED: True, CONF_ENC_RAND: RAND.hex()},
    )
    entry.add_to_hass(hass)
    dtu = DTU("dtu", is_encrypted=True, enc_rand=RAND)
    update_entry = Mock(wraps=hass.config_entries.async_update_entry)
    hass.config_entries.async_update_entry = update_entry

    async_sync_encryption_state(hass, entry, dtu, _dtu_info(DFS_ENCRYPTED, RAND))

    assert update_entry.call_count == 0
