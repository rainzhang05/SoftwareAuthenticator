"""Raw CTAPHID packets on the hidraw node, for transport-level tests.

This bypasses python-fido2's CtapHidDevice, which hides stray or out-of-order
packets, so tests can check exactly which packets the authenticator sends.
"""

from __future__ import annotations

import os
import select
import struct
from dataclasses import dataclass

PACKET_SIZE = 64
BROADCAST_CID = 0xFFFFFFFF

PING = 0x01
MSG = 0x03
INIT = 0x06
CBOR = 0x10
CANCEL = 0x11
KEEPALIVE = 0x3B
ERROR = 0x3F

READ_TIMEOUT_S = 15.0


class UnexpectedPacket(AssertionError):
    pass


@dataclass
class Message:
    cid: int
    cmd: int
    payload: bytes

    def __str__(self) -> str:
        if self.cmd == ERROR and len(self.payload) == 1:
            return f"ERROR {self.payload[0]:#04x} on channel {self.cid:#010x}"
        return f"command {self.cmd:#04x} with {len(self.payload)} bytes on channel {self.cid:#010x}"


class RawHid:
    def __init__(self, path: str):
        self.fd = os.open(path, os.O_RDWR)

    def close(self) -> None:
        os.close(self.fd)

    def write_packet(self, packet: bytes) -> None:
        assert len(packet) <= PACKET_SIZE
        # Report ID 0, then the 64-byte report.
        os.write(self.fd, b"\0" + packet.ljust(PACKET_SIZE, b"\0"))

    def read_packet(self, timeout: float = READ_TIMEOUT_S) -> bytes:
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            raise TimeoutError(f"no CTAPHID packet within {timeout}s")
        return os.read(self.fd, PACKET_SIZE)

    def init_packets(self, cid: int, cmd: int, payload: bytes) -> list[bytes]:
        """Split a message into its initialization and continuation packets."""
        packets = [struct.pack(">IBH", cid, 0x80 | cmd, len(payload)) + payload[: PACKET_SIZE - 7]]
        rest, seq = payload[PACKET_SIZE - 7 :], 0
        while rest:
            packets.append(struct.pack(">IB", cid, seq) + rest[: PACKET_SIZE - 5])
            rest, seq = rest[PACKET_SIZE - 5 :], seq + 1
        return packets

    def send(self, cid: int, cmd: int, payload: bytes = b"") -> None:
        for packet in self.init_packets(cid, cmd, payload):
            self.write_packet(packet)

    def receive(self) -> Message:
        """Read one complete message, skipping keepalives."""
        while True:
            packet = self.read_packet()
            cid, cmd, length = struct.unpack(">IBH", packet[:7])
            if not cmd & 0x80:
                raise UnexpectedPacket(f"continuation packet {packet.hex()} without an initialization packet")
            cmd &= 0x7F
            payload = packet[7 : 7 + length]
            seq = 0
            while len(payload) < length:
                packet = self.read_packet()
                next_cid, next_seq = struct.unpack(">IB", packet[:5])
                if next_cid != cid or next_seq != seq:
                    raise UnexpectedPacket(f"expected continuation {seq} on {cid:#010x}, got {packet.hex()}")
                payload += packet[5 : 5 + length - len(payload)]
                seq += 1
            if cmd != KEEPALIVE:
                return Message(cid, cmd, payload)

    def expect(self, cid: int, cmd: int) -> Message:
        message = self.receive()
        if message.cid != cid or message.cmd != cmd:
            raise UnexpectedPacket(f"expected command {cmd:#04x} on channel {cid:#010x}, got {message}")
        return message

    def allocate_channel(self) -> int:
        nonce = os.urandom(8)
        self.send(BROADCAST_CID, INIT, nonce)
        response = self.expect(BROADCAST_CID, INIT)
        assert response.payload[:8] == nonce, "INIT nonce not echoed"
        (cid,) = struct.unpack(">I", response.payload[8:12])
        return cid
