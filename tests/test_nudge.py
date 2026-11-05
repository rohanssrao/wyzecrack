"""nudge.py: which frames are the camera's MQTT connection."""
import struct

import socket

from wyze_splice.nudge import MQTT_PORT, _checksum, mqtt_segment, rst_packet


def _frame(sport, dport, flags, proto=6, ack=7):
    eth = bytes(12) + b"\x08\x00"
    ip = (bytes((0x45, 0)) + struct.pack("!H", 40) + bytes(5) + bytes((proto,))
          + bytes(2) + socket.inet_aton("192.168.1.21") + socket.inet_aton("44.1.2.3"))
    tcp = struct.pack("!HHII", sport, dport, 1, ack) + bytes(1) + bytes((flags,)) + bytes(6)
    return eth + ip + tcp


def test_mqtt_segments():
    assert mqtt_segment(_frame(40000, MQTT_PORT, 0x02)) == (40000, True, "44.1.2.3", None)
    assert mqtt_segment(_frame(40000, MQTT_PORT, 0x18)) == (40000, False, "44.1.2.3", 7)
    assert mqtt_segment(_frame(40000, 443, 0x02)) is None
    assert mqtt_segment(_frame(40000, MQTT_PORT, 0x02, proto=17)) is None
    assert mqtt_segment(b"short") is None


def test_rst_packet_checksums():
    p = rst_packet("44.1.2.3", MQTT_PORT, "192.168.1.21", 40000, 123456)
    assert len(p) == 40 and p[9] == 6 and p[33] == 0x04
    assert struct.unpack_from("!I", p, 24)[0] == 123456
    assert _checksum(p[:20]) == 0                      # IP header sums to 0
    pseudo = p[12:20] + struct.pack("!BBH", 0, 6, 20)
    assert _checksum(pseudo + p[20:]) == 0
