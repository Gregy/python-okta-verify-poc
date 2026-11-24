from __future__ import annotations

import ssl

import pytest

from okta_poc import fcm
from okta_poc.errors import PoCError
from okta_poc.state import FcmDevice


def test_protobuf_roundtrip():
    data = fcm._pb_int(2, 300) + fcm._pb_fixed64(13, 2**63 + 5) + fcm._pb_bytes(4, fcm._pb_int(12, 1))
    fields = fcm._pb_parse(data)
    assert fields[2] == [300]
    assert fields[13] == [2**63 + 5]
    assert fcm._pb_parse(fields[4][0]) == {12: [1]}


def test_login_packet():
    device = FcmDevice(android_id=0x1234, security_token=99, token="t")
    packet = fcm._login_packet(device, ["pid-1", "pid-2"])
    assert packet[:2] == bytes([41, 2])
    size, start = fcm._read_varint(packet, 2)
    fields = fcm._pb_parse(packet[start:])
    assert len(packet) == start + size
    assert fields[3] == [b"4660"] and fields[5] == [b"99"]
    assert fields[6] == [b"android-1234"]
    assert fields[10] == [b"pid-1", b"pid-2"]
    assert fields[16] == [2]


def _data_message(sender: str, data: dict[str, str], persistent_id: str) -> bytes:
    payload = fcm._pb_bytes(3, sender) + fcm._pb_bytes(9, persistent_id)
    for key, value in data.items():
        payload += fcm._pb_bytes(7, fcm._pb_bytes(1, key) + fcm._pb_bytes(2, value))
    return bytes([fcm.TAG_DATA_MESSAGE]) + fcm._varint(len(payload)) + payload


def _acked_ids(packet: bytes) -> tuple[list[str], int]:
    size, start = fcm._read_varint(packet, 1)
    iq = fcm._pb_parse(packet[start : start + size])
    assert iq[2] == [1] and iq[3] == [b""]  # type SET, empty id
    extension = fcm._pb_parse(iq[7][0])
    assert extension[1] == [fcm.SELECTIVE_ACK_EXTENSION]
    return [item.decode() for item in fcm._pb_parse(extension[2][0])[1]], iq[10][0]


class FakeConnection:
    """Feeds the MCS stream to `listen` in awkward 3-byte chunks."""

    def __init__(self, stream: bytes) -> None:
        self.chunks = [stream[index : index + 3] for index in range(0, len(stream), 3)]
        self.sent: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        pass

    def close(self):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if not self.chunks:
            raise TimeoutError
        return self.chunks.pop(0)


def test_listen_yields_okta_messages_and_answers_heartbeats(monkeypatch, capsys):
    stream = (
        bytes([41])
        + bytes([fcm.TAG_LOGIN_RESPONSE, 0])
        + bytes([fcm.TAG_HEARTBEAT_PING, 0])
        + _data_message("someone-else", {"x": "y"}, "pid-0")
        + _data_message(fcm.SENDER_ID, {"challenge": "a.b.c", "transactionId": "tx"}, "pid-1")
    )
    connection = FakeConnection(stream)
    monkeypatch.setattr(fcm.socket, "create_connection", lambda *args, **kwargs: object())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda self, raw, server_hostname: connection)

    messages = fcm.listen(FcmDevice(android_id=1, security_token=2, token="t"))
    assert next(messages) == {"challenge": "a.b.c", "transactionId": "tx"}
    assert connection.sent[0][:2] == bytes([41, 2])  # login
    # Server messages so far: login response (1), ping (2), data (3, 4).
    heartbeat_ack = bytes([fcm.TAG_HEARTBEAT_ACK]) + fcm._varint(2) + fcm._pb_int(2, 2)
    assert heartbeat_ack in connection.sent
    acks = [packet for packet in connection.sent if packet[0] == fcm.TAG_IQ_STANZA]
    assert [_acked_ids(packet) for packet in acks] == [(["pid-0"], 3), (["pid-1"], 4)]
    assert "unexpected sender" in capsys.readouterr().out


def test_take_frame_waits_for_complete_frames():
    buffer = bytearray([8, 0x85])  # size varint not finished
    assert fcm._take_frame(buffer) is None
    buffer += bytes([0x01]) + b"x" * 100  # size 133, only 100 bytes present
    assert fcm._take_frame(buffer) is None
    buffer += b"x" * 33 + bytes([0, 0])
    assert fcm._take_frame(buffer) == (8, b"x" * 133)
    assert fcm._take_frame(buffer) == (0, b"")
    assert buffer == bytearray()


class FakeResponse:
    def __init__(self, status=200, content=b"", json_value=None):
        self.status_code = status
        self.content = content
        self.text = content.decode(errors="replace")
        self._json = json_value

    def json(self):
        return self._json


class FakeSession:
    def __init__(self, register_answers: list[str]) -> None:
        self.register_answers = register_answers
        self.calls: list[str] = []

    def post(self, url, **kwargs):
        self.calls.append(url)
        if url == fcm.CHECKIN_URL:
            assert kwargs["headers"]["Content-Type"] == "application/x-protobuf"
            return FakeResponse(content=fcm._pb_fixed64(7, 111) + fcm._pb_fixed64(8, 222))
        if url == fcm.INSTALLATIONS_URL:
            assert kwargs["headers"]["X-Android-Package"] == fcm.PACKAGE
            return FakeResponse(json_value={"authToken": {"token": "install-token"}})
        assert url == fcm.REGISTER_URL
        assert kwargs["headers"]["Authorization"] == "AidLogin 111:222"
        assert kwargs["data"]["X-Goog-Firebase-Installations-Auth"] == "install-token"
        return FakeResponse(content=self.register_answers.pop(0).encode())


def test_register_device_retries_phone_registration_error(monkeypatch):
    monkeypatch.setattr(fcm.time, "sleep", lambda seconds: None)
    session = FakeSession(["Error=PHONE_REGISTRATION_ERROR"] * 4 + ["token=FCM_TOKEN"])
    device = fcm.register_device(session)
    assert device == FcmDevice(android_id=111, security_token=222, token="FCM_TOKEN")
    # After 4 failures it started over with a fresh check-in and installation.
    assert session.calls.count(fcm.CHECKIN_URL) == 2
    assert session.calls.count(fcm.INSTALLATIONS_URL) == 2


def test_register_device_gives_up(monkeypatch):
    monkeypatch.setattr(fcm.time, "sleep", lambda seconds: None)
    with pytest.raises(PoCError, match="PHONE_REGISTRATION_ERROR"):
        fcm.register_device(FakeSession(["Error=PHONE_REGISTRATION_ERROR"] * 2), attempts=2)
    with pytest.raises(PoCError, match="DEPRECATED"):
        fcm.register_device(FakeSession(["Error=DEPRECATED"]))
