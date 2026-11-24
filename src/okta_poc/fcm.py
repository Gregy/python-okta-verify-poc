"""Receive Okta Verify push challenges by acting as an Android device on FCM.

Okta sends pushes through Firebase Cloud Messaging (FCM) to the Okta Verify
Android app. To receive them we do what the app + Google Play services do:

1. Android check-in      -> device ID + security token from Google
2. Firebase Installation -> auth token for Okta's Firebase project
3. GCM register3         -> FCM registration token, sent to Okta at enrollment
4. MCS connection        -> long-lived TLS socket to mtalk.google.com that
                            delivers data messages (our challenges)

Steps 1 and 4 use small hand-encoded protobuf messages. This is a port of the
Android path of https://github.com/agusibrahim/fcm_receiver.rs, including the
fixes needed for Okta's project (Android check-in, Installation before
register3, PHONE_REGISTRATION_ERROR retries). Okta's pushes arrive as plain
key/value app data, so no web-push decryption is needed.
"""

from __future__ import annotations

import base64
import os
import socket
import ssl
import struct
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs

import requests

from .errors import PoCError
from .state import FcmDevice

# Public Firebase client configuration of the Okta Verify Android app
# (com.okta.android.auth). These identify the app, they are not Okta secrets.
API_KEY = "AIzaSyDwy_6SVFbhzuHSzH5ld-Q-cnHJMHbGOac"
APP_ID = "1:302730332600:android:fef22a316c6a55e7"
PROJECT_ID = "okta-verify-2"
SENDER_ID = "302730332600"
PACKAGE = "com.okta.android.auth"
# SHA-1 of the APK signing certificate (from the analyzed APK).
PACKAGE_CERT = "d2dd7d391505aabbb7e35432019d4b84a39059a8"

CHECKIN_URL = "https://android.clients.google.com/checkin"
REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
INSTALLATIONS_URL = f"https://firebaseinstallations.googleapis.com/v1/projects/{PROJECT_ID}/installations"
MCS_HOST, MCS_PORT = "mtalk.google.com", 5228
FIREBASE_CLIENT = (
    "android-min-sdk/23 fire-core/20.0.0 device-name/a21snnxx device-brand/samsung "
    "device-model/a21s android-installer/com.android.vending fire-android/30 "
    "fire-installations/17.0.0 fire-fcm/22.0.0 android-platform/ kotlin/1.9.23 "
    "android-target-sdk/34"
)

# MCS protocol
MCS_VERSION = 41
TAG_HEARTBEAT_PING, TAG_HEARTBEAT_ACK, TAG_LOGIN_REQUEST, TAG_LOGIN_RESPONSE = 0, 1, 2, 3
TAG_CLOSE, TAG_IQ_STANZA, TAG_DATA_MESSAGE = 4, 7, 8
SELECTIVE_ACK_EXTENSION = 12
HEARTBEAT_SECONDS = 300


# --- Minimal protobuf encoding --------------------------------------------


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _pb_int(number: int, value: int) -> bytes:
    return _varint(number << 3 | 0) + _varint(value)


def _pb_fixed64(number: int, value: int) -> bytes:
    return _varint(number << 3 | 1) + struct.pack("<Q", value)


def _pb_bytes(number: int, value: bytes | str) -> bytes:
    data = value.encode() if isinstance(value, str) else value
    return _varint(number << 3 | 2) + _varint(len(data)) + data


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data):
            raise PoCError("Truncated protobuf varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _pb_parse(data: bytes) -> dict[int, list[Any]]:
    """Decode a protobuf message into {field number: [values]} (ints or bytes)."""

    fields: dict[int, list[Any]] = {}
    pos = 0
    while pos < len(data):
        key, pos = _read_varint(data, pos)
        number, wire_type = key >> 3, key & 7
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
        elif wire_type == 1:
            (value,), pos = struct.unpack_from("<Q", data, pos), pos + 8
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            value, pos = data[pos : pos + length], pos + length
        elif wire_type == 5:
            (value,), pos = struct.unpack_from("<I", data, pos), pos + 4
        else:
            raise PoCError(f"Unsupported protobuf wire type {wire_type}")
        fields.setdefault(number, []).append(value)
    return fields


# --- Registration ------------------------------------------------------------


class _PhoneRegistrationError(PoCError):
    pass


def _checkin(session: requests.Session) -> tuple[int, int]:
    """Android check-in: returns (android_id, security_token)."""

    body = (
        _pb_int(2, 0)                        # id: 0 = new device
        + _pb_bytes(4, _pb_int(12, 1))       # checkin { type: DEVICE_ANDROID_OS }
        + _pb_fixed64(13, 0)                 # security_token
        + _pb_int(14, 3)                     # version
    )
    response = session.post(
        CHECKIN_URL, data=body, timeout=20,
        headers={"Content-Type": "application/x-protobuf", "User-Agent": ""},
    )
    if response.status_code != 200:
        raise PoCError(f"FCM check-in failed with HTTP {response.status_code}")
    fields = _pb_parse(response.content)
    try:
        return fields[7][0], fields[8][0]
    except KeyError as exc:
        raise PoCError("FCM check-in response has no device credentials") from exc


def _installation_token(session: requests.Session) -> str:
    """Create a Firebase Installation; register3 for Okta's project requires its token."""

    fid = bytearray(os.urandom(17))
    fid[0] = 0b0111_0000 | (fid[0] & 0b0000_1111)  # FID format marker
    response = session.post(
        INSTALLATIONS_URL,
        timeout=20,
        json={
            "fid": base64.b64encode(bytes(fid)).decode("ascii"),
            "appId": APP_ID,
            "authVersion": "FIS_v2",
            "sdkVersion": "a:17.0.0",
        },
        headers={
            "Accept": "application/json",
            "x-goog-api-key": API_KEY,
            "X-Android-Package": PACKAGE,
            "X-Android-Cert": PACKAGE_CERT,
            "x-firebase-client": FIREBASE_CLIENT,
            "x-firebase-client-log-type": "3",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A217F Build/RP1A.200720.012)",
        },
    )
    if response.status_code != 200:
        raise PoCError(f"Firebase Installation failed with HTTP {response.status_code}")
    return response.json()["authToken"]["token"]


def _register3(session: requests.Session, android_id: int, security_token: int, installation: str) -> str:
    response = session.post(
        REGISTER_URL,
        timeout=20,
        headers={"Authorization": f"AidLogin {android_id}:{security_token}", "User-Agent": ""},
        data={
            "X-subtype": SENDER_ID,
            "sender": SENDER_ID,
            "device": str(android_id),
            "app": PACKAGE,
            "cert": PACKAGE_CERT,
            "app_ver": "1",
            "X-app_ver": "1",
            "X-app_ver_name": "1",
            "X-osv": "29",
            "X-cliv": "fiid-21.1.1",
            "X-gmsv": "220217001",
            "X-scope": "*",
            "X-Goog-Firebase-Installations-Auth": installation,
            "X-gms_app_id": APP_ID,
            "X-Firebase-Client": FIREBASE_CLIENT,
            "X-Firebase-Client-Log-Type": "1",
            "target_ver": "31",
        },
    )
    if response.status_code != 200:
        raise PoCError(f"GCM register3 failed with HTTP {response.status_code}")
    result = {name: values[0] for name, values in parse_qs(response.text).items()}
    if result.get("Error") == "PHONE_REGISTRATION_ERROR":
        raise _PhoneRegistrationError("PHONE_REGISTRATION_ERROR")
    if "token" not in result:
        raise PoCError(f"GCM register3 failed: {result.get('Error', 'no token')}")
    return result["token"]


def register_device(session: requests.Session | None = None, attempts: int = 8) -> FcmDevice:
    """Register a new emulated Android device and return its FCM credentials."""

    session = session or requests.Session()
    android_id, security_token = _checkin(session)
    installation = _installation_token(session)
    for attempt in range(1, attempts + 1):
        try:
            token = _register3(session, android_id, security_token, installation)
            print("FCM registration succeeded")
            return FcmDevice(android_id=android_id, security_token=security_token, token=token)
        except _PhoneRegistrationError:
            # register3 often refuses a freshly checked-in device (~2 in 3 tries).
            # Google Play services retries with backoff; halfway through we also
            # start over with a new device in case this one is bad.
            if attempt == attempts:
                raise
            print(f"FCM registration attempt {attempt}/{attempts}: PHONE_REGISTRATION_ERROR; retrying")
            time.sleep(min(attempt, 4))
            if attempt == attempts // 2:
                android_id, security_token = _checkin(session)
                installation = _installation_token(session)
    raise AssertionError("unreachable")


# --- Receiving -----------------------------------------------------------------


def _login_packet(device: FcmDevice, received_ids: list[str]) -> bytes:
    payload = (
        _pb_bytes(1, "chrome-63.0.3234.0")
        + _pb_bytes(2, "mcs.android.com")
        + _pb_bytes(3, str(device.android_id))                   # user
        + _pb_bytes(4, str(device.android_id))                   # resource
        + _pb_bytes(5, str(device.security_token))               # auth_token
        + _pb_bytes(6, f"android-{device.android_id:x}")          # device_id
        + _pb_bytes(8, _pb_bytes(1, "new_vc") + _pb_bytes(2, "1"))  # setting
        # Acknowledges messages we already got, so FCM stops redelivering them.
        + b"".join(_pb_bytes(10, persistent_id) for persistent_id in received_ids)
        + _pb_int(12, 0)                                         # adaptive_heartbeat: false
        + _pb_int(14, 1)                                         # use_rmq2: true
        + _pb_int(16, 2)                                         # auth_service: ANDROID_ID
        + _pb_int(17, 1)                                         # network_type
    )
    return bytes([MCS_VERSION, TAG_LOGIN_REQUEST]) + _varint(len(payload)) + payload


def _take_frame(buffer: bytearray) -> tuple[int, bytes] | None:
    """Remove one complete `tag, varint size, payload` frame from the buffer."""

    if len(buffer) < 2:
        return None
    try:
        size, start = _read_varint(bytes(buffer[1:6]), 0)
    except PoCError:
        return None  # size varint not complete yet
    start += 1
    if len(buffer) < start + size:
        return None
    tag, payload = buffer[0], bytes(buffer[start : start + size])
    del buffer[: start + size]
    return tag, payload


class _Connection:
    """One logged-in MCS session.

    Like Chromium, we count the messages the server sent us and report that
    number (`last_stream_id_received`) in heartbeats and acks; the server
    uses it to confirm what the client has really received.
    """

    def __init__(self, device: FcmDevice, received_ids: list[str]) -> None:
        raw = socket.create_connection((MCS_HOST, MCS_PORT), timeout=20)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=MCS_HOST)
        self.sock.settimeout(HEARTBEAT_SECONDS)
        self.sock.sendall(_login_packet(device, received_ids))
        self.buffer = bytearray()
        self.version_checked = False
        self.received = 0

    def close(self) -> None:
        self.sock.close()

    def send(self, tag: int, payload: bytes = b"") -> None:
        self.sock.sendall(bytes([tag]) + _varint(len(payload)) + payload)

    def send_heartbeat(self, tag: int) -> None:
        self.send(tag, _pb_int(2, self.received))  # last_stream_id_received

    def send_ack(self, persistent_ids: list[str]) -> None:
        """IqStanza with a SelectiveAck: tells FCM to stop redelivering these."""

        selective_ack = b"".join(_pb_bytes(1, persistent_id) for persistent_id in persistent_ids)
        self.send(
            TAG_IQ_STANZA,
            _pb_int(2, 1)                                        # type: SET
            + _pb_bytes(3, "")                                   # id (required)
            + _pb_bytes(7, _pb_int(1, SELECTIVE_ACK_EXTENSION) + _pb_bytes(2, selective_ack))
            + _pb_int(10, self.received),                        # last_stream_id_received
        )

    def frames(self) -> Iterator[tuple[int, bytes]]:
        unanswered_pings = 0
        while True:
            if not self.version_checked and self.buffer:
                if self.buffer[0] < MCS_VERSION and self.buffer[0] != 38:
                    raise PoCError(f"Unsupported MCS version {self.buffer[0]}")
                del self.buffer[0]
                self.version_checked = True
            if self.version_checked and (frame := _take_frame(self.buffer)):
                self.received += 1
                unanswered_pings = 0
                yield frame
                continue
            try:
                chunk = self.sock.recv(32768)
            except TimeoutError:
                if unanswered_pings >= 2:
                    raise PoCError("FCM connection is silent") from None
                self.send_heartbeat(TAG_HEARTBEAT_PING)
                unanswered_pings += 1
                continue
            if not chunk:
                raise PoCError("FCM server closed the connection")
            self.buffer += chunk


def listen(device: FcmDevice) -> Iterator[dict[str, str]]:
    """Yield the key/value data of every FCM message from Okta's sender, forever.

    Reconnects after errors. While the caller handles a message the socket is
    not read; if FCM drops us meanwhile we just log in again.
    """

    received_ids: list[str] = []
    while True:
        connection = None
        try:
            connection = _Connection(device, received_ids[-100:])
            for tag, payload in connection.frames():
                if tag == TAG_HEARTBEAT_PING:
                    connection.send_heartbeat(TAG_HEARTBEAT_ACK)
                elif tag == TAG_LOGIN_RESPONSE:
                    if 3 in _pb_parse(payload):
                        raise PoCError("FCM login was rejected")
                    print("FCM connected; waiting for pushes", flush=True)
                elif tag == TAG_CLOSE:
                    raise PoCError("FCM server sent close")
                elif tag == TAG_DATA_MESSAGE:
                    message = _pb_parse(payload)
                    persistent_ids = [item.decode() for item in message.get(9, [])]
                    if persistent_ids:
                        connection.send_ack(persistent_ids)
                        # Also listed at the next login in case this ack got lost.
                        received_ids.extend(persistent_ids)
                    sender = message.get(3, [b""])[0].decode()
                    if sender != SENDER_ID:
                        print("Ignoring FCM message from an unexpected sender", flush=True)
                        continue
                    data = {}
                    for item in message.get(7, []):
                        pair = _pb_parse(item)
                        data[pair[1][0].decode()] = pair.get(2, [b""])[0].decode()
                    yield data
        except (OSError, PoCError) as exc:
            print(f"FCM connection lost ({exc}); reconnecting in 5 seconds", flush=True)
            time.sleep(5)
        finally:
            if connection:
                connection.close()
