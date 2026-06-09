#!/usr/bin/env python3
"""Cross-platform Harmony Hub USB HID/LTCP bridge.

The Harmony desktop apps talk to the hub as a USB HID device. This script keeps
the transport in userspace: hidapi on macOS/Linux when available, with a Linux
hidraw fallback that uses only Python's standard library.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import errno
import glob
import hashlib
import json
import math
import os
import pathlib
import random
import select
import shutil
import socket
import stat
import subprocess
import sys
import time
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_VENDOR_ID = 0x046D
DEFAULT_PRODUCT_ID = 0xC129
DEFAULT_INPUT_REPORT_LENGTH = 65
DEFAULT_OUTPUT_REPORT_LENGTH = 65
ACTION_CHOICES = (
    "probe",
    "drain",
    "preflight",
    "resync",
    "stage-summary",
    "root-ssh",
    "sysinfo",
    "wifi-status",
    "wifi-scan",
    "wifi-connect",
    "provision-wifi",
)


@dataclasses.dataclass
class DeviceInfo:
    backend: str
    path: str
    vendor_id: int
    product_id: int
    input_report_length: int = DEFAULT_INPUT_REPORT_LENGTH
    output_report_length: int = DEFAULT_OUTPUT_REPORT_LENGTH
    product: str = ""
    manufacturer: str = ""
    serial: str = ""
    usage_page: int | None = None
    usage: int | None = None


@dataclasses.dataclass
class DecodeResult:
    complete: bool = False
    error: str | None = None
    leading_discarded: int = 0
    service: int | None = None
    type: int | None = None
    request_id: int | None = None
    is_response: bool = False
    packet_count: int | None = None
    payload_length: int = 0
    payload: str = ""


@dataclasses.dataclass
class Candidate:
    offset: int
    complete: bool
    error: str | None
    payload_id: str | None
    code: str | None
    decode: DecodeResult
    payload_object: Any


@dataclasses.dataclass
class Response:
    device_path: str
    command: str
    app_request_id: int
    attempt: int
    attempts: int
    matched_response: bool
    drain: Any
    request_json: str
    frames_written: int
    raw_response_length: int
    raw_response_hex: str
    read_reports: list[dict[str, Any]]
    decode: DecodeResult
    payload_object: Any
    candidate_decodes: list[dict[str, Any]]


@dataclasses.dataclass
class StageFile:
    id: str
    source: str
    path: str
    mode: str
    bytes: int
    md5: str
    data: str


class UsbBridgeError(RuntimeError):
    pass


def parse_hex_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = value.strip().lower()
    if text.startswith("0x"):
        return int(text, 16)
    if any(c in "abcdef" for c in text):
        return int(text, 16)
    return int(text, 10)


def resolve_local_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value).expanduser()
    if path.is_absolute():
        return path
    return SCRIPT_DIR / path


def compact_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def pretty_json(obj: Any) -> str:
    return json.dumps(to_jsonable(obj), indent=2, ensure_ascii=False)


def to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return to_jsonable(dataclasses.asdict(obj))
    if isinstance(obj, pathlib.Path):
        return str(obj)
    if isinstance(obj, bytes):
        return hex_string(obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def hex_string(data: bytes, length: int | None = None) -> str:
    if length is not None:
        data = data[:length]
    return " ".join(f"{b:02X}" for b in data)


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def now_epoch() -> int:
    return int(time.time())


def normalize_input_report(report: bytes) -> bytes:
    if not report:
        return b""
    if len(report) >= 65 and report[0] == 0:
        return report[1:65]
    return report[:64]


class HidHandle:
    def write(self, report: bytes) -> None:
        raise NotImplementedError

    def read(self, length: int, timeout_ms: int) -> bytes:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class HidBackend:
    name = "base"

    def enumerate(self, vendor_id: int, product_id: int) -> list[DeviceInfo]:
        raise NotImplementedError

    def open(self, device: DeviceInfo) -> HidHandle:
        raise NotImplementedError


class HidApiHandle(HidHandle):
    def __init__(self, hid_module: Any, path: Any) -> None:
        self._device = hid_module.device()
        self._device.open_path(path)
        try:
            self._device.set_nonblocking(False)
        except Exception:
            pass

    def write(self, report: bytes) -> None:
        written = self._device.write(report)
        if written <= 0:
            raise UsbBridgeError("hidapi write returned no bytes.")

    def read(self, length: int, timeout_ms: int) -> bytes:
        data = self._device.read(length, timeout_ms)
        return bytes(data or [])

    def close(self) -> None:
        self._device.close()


class HidApiBackend(HidBackend):
    name = "hidapi"

    def __init__(self) -> None:
        try:
            import hid  # type: ignore
        except Exception as exc:
            raise UsbBridgeError(
                "Python hidapi binding is not available. Install it with "
                "`python3 -m pip install hidapi`."
            ) from exc
        self._hid = hid
        self._raw_paths: dict[str, Any] = {}

    def enumerate(self, vendor_id: int, product_id: int) -> list[DeviceInfo]:
        devices: list[DeviceInfo] = []
        for item in self._hid.enumerate(vendor_id, product_id):
            path = item.get("path", "")
            path_text = path.decode("utf-8", "replace") if isinstance(path, bytes) else str(path)
            self._raw_paths[path_text] = path
            devices.append(
                DeviceInfo(
                    backend=self.name,
                    path=path_text,
                    vendor_id=int(item.get("vendor_id") or vendor_id),
                    product_id=int(item.get("product_id") or product_id),
                    input_report_length=int(item.get("input_report_length") or DEFAULT_INPUT_REPORT_LENGTH),
                    output_report_length=int(item.get("output_report_length") or DEFAULT_OUTPUT_REPORT_LENGTH),
                    product=str(item.get("product_string") or ""),
                    manufacturer=str(item.get("manufacturer_string") or ""),
                    serial=str(item.get("serial_number") or ""),
                    usage_page=item.get("usage_page"),
                    usage=item.get("usage"),
                )
            )
        return devices

    def open(self, device: DeviceInfo) -> HidHandle:
        path = self._raw_paths.get(device.path, device.path)
        return HidApiHandle(self._hid, path)


class HidrawHandle(HidHandle):
    def __init__(self, path: str) -> None:
        self._fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)

    def write(self, report: bytes) -> None:
        total = 0
        while total < len(report):
            try:
                written = os.write(self._fd, report[total:])
                if written <= 0:
                    raise UsbBridgeError("hidraw write returned no bytes.")
                total += written
            except BlockingIOError:
                select.select([], [self._fd], [], 0.25)

    def read(self, length: int, timeout_ms: int) -> bytes:
        ready, _, _ = select.select([self._fd], [], [], max(0, timeout_ms) / 1000.0)
        if not ready:
            return b""
        try:
            return os.read(self._fd, max(length, DEFAULT_INPUT_REPORT_LENGTH))
        except BlockingIOError:
            return b""

    def close(self) -> None:
        os.close(self._fd)


class LinuxHidrawBackend(HidBackend):
    name = "hidraw"

    def enumerate(self, vendor_id: int, product_id: int) -> list[DeviceInfo]:
        if not sys.platform.startswith("linux"):
            return []
        devices: list[DeviceInfo] = []
        for node in sorted(glob.glob("/dev/hidraw*")):
            hidraw_name = os.path.basename(node)
            sys_device = pathlib.Path("/sys/class/hidraw") / hidraw_name / "device"
            uevent = read_text_if_exists(sys_device / "uevent")
            parsed = parse_hidraw_uevent(uevent)
            if not parsed:
                continue
            dev_vendor, dev_product = parsed
            if dev_vendor != vendor_id or dev_product != product_id:
                continue
            devices.append(
                DeviceInfo(
                    backend=self.name,
                    path=node,
                    vendor_id=dev_vendor,
                    product_id=dev_product,
                    input_report_length=DEFAULT_INPUT_REPORT_LENGTH,
                    output_report_length=DEFAULT_OUTPUT_REPORT_LENGTH,
                    product=read_text_if_exists(sys_device / "name").strip(),
                )
            )
        return devices

    def open(self, device: DeviceInfo) -> HidHandle:
        return HidrawHandle(device.path)


def read_text_if_exists(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_hidraw_uevent(text: str) -> tuple[int, int] | None:
    for line in text.splitlines():
        if not line.startswith("HID_ID="):
            continue
        parts = line.split("=", 1)[1].split(":")
        if len(parts) >= 3:
            return int(parts[-2], 16), int(parts[-1], 16)
    return None


def make_backends(name: str) -> list[HidBackend]:
    if name == "hidapi":
        return [HidApiBackend()]
    if name == "hidraw":
        return [LinuxHidrawBackend()]
    backends: list[HidBackend] = []
    try:
        backends.append(HidApiBackend())
    except UsbBridgeError:
        pass
    backends.append(LinuxHidrawBackend())
    return backends


def read_number(data: bytes, offset: int, length: int) -> int:
    value = 0
    for i in range(length):
        value = (value << 8) | data[offset + i]
    return value


def decode_ltcp(data: bytes) -> DecodeResult:
    result = DecodeResult()
    start = data.find(b"\xff")
    if start < 0:
        result.error = "Need more data for LTCP primary header."
        return result
    if start:
        result.leading_discarded = start
        data = data[start:]
    if len(data) < 4:
        result.error = "Need more data for LTCP primary header."
        return result
    if data[0] != 0xFF:
        result.error = f"Invalid LTCP service byte 0x{data[0]:02X}."
        return result

    pos = 0
    result.service = data[pos]
    pos += 1
    result.type = data[pos]
    pos += 1
    result.request_id = data[pos]
    result.is_response = bool(result.request_id & 0x80)
    pos += 1
    param_count = data[pos] & 0x3F
    pos += 1
    packets = 0

    for _ in range(param_count):
        if pos >= len(data):
            result.error = "Need more data for LTCP parameter."
            return result
        tag = data[pos]
        pos += 1
        length = tag & 0x3F
        if length == 0:
            while pos < len(data) and data[pos] != 0:
                pos += 1
            if pos >= len(data):
                result.error = "Need more data for LTCP string parameter."
                return result
            pos += 1
        else:
            if pos + length > len(data):
                result.error = "Need more data for LTCP numeric parameter."
                return result
            packets = read_number(data, pos, length)
            pos += length
    result.packet_count = packets

    remaining = packets - 1
    payload = bytearray()
    while remaining > 0:
        while pos < len(data) and data[pos] == 0:
            pos += 1
        if pos + 2 > len(data):
            result.error = "Need more data for LTCP secondary header."
            return result
        pos += 1
        length_byte = data[pos]
        pos += 1
        if length_byte & 0x40:
            if pos >= len(data):
                result.error = "Need more data for LTCP long secondary length."
                return result
            chunk_len = ((length_byte & 0x3F) << 8) | data[pos]
            pos += 1
        else:
            chunk_len = length_byte & 0x3F
        if pos + chunk_len > len(data):
            result.error = "Need more data for LTCP secondary payload."
            return result
        payload.extend(data[pos : pos + chunk_len])
        pos += chunk_len
        remaining -= 1

    result.complete = True
    result.error = None
    result.payload_length = len(payload)
    result.payload = payload.decode("utf-8", "replace")
    return result


def convert_json_payload(payload: str) -> Any:
    if not payload.strip():
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def ltcp_candidates(data: bytes) -> list[Candidate]:
    candidates: list[Candidate] = []
    for offset, value in enumerate(data):
        if value != 0xFF:
            continue
        decode = decode_ltcp(data[offset:])
        payload_object = convert_json_payload(decode.payload)
        payload_id = None
        code = None
        if isinstance(payload_object, dict):
            if "id" in payload_object:
                payload_id = str(payload_object["id"])
            if "code" in payload_object:
                code = str(payload_object["code"])
        candidates.append(
            Candidate(
                offset=offset,
                complete=decode.complete,
                error=decode.error,
                payload_id=payload_id,
                code=code,
                decode=decode,
                payload_object=payload_object,
            )
        )
    return candidates


def select_ltcp_candidate(candidates: list[Candidate], expected_id: int, allow_loose: bool) -> Candidate | None:
    if not candidates:
        return None
    expected = str(expected_id)
    matching_complete = [c for c in candidates if c.complete and c.payload_id == expected]
    if matching_complete:
        return matching_complete[-1]
    if allow_loose:
        complete = [c for c in candidates if c.complete]
        if complete:
            return complete[-1]
    matching_any = [c for c in candidates if c.payload_id == expected]
    if matching_any:
        return matching_any[-1]
    return candidates[-1]


def candidate_matches(candidate: Candidate | None, expected_id: int, allow_loose: bool) -> bool:
    if not candidate or not candidate.complete:
        return False
    if candidate.payload_id == str(expected_id):
        return True
    return allow_loose


def new_ltcp_frames(request_json: str) -> list[bytes]:
    payload = request_json.encode("ascii")
    if len(payload) > 16383:
        raise UsbBridgeError(f"Payload is too large for one LTCP secondary packet ({len(payload)} bytes). Lower --chunk-size.")
    stream = bytearray([0xFF, 0x08, 0x00, 0x01, 0x01, 0x02, 0x01])
    if len(payload) > 63:
        stream.append(0x80 | 0x40 | ((len(payload) >> 8) & 0x3F))
        stream.append(len(payload) & 0xFF)
    else:
        stream.append(0x80 | len(payload))
    stream.extend(payload)
    frames: list[bytes] = []
    for offset in range(0, len(stream), 64):
        frame = bytearray(64)
        chunk = stream[offset : offset + 64]
        frame[: len(chunk)] = chunk
        frames.append(bytes(frame))
    return frames


class HarmonyUsbBridge:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.vendor_id = parse_hex_int(args.vendor_id)
        self.product_id = parse_hex_int(args.product_id)
        self.next_command_id = random.randint(100000, 899999)
        self._device: DeviceInfo | None = None
        self._backend: HidBackend | None = None

    def enumerate_devices(self) -> list[DeviceInfo]:
        if self.args.device_path:
            return [
                DeviceInfo(
                    backend=self.args.backend if self.args.backend != "auto" else ("hidraw" if sys.platform.startswith("linux") else "hidapi"),
                    path=self.args.device_path,
                    vendor_id=self.vendor_id,
                    product_id=self.product_id,
                )
            ]
        devices: list[DeviceInfo] = []
        for backend in make_backends(self.args.backend):
            found = backend.enumerate(self.vendor_id, self.product_id)
            if found:
                devices.extend(found)
                if self.args.backend != "auto":
                    break
        return devices

    def get_device(self) -> tuple[HidBackend, DeviceInfo]:
        if self._device and self._backend:
            return self._backend, self._device
        for backend in make_backends(self.args.backend):
            if self.args.device_path and backend.name != (self.args.backend if self.args.backend != "auto" else backend.name):
                continue
            devices = (
                [
                    DeviceInfo(
                        backend=backend.name,
                        path=self.args.device_path,
                        vendor_id=self.vendor_id,
                        product_id=self.product_id,
                    )
                ]
                if self.args.device_path
                else backend.enumerate(self.vendor_id, self.product_id)
            )
            if devices:
                self._backend = backend
                self._device = devices[0]
                return backend, devices[0]
        hint = ""
        if sys.platform == "darwin":
            hint = " Install hidapi with `python3 -m pip install hidapi`."
        elif sys.platform.startswith("linux"):
            hint = " Check USB permissions, try sudo, or add a udev rule for 046d:c129."
        raise UsbBridgeError(f"No Harmony Hub USB HID device found for {self.vendor_id:04x}:{self.product_id:04x}.{hint}")

    def open_handle(self) -> tuple[HidHandle, DeviceInfo]:
        backend, device = self.get_device()
        return backend.open(device), device

    def drain(self, max_reports: int | None = None, wait_ms: int | None = None) -> dict[str, Any]:
        max_reports = self.args.drain_reports if max_reports is None else max_reports
        wait_ms = self.args.drain_wait_ms if wait_ms is None else wait_ms
        handle, device = self.open_handle()
        samples = []
        try:
            for _ in range(max_reports):
                report = handle.read(device.input_report_length, wait_ms)
                if not report:
                    break
                samples.append({"read": len(report), "hex": hex_string(report, min(len(report), 24))})
        finally:
            handle.close()
        return {"reports": len(samples), "samples": samples[:4]}

    def new_command_json(self, command_name: str, command_data: Any, command_timeout: int = 5) -> tuple[int, str]:
        request_id = self.next_command_id
        self.next_command_id += 1
        return request_id, compact_json({"id": request_id, "cmd": command_name, "data": command_data, "timeout": command_timeout})

    def invoke(self, command_name: str, command_data: Any = "", read_timeout_ms: int | None = None) -> Response:
        read_timeout_ms = self.args.timeout_ms if read_timeout_ms is None else read_timeout_ms
        attempts = max(1, self.args.retry_count + 1)
        last_response: Response | None = None

        for attempt in range(1, attempts + 1):
            drain_result = None
            if not self.args.no_drain:
                try:
                    drain_result = self.drain()
                except Exception as exc:
                    drain_result = {"error": str(exc)}

            request_id, request_json = self.new_command_json(command_name, command_data)
            frames = new_ltcp_frames(request_json)
            raw_response = bytearray()
            read_reports: list[dict[str, Any]] = []
            selected: Candidate | None = None
            candidates: list[Candidate] = []
            handle, device = self.open_handle()
            try:
                if device.output_report_length != DEFAULT_OUTPUT_REPORT_LENGTH:
                    raise UsbBridgeError(f"Unexpected output report length {device.output_report_length}; expected 65.")
                for frame in frames:
                    handle.write(b"\x00" + frame)

                deadline = time.monotonic() + read_timeout_ms / 1000.0
                while time.monotonic() < deadline:
                    remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
                    report = handle.read(device.input_report_length, remaining_ms)
                    if not report:
                        break
                    read_reports.append({"bytesRead": len(report), "hex": hex_string(report)})
                    raw_response.extend(normalize_input_report(report))
                    candidates = ltcp_candidates(bytes(raw_response))
                    selected = select_ltcp_candidate(candidates, request_id, self.args.loose_response_match)
                    if candidate_matches(selected, request_id, self.args.loose_response_match):
                        break
            finally:
                handle.close()

            if not selected:
                candidates = ltcp_candidates(bytes(raw_response))
                selected = select_ltcp_candidate(candidates, request_id, self.args.loose_response_match)

            decode = selected.decode if selected else decode_ltcp(bytes(raw_response))
            payload_object = selected.payload_object if selected else convert_json_payload(decode.payload)
            matched = candidate_matches(selected, request_id, self.args.loose_response_match)
            last_response = Response(
                device_path=device.path,
                command=command_name,
                app_request_id=request_id,
                attempt=attempt,
                attempts=attempts,
                matched_response=matched,
                drain=drain_result,
                request_json=request_json,
                frames_written=len(frames),
                raw_response_length=len(raw_response),
                raw_response_hex=hex_string(bytes(raw_response)),
                read_reports=read_reports,
                decode=decode,
                payload_object=payload_object,
                candidate_decodes=[
                    {
                        "offset": c.offset,
                        "complete": c.complete,
                        "error": c.error,
                        "payloadId": c.payload_id,
                        "code": c.code,
                        "payloadLength": c.decode.payload_length,
                    }
                    for c in candidates
                ],
            )
            if matched:
                return last_response
            if attempt < attempts and self.args.retry_delay_ms > 0:
                time.sleep(self.args.retry_delay_ms / 1000.0)

        assert last_response is not None
        return last_response


def response_code(response: Response) -> str:
    if isinstance(response.payload_object, dict) and "code" in response.payload_object:
        return str(response.payload_object["code"])
    return ""


def assert_ok(response: Response, what: str) -> None:
    code = response_code(response)
    if code != "200":
        payload = response.decode.payload if response and response.decode else ""
        complete = response.decode.complete if response and response.decode else False
        error = response.decode.error if response and response.decode else "no decode"
        attempt_text = f"{response.attempt}/{response.attempts}" if response else "none"
        raise UsbBridgeError(f"{what} failed with code '{code}' (attempt {attempt_text}, complete={complete}, error={error}): {payload}")


def command_json_get(bridge: HarmonyUsbBridge, path: str, file_name: str) -> Response:
    return bridge.invoke("connect.jsonfiletransfer?get", {"path": path, "file": file_name})


def command_json_put(bridge: HarmonyUsbBridge, path: str, file_name: str, content: Any) -> Response:
    return bridge.invoke("connect.jsonfiletransfer?put", {"path": path, "file": file_name, "content": content})


def command_log_put(bridge: HarmonyUsbBridge, file_name: str, body: str) -> Response:
    return bridge.invoke("harmony.log?put", {"resource": [{"fileName": file_name, "data": body}]})


def redact(obj: Any, show_ssids: bool = False, name: str = "") -> Any:
    low = name.lower()
    if low in {"password", "passphrase", "psk", "key"}:
        return "<redacted>"
    if low == "ssid" and not show_ssids:
        return "<ssid>"
    if isinstance(obj, dict):
        return {str(k): redact(v, show_ssids, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, show_ssids, name) for v in obj]
    return obj


def response_summary(response: Response, raw_output: bool = False, show_ssids: bool = False) -> Any:
    payload = redact(response.payload_object, show_ssids) if show_ssids or response.payload_object else response.payload_object
    if raw_output or not response.payload_object:
        return {
            "command": response.command,
            "appRequestId": response.app_request_id,
            "attempt": response.attempt,
            "attempts": response.attempts,
            "matchedResponse": response.matched_response,
            "drain": response.drain,
            "complete": response.decode.complete,
            "error": response.decode.error,
            "payloadLength": response.decode.payload_length,
            "payload": payload if payload is not None else response.decode.payload,
            "rawResponseLength": response.raw_response_length,
            "rawResponseHex": response.raw_response_hex,
            "readReports": response.read_reports,
            "candidates": response.candidate_decodes,
        }
    return payload


def write_response(response: Response, args: argparse.Namespace, redacted: bool = False) -> None:
    payload = response_summary(response, args.raw_output, args.show_ssids if redacted else True)
    if redacted and not args.show_ssids:
        payload = redact(payload, False)
    print(pretty_json(payload))


def add_stage_file(files: list[StageFile], source: pathlib.Path, remote_path: str, mode: str, file_id: str) -> None:
    if not source.is_file():
        raise UsbBridgeError(f"Missing runtime file: {source}")
    data = source.read_bytes()
    files.append(
        StageFile(
            id=file_id,
            source=str(source),
            path=remote_path,
            mode=mode,
            bytes=len(data),
            md5=md5_bytes(data),
            data=base64.b64encode(data).decode("ascii"),
        )
    )


def add_stage_bytes(files: list[StageFile], data: bytes, remote_path: str, mode: str, file_id: str, source: str) -> None:
    files.append(
        StageFile(
            id=file_id,
            source=source,
            path=remote_path,
            mode=mode,
            bytes=len(data),
            md5=md5_bytes(data),
            data=base64.b64encode(data).decode("ascii"),
        )
    )


def ensure_keypair(args: argparse.Namespace) -> None:
    pub_path = resolve_local_path(args.public_key_file)
    priv_path = resolve_local_path(args.private_key_file)
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    if pub_path.exists():
        if priv_path.exists():
            chmod_private_key(priv_path)
        return
    if priv_path.exists():
        raise UsbBridgeError(f"Private key exists but public key is missing: {pub_path}. Restore the .pub file or choose another key path.")
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        raise UsbBridgeError("No public key was found and ssh-keygen is not available. Install OpenSSH or pass --public-key-file.")
    print("Generating a local SSH keypair for this hub...")
    subprocess.run([ssh_keygen, "-t", "ed25519", "-f", str(priv_path), "-N", "", "-C", "harmony-root-usb"], check=True)
    chmod_private_key(priv_path)


def chmod_private_key(path: pathlib.Path) -> None:
    if os.name == "posix" and path.exists():
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def new_owned_runtime_manifest(args: argparse.Namespace) -> dict[str, Any]:
    files: list[StageFile] = []
    root = resolve_local_path(args.package_root)
    public_key = resolve_local_path(args.public_key_file)
    dropbearmulti = root / "dropbearmulti"
    add_stage_file(files, dropbearmulti, "/data/rootssh/bin/dropbearmulti", "755", "f001")
    add_stage_file(files, public_key, "/home/root/.ssh/authorized_keys", "600", "f002")
    add_stage_bytes(files, b'#!/bin/sh\nexec /data/rootssh/bin/dropbear -s -g -K 300 "$@"\n', "/usr/sbin/dropbear", "755", "f003", "dropbear-wrapper")
    add_stage_bytes(files, b'#!/bin/sh\nexec /data/rootssh/bin/dropbearkey "$@"\n', "/usr/sbin/dropbearkey", "755", "f004", "dropbearkey-wrapper")
    add_stage_bytes(files, b"1\n", "/etc/tdeenable", "644", "f005", "tde-marker")

    manifest_files = []
    for item in files:
        chunks = math.ceil(len(item.data) / args.chunk_size)
        manifest_files.append(
            {
                "id": item.id,
                "path": item.path,
                "mode": item.mode,
                "bytes": item.bytes,
                "md5": item.md5,
                "chunks": chunks,
            }
        )
    commands = [
        "mkdir -p /data/rootssh/bin /etc/dropbear /home/root/.ssh",
        "ln -sf dropbearmulti /data/rootssh/bin/dropbear",
        "ln -sf dropbearmulti /data/rootssh/bin/dropbearkey",
        "chmod 700 /home/root/.ssh",
        "chmod 600 /home/root/.ssh/authorized_keys",
        "chmod 755 /data/rootssh/bin/dropbearmulti /usr/sbin/dropbear /usr/sbin/dropbearkey",
        "[ -f /etc/dropbear/dropbear_rsa_host_key ] || /usr/sbin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key",
        "killall dropbear 2>/dev/null || true",
        "/usr/sbin/dropbear -R -E -p 22",
    ]
    return {
        "stage_files": files,
        "manifest": {
            "version": "rootssh-usb-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
            "files": manifest_files,
            "commands": commands,
        },
    }


def owned_runtime_stage_summary(args: argparse.Namespace) -> dict[str, Any]:
    if args.chunk_size < 1024 or args.chunk_size > 12000:
        raise UsbBridgeError("--chunk-size should be between 1024 and 12000 to stay under LTCP limits.")
    package = new_owned_runtime_manifest(args)
    files_out = []
    total_bytes = 0
    total_chunks = 0
    for item in package["stage_files"]:
        chunks = math.ceil(len(item.data) / args.chunk_size)
        total_bytes += item.bytes
        total_chunks += chunks
        files_out.append(
            {
                "id": item.id,
                "source": item.source,
                "path": item.path,
                "mode": item.mode,
                "bytes": item.bytes,
                "base64Bytes": len(item.data),
                "chunks": chunks,
                "md5": item.md5,
            }
        )
    return {
        "chunkSize": args.chunk_size,
        "fileCount": len(files_out),
        "totalBytes": total_bytes,
        "totalChunks": total_chunks,
        "files": files_out,
        "installerCommands": package["manifest"]["commands"],
    }


def tcp_port_open(address: str, port: int, timeout: float = 2.5) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_hub_lan(args: argparse.Namespace) -> None:
    if not args.wait_for_lan:
        return
    if not args.hub_ip:
        print("WARNING: --wait-for-lan was set, but --hub-ip is empty. Skipping LAN reachability check.", file=sys.stderr)
        return
    print(f"Waiting for hub LAN port {args.hub_ip}:{args.lan_port}...")
    deadline = time.monotonic() + max(1, args.lan_wait_seconds)
    open_ = False
    while time.monotonic() < deadline:
        if tcp_port_open(args.hub_ip, args.lan_port):
            open_ = True
            break
        time.sleep(2)
    print(f"lan_port_{args.lan_port}_open={str(open_).lower()}")


def test_root_ssh_login(args: argparse.Namespace) -> None:
    if not args.hub_ip:
        return
    priv_path = resolve_local_path(args.private_key_file)
    if not priv_path.exists():
        print(f"WARNING: Private key not found for SSH verification: {priv_path}", file=sys.stderr)
        return
    chmod_private_key(priv_path)
    ssh = shutil.which("ssh")
    if not ssh:
        print("WARNING: ssh executable not found; skipping login verification.", file=sys.stderr)
        return
    print(f"Waiting for Dropbear SSH on {args.hub_ip}:22...")
    deadline = time.monotonic() + 75
    open_ = False
    while time.monotonic() < deadline:
        if tcp_port_open(args.hub_ip, 22):
            open_ = True
            break
        time.sleep(2)
    print(f"ssh_port_22_open={str(open_).lower()}")
    if not open_:
        return
    proc = subprocess.run(
        [
            ssh,
            "-i",
            str(priv_path),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=8",
            f"root@{args.hub_ip}",
            "id; ps | grep '[d]ropbear'",
        ],
        check=False,
    )
    print(f"ssh_check_exit_code={proc.returncode}")


def assert_usb_preflight_ready(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    if args.skip_preflight:
        print("usb_preflight_skipped=true")
        return
    print("Running read-only USB preflight...")
    sysinfo = bridge.invoke("sys.info", "", args.timeout_ms)
    code = response_code(sysinfo)
    if code != "200" or not sysinfo.matched_response or not sysinfo.decode.complete:
        summary = {
            "code": code,
            "complete": sysinfo.decode.complete,
            "matchedResponse": sysinfo.matched_response,
            "appRequestId": sysinfo.app_request_id,
            "attempt": sysinfo.attempt,
            "attempts": sysinfo.attempts,
            "error": sysinfo.decode.error,
            "rawResponseLength": sysinfo.raw_response_length,
            "candidates": sysinfo.candidate_decodes,
        }
        raise UsbBridgeError("USB preflight failed; not starting the requested USB action. Summary: " + compact_json(summary))
    data = sysinfo.payload_object.get("data", {}) if isinstance(sysinfo.payload_object, dict) else {}
    print(f"usb_preflight_ok=true fw={data.get('fw_ver', '')} attempt={sysinfo.attempt}/{sysinfo.attempts}")


def install_root_access(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    pub_path = resolve_local_path(args.public_key_file)
    if not pub_path.exists():
        raise UsbBridgeError(f"Public key not found: {pub_path}")
    public_key = pub_path.read_text(encoding="utf-8").strip()
    print("Enabling TDE/root marker over USB...")
    response = command_log_put(bridge, "../etc/tdeenable", "1\n")
    assert_ok(response, "write /etc/tdeenable")

    print("Creating root SSH key directories...")
    response = command_json_put(bridge, "../../home/root/.ssh", "codex-dir-probe.json", {"created": now_epoch()})
    assert_ok(response, "create /home/root/.ssh")
    response = command_json_put(bridge, "../../etc/dropbear", "codex-dir-probe.json", {"created": now_epoch()})
    assert_ok(response, "create /etc/dropbear")

    print("Installing public key for root/dropbear...")
    response = command_log_put(bridge, "../home/root/.ssh/authorized_keys", public_key + "\n")
    assert_ok(response, "write /home/root/.ssh/authorized_keys")
    response = command_log_put(bridge, "../etc/dropbear/authorized_keys", public_key + "\n")
    assert_ok(response, "write /etc/dropbear/authorized_keys")

    if args.reboot:
        print("Requesting reboot so the root SSH path comes up cleanly...")
        response = bridge.invoke("setup.firmware?reboot", {}, 2000)
        write_response(response, args)


def run_probe(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    devices = bridge.enumerate_devices()
    print(pretty_json([to_jsonable(device) for device in devices]))


def run_drain(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    _, device = bridge.get_device()
    result = bridge.drain()
    print(pretty_json({"devicePath": device.path, "reports": result["reports"], "samples": result["samples"]}))


def run_preflight(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    _, device = bridge.get_device()
    sysinfo = bridge.invoke("sys.info", "", args.timeout_ms)
    write_result = None
    if args.write_probe:
        write_result = command_log_put(bridge, "codex-usb-preflight.txt", "ok " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n")
    out = {
        "device": {
            "backend": device.backend,
            "vendorId": f"{device.vendor_id:04X}",
            "productId": f"{device.product_id:04X}",
            "devicePath": device.path,
            "inputReportByteLength": device.input_report_length,
            "outputReportByteLength": device.output_report_length,
        },
        "transport": {
            "timeoutMs": args.timeout_ms,
            "retryCount": args.retry_count,
            "retryDelayMs": args.retry_delay_ms,
            "drainReports": args.drain_reports,
            "drainWaitMs": args.drain_wait_ms,
            "looseResponseMatch": args.loose_response_match,
        },
        "sysinfo": {
            "code": response_code(sysinfo),
            "complete": sysinfo.decode.complete,
            "matchedResponse": sysinfo.matched_response,
            "appRequestId": sysinfo.app_request_id,
            "attempt": sysinfo.attempt,
            "attempts": sysinfo.attempts,
            "error": sysinfo.decode.error,
            "payload": sysinfo.payload_object,
            "readReports": sysinfo.read_reports,
            "candidates": sysinfo.candidate_decodes,
        },
        "writeProbe": None,
    }
    if write_result:
        out["writeProbe"] = {
            "code": response_code(write_result),
            "complete": write_result.decode.complete,
            "matchedResponse": write_result.matched_response,
            "appRequestId": write_result.app_request_id,
            "attempt": write_result.attempt,
            "attempts": write_result.attempts,
        }
    print(pretty_json(out))


def run_resync(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    results = []
    for outer in range(1, args.resync_attempts + 1):
        sysinfo = bridge.invoke("sys.info", "", args.timeout_ms)
        summary = {
            "code": response_code(sysinfo),
            "complete": sysinfo.decode.complete,
            "matchedResponse": sysinfo.matched_response,
            "appRequestId": sysinfo.app_request_id,
            "attempt": sysinfo.attempt,
            "attempts": sysinfo.attempts,
            "error": sysinfo.decode.error,
            "rawResponseLength": sysinfo.raw_response_length,
            "readReportCount": len(sysinfo.read_reports),
            "candidates": sysinfo.candidate_decodes,
            "outerAttempt": outer,
        }
        results.append(summary)
        if response_code(sysinfo) == "200" and sysinfo.matched_response and sysinfo.decode.complete:
            data = sysinfo.payload_object.get("data", {}) if isinstance(sysinfo.payload_object, dict) else {}
            print(pretty_json({"ok": True, "outerAttempts": outer, "firmware": data.get("fw_ver"), "link": data.get("link_type"), "results": results}))
            return
        if outer < args.resync_attempts:
            time.sleep(max(0.1, args.retry_delay_ms / 1000.0))
    print(pretty_json({"ok": False, "outerAttempts": args.resync_attempts, "results": results}))


def run_wifi_status(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    response = bridge.invoke("wifi.status", {"donotresolve": 1}, max(args.timeout_ms, 10000))
    write_response(response, args, redacted=True)
    assert_ok(response, "wifi.status")


def run_wifi_scan(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    response = bridge.invoke("wifi.networks", {}, max(args.timeout_ms, 60000))
    write_response(response, args, redacted=True)
    assert_ok(response, "wifi.networks")


def ssid_label(args: argparse.Namespace) -> str:
    return args.ssid if args.show_ssids else "<ssid>"


def run_wifi_connect(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    if not args.ssid.strip():
        raise UsbBridgeError("--ssid is required for --action wifi-connect/provision-wifi.")
    encryption = args.encryption.strip() or "WPA2-PSK"
    if encryption.upper() not in {"NONE", "OPEN"} and args.wifi_password == "":
        raise UsbBridgeError("--wifi-password is required unless --encryption is NONE or OPEN.")
    data: dict[str, Any] = {"ssid": args.ssid, "password": args.wifi_password, "encryption": encryption}
    if args.no_save:
        data["nosave"] = True
    print(f"Provisioning Wi-Fi over USB: ssid={ssid_label(args)} encryption={encryption} save={str(not args.no_save).lower()}")
    response = bridge.invoke("wifi.connect", data, max(args.timeout_ms, 40000))
    write_response(response, args, redacted=True)
    assert_ok(response, "wifi.connect")
    wait_hub_lan(args)


def install_usb_root_ssh(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    if args.chunk_size < 1024 or args.chunk_size > 12000:
        raise UsbBridgeError("--chunk-size should be between 1024 and 12000 to stay under LTCP limits.")
    ensure_keypair(args)
    assert_usb_preflight_ready(bridge, args)
    install_root_access(bridge, args)

    print("Preparing staged USB root SSH package...")
    package = new_owned_runtime_manifest(args)
    plugin_source = resolve_local_path("rootsshusb.lua")
    plugin_text = plugin_source.read_text(encoding="utf-8")
    plugin_manifest = '{"plugin":"rootsshusb"}\n'

    for directory in ("../../pkg/rootsshusb", "../../data/rootsshusb", "../../data/rootsshusb/chunks"):
        response = command_json_put(bridge, directory, "codex-dir-probe.json", {"created": now_epoch()})
        assert_ok(response, f"create {directory}")

    print("Installing USB root SSH staging plugin...")
    response = command_log_put(bridge, "../pkg/rootsshusb/manifest.json", plugin_manifest)
    assert_ok(response, "write rootsshusb manifest")
    response = command_log_put(bridge, "../pkg/rootsshusb/rootsshusb.lua", plugin_text)
    assert_ok(response, "write rootsshusb plugin")

    stage_files: list[StageFile] = package["stage_files"]
    total_chunks = sum(math.ceil(len(item.data) / args.chunk_size) for item in stage_files)
    sent = 0
    for item in stage_files:
        chunks = math.ceil(len(item.data) / args.chunk_size)
        for index in range(chunks):
            start = index * args.chunk_size
            chunk = item.data[start : start + args.chunk_size]
            remote = f"../data/rootsshusb/chunks/{item.id}.{index + 1}"
            sent += 1
            print(f"Uploading Harmony runtime over USB: {sent}/{total_chunks} chunks {item.path}", flush=True)
            response = command_log_put(bridge, remote, chunk)
            assert_ok(response, f"write chunk {remote}")
        print(f"staged {item.path} bytes={item.bytes} chunks={chunks} md5={item.md5}")

    manifest_json = compact_json(package["manifest"]) + "\n"
    response = command_log_put(bridge, "../data/rootsshusb/manifest.json", manifest_json)
    assert_ok(response, "write USB installer manifest")

    print("Triggering hub-side installer...")
    response = bridge.invoke("harmony.automation?discover", {"gatewayType": "rootsshusb"}, 30000)
    print(f"installer_trigger_code={response_code(response)}")
    time.sleep(2)
    result = command_json_get(bridge, "../../data/rootsshusb", "result.json")
    write_response(result, args)
    test_root_ssh_login(args)


def dry_run(args: argparse.Namespace) -> None:
    sample_data: Any = ""
    command_name = "sys.info"
    timeout_ms = args.timeout_ms
    if args.action == "wifi-status":
        command_name = "wifi.status"
        sample_data = {"donotresolve": 1}
    elif args.action == "wifi-scan":
        command_name = "wifi.networks"
        sample_data = {}
        timeout_ms = max(timeout_ms, 60000)
    elif args.action in {"wifi-connect", "provision-wifi"}:
        command_name = "wifi.connect"
        sample_data = {
            "ssid": args.ssid or "<ssid>",
            "password": "<redacted>",
            "encryption": args.encryption or "WPA2-PSK",
        }
        if args.no_save:
            sample_data["nosave"] = True
        timeout_ms = max(timeout_ms, 40000)
    request = {"id": 123456, "cmd": command_name, "data": sample_data, "timeout": 5}
    frames = new_ltcp_frames(compact_json(request))
    print(pretty_json({"dryRun": True, "action": args.action, "command": command_name, "timeoutMs": timeout_ms, "frameCount": len(frames), "firstFrameHex": hex_string(frames[0])}))


def self_test() -> None:
    request = compact_json({"id": 123456, "cmd": "sys.info", "data": "", "timeout": 5})
    frames = new_ltcp_frames(request)
    assert len(frames) >= 1
    raw = b"".join(frames)
    decoded = decode_ltcp(raw)
    assert decoded.complete, decoded
    assert decoded.payload == request, decoded.payload
    candidates = ltcp_candidates(raw)
    assert candidates and candidates[-1].complete
    print("USB bridge self-test OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Harmony Hub USB HID/LTCP bridge")
    parser.add_argument("--action", choices=ACTION_CHOICES, default="preflight")
    parser.add_argument("--backend", choices=("auto", "hidapi", "hidraw"), default="auto")
    parser.add_argument("--device-path", default="")
    parser.add_argument("--vendor-id", default="046D")
    parser.add_argument("--product-id", default="C129")
    parser.add_argument("--timeout-ms", type=int, default=5000)
    parser.add_argument("--retry-count", type=int, default=2)
    parser.add_argument("--retry-delay-ms", type=int, default=250)
    parser.add_argument("--drain-reports", type=int, default=32)
    parser.add_argument("--drain-wait-ms", type=int, default=40)
    parser.add_argument("--resync-attempts", type=int, default=6)
    parser.add_argument("--raw-output", action="store_true")
    parser.add_argument("--no-drain", action="store_true")
    parser.add_argument("--loose-response-match", action="store_true")
    parser.add_argument("--write-probe", action="store_true")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--public-key-file", default="keys/harmony_root_ed25519.pub")
    parser.add_argument("--private-key-file", default="keys/harmony_root_ed25519")
    parser.add_argument("--hub-ip", default="")
    parser.add_argument("--reboot", action="store_true")
    parser.add_argument("--ssid", default="")
    parser.add_argument("--wifi-password", default="")
    parser.add_argument("--encryption", default="WPA2-PSK")
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--show-ssids", action="store_true")
    parser.add_argument("--wait-for-lan", action="store_true")
    parser.add_argument("--lan-port", type=int, default=8088)
    parser.add_argument("--lan-wait-seconds", type=int, default=90)
    parser.add_argument("--package-root", default=".")
    parser.add_argument("--chunk-size", type=int, default=8000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.self_test:
        self_test()
        return
    if args.dry_run:
        dry_run(args)
        return

    bridge = HarmonyUsbBridge(args)
    if args.action == "probe":
        run_probe(bridge, args)
    elif args.action == "drain":
        run_drain(bridge, args)
    elif args.action == "preflight":
        run_preflight(bridge, args)
    elif args.action == "resync":
        run_resync(bridge, args)
    elif args.action == "stage-summary":
        ensure_keypair(args)
        print(pretty_json(owned_runtime_stage_summary(args)))
    elif args.action == "sysinfo":
        response = bridge.invoke("sys.info", "", args.timeout_ms)
        write_response(response, args)
    elif args.action == "wifi-status":
        run_wifi_status(bridge, args)
    elif args.action == "wifi-scan":
        run_wifi_scan(bridge, args)
    elif args.action in {"wifi-connect", "provision-wifi"}:
        run_wifi_connect(bridge, args)
    elif args.action == "root-ssh":
        install_usb_root_ssh(bridge, args)
    else:
        raise UsbBridgeError(f"Unknown action: {args.action}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("\nInterrupted")
    except (UsbBridgeError, OSError, subprocess.CalledProcessError) as exc:
        print("", file=sys.stderr)
        print("ERROR:", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
