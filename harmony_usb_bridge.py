#!/usr/bin/env python3
"""Cross-platform Harmony Hub USB HID/LTCP bridge.

The Harmony desktop apps talk to the hub as a USB HID device. This script keeps
the transport in userspace: hidapi on macOS/Linux when available, with a Linux
hidraw fallback that uses only Python's standard library.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import ctypes
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
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_VENDOR_ID = 0x046D
DEFAULT_PRODUCT_ID = 0xC129
DEFAULT_INPUT_REPORT_LENGTH = 65
DEFAULT_OUTPUT_REPORT_LENGTH = 65
USB_LOCK_PATH = SCRIPT_DIR / ".harmony_usb_bridge.lock"
RAW_DEVICE_INFO_PATH = "/rf/deviceinfo"
RAW_WIFI_STATUS_PATH = "/sys/wifi/connect"
RAW_WIFI_NETWORKS_PATH = "/sys/wifi/networks"
RAW_WIFI_CONNECT_PATH = "/sys/wifi/connect"
WINDOWS_USB_OWNER_PROCESS_NAMES = {
    "iexplore.exe",
    "logipluginservice.exe",
    "logipluginserviceext.exe",
    "myharmony.exe",
    "silverlight.configuration.exe",
}
ACTION_CHOICES = (
    "probe",
    "drain",
    "preflight",
    "resync",
    "sysinfo",
    "wifi-status",
    "wifi-scan",
    "wifi-connect",
    "provision-wifi",
    "factory-reset",
    "flash-firmware",
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
class RawResponse:
    device_path: str
    command_id: int
    sequence: int
    matched_response: bool
    frames_written: int
    raw_response_length: int
    raw_response_hex: str
    packet_hex: str
    read_reports: list[dict[str, Any]]
    drain: Any


@dataclasses.dataclass
class RawFileRead:
    device_path: str
    remote_path: str
    size: int
    data: bytes
    open_response: RawResponse
    read_responses: list[RawResponse]
    close_response: RawResponse | None


@dataclasses.dataclass
class FirmwareImage:
    name: str
    remote_path: str
    operation_type: str
    data: bytes
    checksum_type: str
    checksum_seed: int
    checksum_offset: int
    checksum_length: int
    checksum_expected: str
    reset: bool


@dataclasses.dataclass
class FirmwareBundle:
    path: pathlib.Path
    intended_skins: list[int]
    images: list[FirmwareImage]


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
    return json.dumps(to_jsonable(obj), indent=2, ensure_ascii=True)


@contextlib.contextmanager
def usb_process_lock() -> Any:
    USB_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with USB_LOCK_PATH.open("a+b") as lock_file:
        lock_file.seek(0)
        lock_file.write(b"\0")
        lock_file.flush()
        if sys.platform.startswith("win"):
            import msvcrt

            lock_file.seek(0)
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise UsbBridgeError("another Harmony USB bridge process is already running; wait for it to finish before starting another USB action.") from exc
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            try:
                import fcntl
            except ImportError:
                yield
                return
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise UsbBridgeError("another Harmony USB bridge process is already running; wait for it to finish before starting another USB action.") from exc
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_descriptor_int(value: str, default: int = 0) -> int:
    text = (value or "").strip()
    if not text:
        return default
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 10)


def find_zip_member(names: list[str], basename: str) -> str:
    wanted = basename.lower()
    matches = [name for name in names if pathlib.PurePosixPath(name).name.lower() == wanted]
    if not matches:
        raise UsbBridgeError(f"{basename} not found in firmware bundle")
    return matches[0]


def parse_hfw2_bundle(path_value: str) -> FirmwareBundle:
    path = resolve_local_path(path_value)
    if not path.is_file():
        raise UsbBridgeError(f"firmware file not found: {path}")
    if path.suffix.lower() != ".hfw2":
        raise UsbBridgeError(f"firmware file should have .hfw2 extension: {path}")

    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise UsbBridgeError(f"firmware file is not a readable .hfw2/zip bundle: {path}") from exc

    with archive:
        names = archive.namelist()
        descriptor_name = find_zip_member(names, "Description.xml")
        descriptor = archive.read(descriptor_name)
        try:
            root = ET.fromstring(descriptor)
        except ET.ParseError as exc:
            raise UsbBridgeError(f"Description.xml is not valid XML in {path}") from exc

        intended_skins: list[int] = []
        for skin in root.findall("./INTENDED/SKIN"):
            if skin.text and skin.text.strip():
                intended_skins.append(parse_descriptor_int(skin.text.strip()))

        files_by_name: dict[str, ET.Element] = {}
        for file_node in root.findall("./FILES/FILE"):
            name = (file_node.get("NAME") or "").strip()
            if name:
                files_by_name[name] = file_node

        images: list[FirmwareImage] = []
        order_nodes = list(root.findall("./ORDER/ORDER_ELEMENT"))
        if not order_nodes:
            order_nodes = [ET.Element("ORDER_ELEMENT", {"NAME": name, "RESET": "true"}) for name in files_by_name]

        for order_node in order_nodes:
            image_name = (order_node.get("NAME") or "").strip()
            if image_name not in files_by_name:
                raise UsbBridgeError(f"ORDER references missing firmware file {image_name!r}")
            file_node = files_by_name[image_name]
            checksum_node = file_node.find("./CHECKSUM")
            if checksum_node is None:
                raise UsbBridgeError(f"{image_name} has no CHECKSUM entry")

            member_name = find_zip_member(names, image_name)
            data = archive.read(member_name)
            checksum_type = (checksum_node.get("TYPE") or "").strip().upper()
            checksum_seed = parse_descriptor_int(checksum_node.get("SEED") or "0")
            checksum_offset = parse_descriptor_int(checksum_node.get("OFFSET") or "0")
            checksum_length = parse_descriptor_int(checksum_node.get("LENGTH") or str(len(data)))
            checksum_expected = (checksum_node.get("EXPECTEDVALUE") or "").strip().lower()
            if checksum_type != "MD5":
                raise UsbBridgeError(f"{image_name} uses unsupported checksum type {checksum_type!r}; expected MD5")
            if checksum_seed != 0:
                raise UsbBridgeError(f"{image_name} uses unsupported checksum seed {checksum_seed}; expected 0")
            if checksum_offset < 0 or checksum_length < 0 or checksum_offset + checksum_length > len(data):
                raise UsbBridgeError(f"{image_name} checksum range is outside the payload")
            actual = md5_bytes(data[checksum_offset : checksum_offset + checksum_length])
            if checksum_expected and actual.lower() != checksum_expected:
                raise UsbBridgeError(f"{image_name} checksum mismatch: expected {checksum_expected}, got {actual}")

            images.append(
                FirmwareImage(
                    name=image_name,
                    remote_path=(file_node.get("PATH") or "").strip(),
                    operation_type=(file_node.get("OPERATIONTYPE") or "").strip(),
                    data=data,
                    checksum_type=checksum_type,
                    checksum_seed=checksum_seed,
                    checksum_offset=checksum_offset,
                    checksum_length=checksum_length,
                    checksum_expected=checksum_expected,
                    reset=(order_node.get("RESET") or "").strip().lower() == "true",
                )
            )

    if not images:
        raise UsbBridgeError(f"no firmware images found in {path}")
    return FirmwareBundle(path=path, intended_skins=intended_skins, images=images)


def firmware_bundle_summary(bundle: FirmwareBundle) -> dict[str, Any]:
    return {
        "path": str(bundle.path),
        "size": bundle.path.stat().st_size,
        "sha256": sha256_bytes(bundle.path.read_bytes()),
        "intendedSkins": bundle.intended_skins,
        "images": [
            {
                "name": image.name,
                "remotePath": image.remote_path,
                "operationType": image.operation_type,
                "bytes": len(image.data),
                "md5": md5_bytes(image.data),
                "checksum": {
                    "type": image.checksum_type,
                    "offset": image.checksum_offset,
                    "length": image.checksum_length,
                    "expected": image.checksum_expected,
                },
                "reset": image.reset,
            }
            for image in bundle.images
        ],
    }


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


class WinGuid(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WinDeviceInterfaceData(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("InterfaceClassGuid", WinGuid),
        ("Flags", ctypes.c_ulong),
        ("Reserved", ctypes.c_void_p),
    ]


class WinHidAttributes(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_ulong),
        ("VendorID", ctypes.c_ushort),
        ("ProductID", ctypes.c_ushort),
        ("VersionNumber", ctypes.c_ushort),
    ]


class WinHidCaps(ctypes.Structure):
    _fields_ = [
        ("Usage", ctypes.c_ushort),
        ("UsagePage", ctypes.c_ushort),
        ("InputReportByteLength", ctypes.c_ushort),
        ("OutputReportByteLength", ctypes.c_ushort),
        ("FeatureReportByteLength", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort * 17),
        ("NumberLinkCollectionNodes", ctypes.c_ushort),
        ("NumberInputButtonCaps", ctypes.c_ushort),
        ("NumberInputValueCaps", ctypes.c_ushort),
        ("NumberInputDataIndices", ctypes.c_ushort),
        ("NumberOutputButtonCaps", ctypes.c_ushort),
        ("NumberOutputValueCaps", ctypes.c_ushort),
        ("NumberOutputDataIndices", ctypes.c_ushort),
        ("NumberFeatureButtonCaps", ctypes.c_ushort),
        ("NumberFeatureValueCaps", ctypes.c_ushort),
        ("NumberFeatureDataIndices", ctypes.c_ushort),
    ]


class WinOverlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.c_ulong),
        ("OffsetHigh", ctypes.c_ulong),
        ("hEvent", ctypes.c_void_p),
    ]


class WindowsHidApi:
    DIGCF_PRESENT = 0x00000002
    DIGCF_DEVICEINTERFACE = 0x00000010
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_FLAG_OVERLAPPED = 0x40000000
    ERROR_NO_MORE_ITEMS = 259
    ERROR_OPERATION_ABORTED = 995
    ERROR_IO_PENDING = 997
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102
    HIDP_STATUS_SUCCESS = 0x00110000

    def __init__(self) -> None:
        if not sys.platform.startswith("win"):
            raise UsbBridgeError("Windows native HID backend is only available on Windows.")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
        self.hid = ctypes.WinDLL("hid", use_last_error=True)
        self._configure()

    def _configure(self) -> None:
        self.hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(WinGuid)]
        self.hid.HidD_GetHidGuid.restype = None
        self.hid.HidD_GetAttributes.argtypes = [ctypes.c_void_p, ctypes.POINTER(WinHidAttributes)]
        self.hid.HidD_GetAttributes.restype = ctypes.c_bool
        self.hid.HidD_SetNumInputBuffers.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.hid.HidD_SetNumInputBuffers.restype = ctypes.c_bool
        self.hid.HidD_FlushQueue.argtypes = [ctypes.c_void_p]
        self.hid.HidD_FlushQueue.restype = ctypes.c_bool
        self.hid.HidD_GetPreparsedData.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self.hid.HidD_GetPreparsedData.restype = ctypes.c_bool
        self.hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
        self.hid.HidD_FreePreparsedData.restype = ctypes.c_bool
        self.hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(WinHidCaps)]
        self.hid.HidP_GetCaps.restype = ctypes.c_ulong

        self.setupapi.SetupDiGetClassDevsW.argtypes = [
            ctypes.POINTER(WinGuid),
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        self.setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
        self.setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(WinGuid),
            ctypes.c_ulong,
            ctypes.POINTER(WinDeviceInterfaceData),
        ]
        self.setupapi.SetupDiEnumDeviceInterfaces.restype = ctypes.c_bool
        self.setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(WinDeviceInterfaceData),
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_void_p,
        ]
        self.setupapi.SetupDiGetDeviceInterfaceDetailW.restype = ctypes.c_bool
        self.setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
        self.setupapi.SetupDiDestroyDeviceInfoList.restype = ctypes.c_bool

        self.kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ]
        self.kernel32.CreateFileW.restype = ctypes.c_void_p
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_bool
        self.kernel32.ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(WinOverlapped),
        ]
        self.kernel32.ReadFile.restype = ctypes.c_bool
        self.kernel32.WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(WinOverlapped),
        ]
        self.kernel32.WriteFile.restype = ctypes.c_bool
        self.kernel32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_bool, ctypes.c_wchar_p]
        self.kernel32.CreateEventW.restype = ctypes.c_void_p
        self.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        self.kernel32.GetOverlappedResult.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(WinOverlapped),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_bool,
        ]
        self.kernel32.GetOverlappedResult.restype = ctypes.c_bool
        self.kernel32.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(WinOverlapped)]
        self.kernel32.CancelIoEx.restype = ctypes.c_bool

    @staticmethod
    def invalid_handle(handle: Any) -> bool:
        return handle is None or handle == 0 or handle == ctypes.c_void_p(-1).value

    def close_handle(self, handle: Any) -> None:
        if not self.invalid_handle(handle):
            self.kernel32.CloseHandle(handle)

    def open_path(self, path: str, desired_access: int, overlapped: bool = True) -> Any:
        flags = self.FILE_FLAG_OVERLAPPED if overlapped else 0
        handle = self.kernel32.CreateFileW(
            path,
            desired_access,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE,
            None,
            self.OPEN_EXISTING,
            flags,
            None,
        )
        if self.invalid_handle(handle):
            raise OSError(ctypes.get_last_error(), f"CreateFileW failed for {path}")
        return handle

    def enumerate(self, vendor_id: int, product_id: int) -> list[DeviceInfo]:
        needle = f"vid_{vendor_id:04x}&pid_{product_id:04x}"
        guid = WinGuid()
        self.hid.HidD_GetHidGuid(ctypes.byref(guid))
        devs = self.setupapi.SetupDiGetClassDevsW(
            ctypes.byref(guid),
            None,
            None,
            self.DIGCF_PRESENT | self.DIGCF_DEVICEINTERFACE,
        )
        if self.invalid_handle(devs):
            raise OSError(ctypes.get_last_error(), "SetupDiGetClassDevsW failed")

        devices: list[DeviceInfo] = []
        try:
            index = 0
            while True:
                iface = WinDeviceInterfaceData()
                iface.cbSize = ctypes.sizeof(WinDeviceInterfaceData)
                ok = self.setupapi.SetupDiEnumDeviceInterfaces(devs, None, ctypes.byref(guid), index, ctypes.byref(iface))
                if not ok:
                    err = ctypes.get_last_error()
                    if err == self.ERROR_NO_MORE_ITEMS:
                        break
                    raise OSError(err, "SetupDiEnumDeviceInterfaces failed")
                index += 1

                required = ctypes.c_ulong(0)
                self.setupapi.SetupDiGetDeviceInterfaceDetailW(devs, ctypes.byref(iface), None, 0, ctypes.byref(required), None)
                if not required.value:
                    continue
                detail = ctypes.create_string_buffer(required.value)
                ctypes.c_ulong.from_buffer(detail).value = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
                ok = self.setupapi.SetupDiGetDeviceInterfaceDetailW(
                    devs,
                    ctypes.byref(iface),
                    ctypes.cast(detail, ctypes.c_void_p),
                    required.value,
                    ctypes.byref(required),
                    None,
                )
                if not ok:
                    continue
                path = ctypes.wstring_at(ctypes.addressof(detail) + 4)
                if needle not in path.lower():
                    continue
                devices.append(self.device_info_from_path(path, vendor_id, product_id))
        finally:
            self.setupapi.SetupDiDestroyDeviceInfoList(devs)
        return devices

    def device_info_from_path(self, path: str, vendor_id: int, product_id: int) -> DeviceInfo:
        try:
            handle = self.open_path(path, 0)
        except OSError:
            return DeviceInfo(backend="winhid", path=path, vendor_id=vendor_id, product_id=product_id)
        try:
            attrs = WinHidAttributes()
            attrs.Size = ctypes.sizeof(WinHidAttributes)
            dev_vendor = vendor_id
            dev_product = product_id
            if self.hid.HidD_GetAttributes(handle, ctypes.byref(attrs)):
                dev_vendor = int(attrs.VendorID)
                dev_product = int(attrs.ProductID)

            input_len = DEFAULT_INPUT_REPORT_LENGTH
            output_len = DEFAULT_OUTPUT_REPORT_LENGTH
            usage_page = None
            usage = None
            prep = ctypes.c_void_p()
            if self.hid.HidD_GetPreparsedData(handle, ctypes.byref(prep)):
                try:
                    caps = WinHidCaps()
                    status = self.hid.HidP_GetCaps(prep, ctypes.byref(caps))
                    if status == self.HIDP_STATUS_SUCCESS:
                        input_len = int(caps.InputReportByteLength) or DEFAULT_INPUT_REPORT_LENGTH
                        output_len = int(caps.OutputReportByteLength) or DEFAULT_OUTPUT_REPORT_LENGTH
                        usage_page = int(caps.UsagePage)
                        usage = int(caps.Usage)
                finally:
                    self.hid.HidD_FreePreparsedData(prep)
            return DeviceInfo(
                backend="winhid",
                path=path,
                vendor_id=dev_vendor,
                product_id=dev_product,
                input_report_length=input_len,
                output_report_length=output_len,
                usage_page=usage_page,
                usage=usage,
            )
        finally:
            self.close_handle(handle)


class WindowsHidHandle(HidHandle):
    def __init__(self, api: WindowsHidApi, path: str) -> None:
        self._api = api
        self._handle = api.open_path(path, api.GENERIC_READ | api.GENERIC_WRITE, overlapped=True)
        api.hid.HidD_SetNumInputBuffers(self._handle, 64)
        api.hid.HidD_FlushQueue(self._handle)

    def _overlapped_io(self, fn: Any, buffer: Any, length: int, timeout_ms: int, label: str) -> int:
        event = self._api.kernel32.CreateEventW(None, True, False, None)
        if self._api.invalid_handle(event):
            raise OSError(ctypes.get_last_error(), "CreateEventW failed")
        overlapped = WinOverlapped()
        overlapped.hEvent = event
        transferred = ctypes.c_ulong(0)
        try:
            ok = fn(self._handle, buffer, length, None, ctypes.byref(overlapped))
            err = ctypes.get_last_error()
            if not ok and err != self._api.ERROR_IO_PENDING:
                raise OSError(err, f"HID overlapped {label} failed")
            if not ok:
                wait = self._api.kernel32.WaitForSingleObject(event, max(1, timeout_ms))
                if wait == self._api.WAIT_TIMEOUT:
                    self._api.kernel32.CancelIoEx(self._handle, ctypes.byref(overlapped))
                    self._api.kernel32.WaitForSingleObject(event, 1000)
                    cancel_ok = self._api.kernel32.GetOverlappedResult(
                        self._handle,
                        ctypes.byref(overlapped),
                        ctypes.byref(transferred),
                        False,
                    )
                    if not cancel_ok:
                        err = ctypes.get_last_error()
                        if err != self._api.ERROR_OPERATION_ABORTED:
                            raise OSError(err, f"cancelled HID overlapped {label} failed")
                    return 0
                if wait != self._api.WAIT_OBJECT_0:
                    raise OSError(ctypes.get_last_error(), f"WaitForSingleObject failed: {wait}")
            ok = self._api.kernel32.GetOverlappedResult(self._handle, ctypes.byref(overlapped), ctypes.byref(transferred), False)
            if not ok:
                raise OSError(ctypes.get_last_error(), "GetOverlappedResult failed")
            return int(transferred.value)
        finally:
            self._api.close_handle(event)

    def write(self, report: bytes) -> None:
        buffer = ctypes.create_string_buffer(report, len(report))
        written = self._overlapped_io(self._api.kernel32.WriteFile, buffer, len(report), 5000, "write")
        if written != len(report):
            raise OSError(f"short HID write: {written}/{len(report)}")

    def read(self, length: int, timeout_ms: int) -> bytes:
        buffer = ctypes.create_string_buffer(length)
        read = self._overlapped_io(self._api.kernel32.ReadFile, buffer, length, timeout_ms, "read")
        if read <= 0:
            return b""
        return bytes(buffer.raw[:read])

    def close(self) -> None:
        self._api.close_handle(self._handle)
        self._handle = None


class WindowsNativeBackend(HidBackend):
    name = "winhid"

    def __init__(self) -> None:
        self._api = WindowsHidApi()

    def enumerate(self, vendor_id: int, product_id: int) -> list[DeviceInfo]:
        return self._api.enumerate(vendor_id, product_id)

    def open(self, device: DeviceInfo) -> HidHandle:
        return WindowsHidHandle(self._api, device.path)


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
    if name == "winhid":
        return [WindowsNativeBackend()]
    backends: list[HidBackend] = []
    try:
        backends.append(HidApiBackend())
    except UsbBridgeError:
        pass
    if sys.platform.startswith("win"):
        try:
            backends.append(WindowsNativeBackend())
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
        raise UsbBridgeError(f"Payload is too large for one LTCP secondary packet ({len(payload)} bytes).")
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


def raw_param_byte(value: int) -> bytes:
    if value < 0 or value > 0xFF:
        raise UsbBridgeError(f"byte parameter out of range: {value}")
    return bytes([0x01, value])


def raw_param_word(value: int) -> bytes:
    if value < 0 or value > 0xFFFF:
        raise UsbBridgeError(f"word parameter out of range: {value}")
    return bytes([0x02, value & 0xFF, (value >> 8) & 0xFF])


def raw_param_dword(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise UsbBridgeError(f"dword parameter out of range: {value}")
    return bytes([0x04, value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF, (value >> 24) & 0xFF])


def raw_param_string(value: str) -> bytes:
    try:
        data = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise UsbBridgeError(f"raw LTCP string parameters must be ASCII: {value!r}") from exc
    if b"\x00" in data:
        raise UsbBridgeError("raw LTCP string parameters cannot contain NUL bytes")
    return b"\x80" + data + b"\x00"


def raw_frames_from_stream(stream: bytes) -> list[bytes]:
    frames: list[bytes] = []
    for offset in range(0, len(stream), 64):
        frame = bytearray(64)
        chunk = stream[offset : offset + 64]
        frame[: len(chunk)] = chunk
        frames.append(bytes(frame))
    return frames


def raw_primary_frames(command_id: int, sequence: int, params: list[bytes], param_count: int | None = None) -> list[bytes]:
    if command_id < 0 or command_id > 0xFF:
        raise UsbBridgeError(f"command id out of range: {command_id}")
    if sequence < 0 or sequence > 0x7F:
        raise UsbBridgeError(f"sequence out of range: {sequence}")
    declared = len(params) if param_count is None else param_count
    if declared < 0 or declared > 0x3F:
        raise UsbBridgeError(f"parameter count out of range: {declared}")
    stream = bytearray([0xFF, command_id, sequence, declared])
    for param in params:
        stream.extend(param)
    return raw_frames_from_stream(bytes(stream))


def raw_data_frames(data: bytes, packet_data_size: int = 62) -> list[bytes]:
    frames: list[bytes] = []
    if packet_data_size <= 0 or packet_data_size > 62:
        raise UsbBridgeError(f"raw data packet size should be 1..62, got {packet_data_size}")
    for offset in range(0, len(data), packet_data_size):
        frame = bytearray(64)
        frame[0] = 0x00
        frame[1] = 0x00
        chunk = data[offset : offset + packet_data_size]
        frame[2 : 2 + len(chunk)] = chunk
        frames.append(bytes(frame))
    if not frames:
        frame = bytearray(64)
        frame[0] = 0x00
        frame[1] = 0x00
        frames.append(bytes(frame))
    return frames


def raw_done_frame() -> bytes:
    frame = bytearray(64)
    frame[0] = 0x7E
    return bytes(frame)


def find_raw_response_offset(raw: bytes, command_id: int, sequence: int) -> int:
    for offset in range(0, max(0, len(raw) - 3)):
        if raw[offset] == 0xFF and raw[offset + 1] == command_id and (raw[offset + 2] & 0x7F) == (sequence & 0x7F):
            return offset
    return -1


def find_raw_response_packet(raw: bytes, command_id: int, sequence: int) -> bytes:
    offset = find_raw_response_offset(raw, command_id, sequence)
    if offset >= 0:
        return raw[offset : offset + 64]
    return b""


class HarmonyUsbBridge:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.vendor_id = parse_hex_int(args.vendor_id)
        self.product_id = parse_hex_int(args.product_id)
        self.next_command_id = random.randint(100000, 899999)
        self.next_raw_sequence = random.randint(1, 0x7E)
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

    def new_raw_sequence(self) -> int:
        sequence = self.next_raw_sequence & 0x7F
        if sequence == 0:
            sequence = 1
        self.next_raw_sequence = (sequence + 1) & 0x7F
        if self.next_raw_sequence == 0:
            self.next_raw_sequence = 1
        return sequence

    def exchange_reports(
        self,
        handle: HidHandle,
        device: DeviceInfo,
        frames: list[bytes],
        read_timeout_ms: int,
        expect_response: bool,
        stop_when: Any,
    ) -> tuple[bytes, list[dict[str, Any]]]:
        if device.output_report_length != DEFAULT_OUTPUT_REPORT_LENGTH:
            raise UsbBridgeError(f"Unexpected output report length {device.output_report_length}; expected 65.")
        for frame in frames:
            if len(frame) != 64:
                raise UsbBridgeError(f"raw HID frame should be 64 bytes, got {len(frame)}")

        raw_response = bytearray()
        read_reports: list[dict[str, Any]] = []
        if not expect_response:
            for frame in frames:
                handle.write(b"\x00" + frame)
            return bytes(raw_response), read_reports

        deadline = time.monotonic() + read_timeout_ms / 1000.0
        if device.backend == "winhid":
            lock = threading.Lock()
            stop = threading.Event()
            started = threading.Event()

            def read_loop() -> None:
                started.set()
                while not stop.is_set() and time.monotonic() < deadline:
                    remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
                    report = handle.read(device.input_report_length, min(remaining_ms, 250))
                    if not report:
                        continue
                    with lock:
                        read_reports.append({"bytesRead": len(report), "hex": hex_string(report)})
                        raw_response.extend(normalize_input_report(report))

            reader = threading.Thread(target=read_loop, name="harmony-usb-read", daemon=True)
            reader.start()
            started.wait(0.25)
            time.sleep(0.02)
            try:
                for frame in frames:
                    handle.write(b"\x00" + frame)
                while time.monotonic() < deadline:
                    with lock:
                        raw_snapshot = bytes(raw_response)
                    if raw_snapshot and stop_when(raw_snapshot):
                        break
                    time.sleep(0.01)
            finally:
                stop.set()
                reader.join(timeout=1.0)
            with lock:
                return bytes(raw_response), list(read_reports)

        for frame in frames:
            handle.write(b"\x00" + frame)
        while time.monotonic() < deadline:
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            report = handle.read(device.input_report_length, remaining_ms)
            if not report:
                break
            read_reports.append({"bytesRead": len(report), "hex": hex_string(report)})
            raw_response.extend(normalize_input_report(report))
            if stop_when(bytes(raw_response)):
                break
        return bytes(raw_response), read_reports

    def raw_exchange(
        self,
        command_id: int,
        frames: list[bytes],
        sequence: int,
        read_timeout_ms: int,
        expect_response: bool = True,
    ) -> RawResponse:
        drain_result = None
        if not self.args.no_drain:
            try:
                drain_result = self.drain()
            except Exception as exc:
                drain_result = {"error": str(exc)}

        handle, device = self.open_handle()
        try:
            return self.raw_exchange_on_handle(handle, device, command_id, frames, sequence, read_timeout_ms, expect_response, drain_result)
        finally:
            handle.close()

    def raw_exchange_on_handle(
        self,
        handle: HidHandle,
        device: DeviceInfo,
        command_id: int,
        frames: list[bytes],
        sequence: int,
        read_timeout_ms: int,
        expect_response: bool = True,
        drain_result: Any = None,
        stop_when: Any | None = None,
    ) -> RawResponse:
        packet = b""
        if stop_when is None:
            stop_when = lambda raw: bool(find_raw_response_packet(raw, command_id, sequence))
        raw_response, read_reports = self.exchange_reports(
            handle,
            device,
            frames,
            read_timeout_ms,
            expect_response,
            stop_when,
        )
        if expect_response and not packet:
            packet = find_raw_response_packet(raw_response, command_id, sequence)
        return RawResponse(
            device_path=device.path,
            command_id=command_id,
            sequence=sequence,
            matched_response=bool(packet) if expect_response else True,
            frames_written=len(frames),
            raw_response_length=len(raw_response),
            raw_response_hex=hex_string(raw_response),
            packet_hex=hex_string(packet),
            read_reports=read_reports,
            drain=drain_result,
        )

    def raw_command(
        self,
        command_id: int,
        params: list[bytes],
        read_timeout_ms: int,
        param_count: int | None = None,
        expect_response: bool = True,
    ) -> RawResponse:
        sequence = self.new_raw_sequence()
        frames = raw_primary_frames(command_id, sequence, params, param_count)
        return self.raw_exchange(command_id, frames, sequence, read_timeout_ms, expect_response)

    def raw_command_on_handle(
        self,
        handle: HidHandle,
        device: DeviceInfo,
        command_id: int,
        params: list[bytes],
        read_timeout_ms: int,
        param_count: int | None = None,
        expect_response: bool = True,
        stop_when: Any | None = None,
    ) -> RawResponse:
        sequence = self.new_raw_sequence()
        frames = raw_primary_frames(command_id, sequence, params, param_count)
        return self.raw_exchange_on_handle(handle, device, command_id, frames, sequence, read_timeout_ms, expect_response, None, stop_when)

    def raw_write_data(
        self,
        handle_id: int,
        data: bytes,
        read_timeout_ms: int,
        packets_per_chunk: int = 500,
        include_done: bool = False,
        label: str = "file",
        packet_count_width: str = "word",
    ) -> list[RawResponse]:
        handle, device = self.open_handle()
        try:
            return self.raw_write_data_on_handle(handle, device, handle_id, data, read_timeout_ms, packets_per_chunk, include_done, label, packet_count_width)
        finally:
            handle.close()

    def raw_write_data_on_handle(
        self,
        handle: HidHandle,
        device: DeviceInfo,
        handle_id: int,
        data: bytes,
        read_timeout_ms: int,
        packets_per_chunk: int = 500,
        include_done: bool = False,
        label: str = "file",
        packet_count_width: str = "word",
    ) -> list[RawResponse]:
        if packets_per_chunk <= 0 or packets_per_chunk > 0xFFFF:
            raise UsbBridgeError(f"packets_per_chunk out of range: {packets_per_chunk}")
        if packet_count_width not in {"byte", "word"}:
            raise UsbBridgeError(f"packet_count_width should be 'byte' or 'word', got {packet_count_width!r}")
        packet_data_size = 62
        chunk_size = packet_data_size * packets_per_chunk
        responses: list[RawResponse] = []
        total = max(1, math.ceil(len(data) / chunk_size))
        for index, offset in enumerate(range(0, len(data), chunk_size), start=1):
            chunk = data[offset : offset + chunk_size]
            data_packets = raw_data_frames(chunk, packet_data_size)
            packet_count = len(data_packets) + (1 if include_done else 0)
            sequence = self.new_raw_sequence()
            count_param = raw_param_byte(packet_count) if packet_count_width == "byte" else raw_param_word(packet_count)
            frames = raw_primary_frames(0x03, sequence, [raw_param_byte(handle_id), count_param])
            frames.extend(data_packets)
            if include_done:
                frames.append(raw_done_frame())
            print(f"Writing {label}: chunk {index}/{total} bytes={len(chunk)} packets={packet_count}", flush=True)
            response = self.raw_exchange_on_handle(handle, device, 0x03, frames, sequence, read_timeout_ms, expect_response=True)
            assert_raw_ok(response, f"write {label} chunk {index}/{total}")
            responses.append(response)
        return responses

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
            selected: Candidate | None = None
            candidates: list[Candidate] = []
            handle, device = self.open_handle()
            try:
                raw_response, read_reports = self.exchange_reports(
                    handle,
                    device,
                    frames,
                    read_timeout_ms,
                    True,
                    lambda raw: candidate_matches(
                        select_ltcp_candidate(ltcp_candidates(raw), request_id, self.args.loose_response_match),
                        request_id,
                        self.args.loose_response_match,
                    ),
                )
            finally:
                handle.close()

            if not selected:
                candidates = ltcp_candidates(raw_response)
                selected = select_ltcp_candidate(candidates, request_id, self.args.loose_response_match)

            decode = selected.decode if selected else decode_ltcp(raw_response)
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
                raw_response_hex=hex_string(raw_response),
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


def assert_raw_ok(response: RawResponse, what: str) -> None:
    if not response.matched_response:
        raise UsbBridgeError(
            f"{what} did not return the expected raw LTCP response "
            f"(cmd=0x{response.command_id:02X}, seq=0x{response.sequence:02X}, raw={response.raw_response_hex})"
        )
    packet = bytes.fromhex(response.packet_hex) if response.packet_hex else b""
    if len(packet) >= 3 and packet[2] == 0xFF:
        raise UsbBridgeError(f"{what} returned raw LTCP error packet: {response.packet_hex}")


def raw_file_handle(response: RawResponse, what: str) -> int:
    assert_raw_ok(response, what)
    packet = bytes.fromhex(response.packet_hex)
    if len(packet) <= 5:
        raise UsbBridgeError(f"{what} response did not contain a file handle: {response.packet_hex}")
    return packet[5]


def raw_file_size(response: RawResponse, what: str) -> int:
    assert_raw_ok(response, what)
    packet = bytes.fromhex(response.packet_hex)
    if len(packet) <= 10:
        return 0
    return int.from_bytes(packet[7:11], "big")


def raw_primary_packet_length(raw: bytes, offset: int) -> int:
    if offset + 4 > len(raw):
        return 0
    pos = offset + 4
    param_count = raw[offset + 3] & 0x3F
    for _ in range(param_count):
        if pos >= len(raw):
            return 0
        tag = raw[pos]
        pos += 1
        length = tag & 0x3F
        if length == 0:
            while pos < len(raw) and raw[pos] != 0:
                pos += 1
            if pos >= len(raw):
                return 0
            pos += 1
        else:
            pos += length
            if pos > len(raw):
                return 0
    return pos - offset


def raw_read_payload(raw: bytes, max_bytes: int, command_id: int = 0x04, sequence: int | None = None) -> tuple[bytes, bool]:
    data = bytearray()
    saw_end = False
    pos = 0
    if sequence is not None:
        response_offset = find_raw_response_offset(raw, command_id, sequence)
        if response_offset < 0:
            return b"", False
        response_length = raw_primary_packet_length(raw, response_offset)
        if response_length <= 0:
            return b"", False
        pos = response_offset + response_length

    while pos < len(raw):
        while pos < len(raw) and raw[pos] == 0:
            pos += 1
        if pos >= len(raw):
            break
        if raw[pos] == 0xFE:
            saw_end = True
            break
        if raw[pos] == 0xFF:
            packet_length = raw_primary_packet_length(raw, pos)
            pos += packet_length if packet_length > 0 else 1
            continue
        if pos + 2 > len(raw):
            break
        if max_bytes and len(data) >= max_bytes:
            break
        remaining = max_bytes - len(data) if max_bytes else 62
        size = raw[pos + 1] & 0x3F
        if size == 0:
            size = min(62, remaining)
        take = min(size, remaining)
        if pos + 2 + take > len(raw):
            break
        data.extend(raw[pos + 2 : pos + 2 + take])
        pos += 2 + size
    return bytes(data), saw_end


def raw_read_complete(raw: bytes, command_id: int, sequence: int, wanted_bytes: int) -> bool:
    if not find_raw_response_packet(raw, command_id, sequence):
        return False
    data, saw_end = raw_read_payload(raw, wanted_bytes, command_id, sequence)
    return saw_end or len(data) >= wanted_bytes


def raw_open_read_file_on_handle(
    bridge: HarmonyUsbBridge,
    handle: HidHandle,
    device: DeviceInfo,
    remote_path: str,
    timeout_ms: int = 40000,
) -> tuple[int, int, RawResponse]:
    response = bridge.raw_command_on_handle(handle, device, 0x01, [raw_param_string(remote_path), raw_param_string("R")], timeout_ms)
    handle_id = raw_file_handle(response, f"open {remote_path}")
    size = raw_file_size(response, f"open {remote_path}")
    return handle_id, size, response


def raw_open_write_file_on_handle(
    bridge: HarmonyUsbBridge,
    handle: HidHandle,
    device: DeviceInfo,
    remote_path: str,
    size: int | None,
    timeout_ms: int = 40000,
) -> int:
    params = [raw_param_string(remote_path), raw_param_string("W")]
    param_count = 3
    if size is not None:
        params.append(raw_param_dword(size))
    response = bridge.raw_command_on_handle(handle, device, 0x01, params, timeout_ms, param_count=param_count)
    handle_id = raw_file_handle(response, f"open {remote_path}")
    print(f"Opened {remote_path}: handle={handle_id}", flush=True)
    return handle_id


def raw_open_write_file(bridge: HarmonyUsbBridge, remote_path: str, size: int | None, timeout_ms: int = 40000) -> int:
    handle, device = bridge.open_handle()
    try:
        return raw_open_write_file_on_handle(bridge, handle, device, remote_path, size, timeout_ms)
    finally:
        handle.close()


def raw_close_file_on_handle(
    bridge: HarmonyUsbBridge,
    handle: HidHandle,
    device: DeviceInfo,
    handle_id: int,
    label: str,
    timeout_ms: int = 30000,
) -> RawResponse:
    response = bridge.raw_command_on_handle(handle, device, 0x07, [raw_param_byte(handle_id)], timeout_ms)
    assert_raw_ok(response, f"close {label}")
    print(f"Closed {label}", flush=True)
    return response


def raw_close_file(bridge: HarmonyUsbBridge, handle_id: int, label: str, timeout_ms: int = 30000) -> RawResponse:
    handle, device = bridge.open_handle()
    try:
        return raw_close_file_on_handle(bridge, handle, device, handle_id, label, timeout_ms)
    finally:
        handle.close()


def raw_read_file_on_handle(
    bridge: HarmonyUsbBridge,
    handle: HidHandle,
    device: DeviceInfo,
    remote_path: str,
    packets_per_read: int,
    open_timeout_ms: int = 40000,
    read_timeout_ms: int = 25000,
    close_timeout_ms: int = 30000,
    max_bytes: int = 1024 * 1024,
) -> RawFileRead:
    if packets_per_read <= 0 or packets_per_read > 255:
        raise UsbBridgeError(f"packets_per_read out of range: {packets_per_read}")
    handle_id, size, open_response = raw_open_read_file_on_handle(bridge, handle, device, remote_path, open_timeout_ms)
    if size > max_bytes:
        raise UsbBridgeError(f"{remote_path} reports {size} bytes, refusing to read more than {max_bytes}.")
    data = bytearray()
    read_responses: list[RawResponse] = []
    close_response: RawResponse | None = None
    try:
        while len(data) < size:
            wanted = min(size - len(data), packets_per_read * 62)
            sequence = bridge.new_raw_sequence()
            frames = raw_primary_frames(0x04, sequence, [raw_param_byte(handle_id), raw_param_byte(packets_per_read)])
            response = bridge.raw_exchange_on_handle(
                handle,
                device,
                0x04,
                frames,
                sequence,
                read_timeout_ms,
                True,
                None,
                lambda raw, sequence=sequence, wanted=wanted: raw_read_complete(raw, 0x04, sequence, wanted),
            )
            assert_raw_ok(response, f"read {remote_path}")
            chunk, saw_end = raw_read_payload(bytes.fromhex(response.raw_response_hex), wanted, 0x04, sequence)
            if not chunk and not saw_end:
                raise UsbBridgeError(f"read {remote_path} returned no data before EOF.")
            data.extend(chunk)
            read_responses.append(response)
            if saw_end:
                break
    finally:
        close_response = raw_close_file_on_handle(bridge, handle, device, handle_id, remote_path, close_timeout_ms)
    return RawFileRead(
        device_path=device.path,
        remote_path=remote_path,
        size=size,
        data=bytes(data[:size]),
        open_response=open_response,
        read_responses=read_responses,
        close_response=close_response,
    )


def raw_read_file(bridge: HarmonyUsbBridge, remote_path: str, packets_per_read: int, read_timeout_ms: int = 25000) -> RawFileRead:
    handle, device = bridge.open_handle()
    try:
        return raw_read_file_on_handle(bridge, handle, device, remote_path, packets_per_read, read_timeout_ms=read_timeout_ms)
    finally:
        handle.close()


def raw_devctrl_checksum_on_handle(
    bridge: HarmonyUsbBridge,
    handle: HidHandle,
    device: DeviceInfo,
    handle_id: int,
    image: FirmwareImage,
    timeout_ms: int = 30000,
) -> RawResponse:
    response = bridge.raw_command_on_handle(
        handle,
        device,
        0x06,
        [
            raw_param_byte(handle_id),
            raw_param_byte(0x01),
            raw_param_string(image.checksum_type),
            raw_param_word(image.checksum_seed),
            raw_param_dword(image.checksum_offset),
            raw_param_dword(image.checksum_length),
            raw_param_string(image.checksum_expected),
        ],
        timeout_ms,
    )
    assert_raw_ok(response, f"checksum {image.name}")
    packet = bytes.fromhex(response.packet_hex)
    if len(packet) <= 7 or packet[7] != ord("m"):
        raise UsbBridgeError(f"checksum {image.name} did not return match marker 'm': {response.packet_hex}")
    print(f"Checksum OK for {image.name}", flush=True)
    return response


def raw_devctrl_checksum(bridge: HarmonyUsbBridge, handle_id: int, image: FirmwareImage, timeout_ms: int = 30000) -> RawResponse:
    handle, device = bridge.open_handle()
    try:
        return raw_devctrl_checksum_on_handle(bridge, handle, device, handle_id, image, timeout_ms)
    finally:
        handle.close()


def raw_flush_firmware_on_handle(
    bridge: HarmonyUsbBridge,
    handle: HidHandle,
    device: DeviceInfo,
    handle_id: int,
    image_name: str,
    timeout_ms: int = 30000,
) -> RawResponse:
    response = bridge.raw_command_on_handle(handle, device, 0x05, [raw_param_byte(handle_id), raw_param_byte(0x00)], timeout_ms)
    assert_raw_ok(response, f"commit firmware {image_name}")
    print(f"Committed firmware {image_name}", flush=True)
    return response


def raw_flush_firmware(bridge: HarmonyUsbBridge, handle_id: int, image_name: str, timeout_ms: int = 30000) -> RawResponse:
    handle, device = bridge.open_handle()
    try:
        return raw_flush_firmware_on_handle(bridge, handle, device, handle_id, image_name, timeout_ms)
    finally:
        handle.close()


def raw_reset_filesystem_on_handle(
    bridge: HarmonyUsbBridge,
    handle: HidHandle,
    device: DeviceInfo,
    timeout_ms: int = 30000,
) -> RawResponse:
    response = bridge.raw_command_on_handle(handle, device, 0xFF, [raw_param_byte(0x66)], timeout_ms)
    assert_raw_ok(response, "reset firmware staging filesystem")
    packet = bytes.fromhex(response.packet_hex)
    if len(packet) <= 3 or packet[3] != 0x00:
        raise UsbBridgeError(f"reset firmware staging filesystem returned unexpected packet: {response.packet_hex}")
    print("Reset firmware staging filesystem", flush=True)
    return response


def raw_reset_filesystem(bridge: HarmonyUsbBridge, timeout_ms: int = 30000) -> RawResponse:
    handle, device = bridge.open_handle()
    try:
        return raw_reset_filesystem_on_handle(bridge, handle, device, timeout_ms)
    finally:
        handle.close()


def raw_reboot_device_on_handle(bridge: HarmonyUsbBridge, handle: HidHandle, device: DeviceInfo) -> RawResponse:
    sequence = bridge.new_raw_sequence()
    frames = raw_primary_frames(0xFF, sequence, [raw_param_byte(0x00)])
    response = bridge.raw_exchange_on_handle(handle, device, 0xFF, frames, sequence, 2000, expect_response=False)
    print("Sent reboot command", flush=True)
    return response


def raw_reboot_device(bridge: HarmonyUsbBridge) -> RawResponse:
    handle, device = bridge.open_handle()
    try:
        return raw_reboot_device_on_handle(bridge, handle, device)
    finally:
        handle.close()


def decode_raw_text(data: bytes) -> str:
    return data.rstrip(b"\x00").decode("utf-8", errors="replace")


def parse_property_lines(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip("\x00")
        if not line:
            continue
        if "," in line:
            key, value = line.split(",", 1)
        elif "=" in line:
            key, value = line.split("=", 1)
        else:
            key, value = line, ""
        rows.append({"key": key.strip(), "value": value.strip()})
    return rows


def property_map(rows: list[dict[str, str]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for row in rows:
        key = row["key"]
        value = row["value"]
        if key in out:
            if not isinstance(out[key], list):
                out[key] = [out[key]]
            out[key].append(value)
        else:
            out[key] = value
    return out


def redact_property_rows(rows: list[dict[str, str]], show_ssids: bool = False) -> list[dict[str, str]]:
    redacted = []
    for row in rows:
        key = row["key"]
        value = row["value"]
        low = key.lower()
        if low in {"password", "passphrase", "psk", "key"}:
            value = "<redacted>"
        elif low == "ssid" and not show_ssids:
            value = "<ssid>"
        redacted.append({"key": key, "value": value})
    return redacted


def raw_file_summary(read: RawFileRead, show_ssids: bool = False) -> dict[str, Any]:
    text = decode_raw_text(read.data)
    rows = parse_property_lines(text)
    mapped = property_map(rows)
    return {
        "remotePath": read.remote_path,
        "reportedSize": read.size,
        "bytesRead": len(read.data),
        "properties": redact(mapped, show_ssids),
        "lines": redact_property_rows(rows, show_ssids),
        "rawText": text if show_ssids else "<hidden; pass --show-ssids to print raw text>",
    }


def wifi_connect_payload(args: argparse.Namespace) -> bytes:
    encryption = args.encryption.strip() or "WPA2-PSK"
    rows = [
        ("ssid", args.ssid.strip()),
        ("password", args.wifi_password),
        ("encryption", encryption),
    ]
    if args.no_save:
        rows.append(("nosave", "true"))
    text = "".join(f"{key},{value}\n" for key, value in rows)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise UsbBridgeError("Wi-Fi properties could not be encoded as UTF-8.") from exc


def command_log_put(bridge: HarmonyUsbBridge, file_name: str, body: str) -> Response:
    return bridge.invoke("harmony.log?put", {"resource": [{"fileName": file_name, "data": body}]})


def redact(obj: Any, show_ssids: bool = False, name: str = "") -> Any:
    low = name.lower()
    if low in {"password", "passphrase", "psk", "key"}:
        if isinstance(obj, list):
            return ["<redacted>" for _ in obj]
        return "<redacted>"
    if low == "ssid" and not show_ssids:
        if isinstance(obj, list):
            return ["<ssid>" for _ in obj]
        return "<ssid>"
    if isinstance(obj, dict):
        return {str(k): redact(v, show_ssids, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, show_ssids, name) for v in obj]
    return obj


def response_summary(response: Response, raw_output: bool = False, show_ssids: bool = False) -> Any:
    payload = redact(response.payload_object, show_ssids) if show_ssids or response.payload_object else response.payload_object
    if raw_output or not response.payload_object:
        summary = {
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
        hint = empty_hid_read_hint(response)
        if hint:
            summary["windowsHidHint"] = hint
        return summary
    return payload


def write_response(response: Response, args: argparse.Namespace, redacted: bool = False) -> None:
    payload = response_summary(response, args.raw_output, args.show_ssids if redacted else True)
    if redacted and not args.show_ssids:
        payload = redact(payload, False)
    print(pretty_json(payload))


def windows_usb_owner_processes() -> list[str]:
    if not sys.platform.startswith("win"):
        return []
    try:
        proc = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []

    names: set[str] = set()
    for row in csv.reader(proc.stdout.splitlines()):
        if not row:
            continue
        name = row[0].strip().lower()
        if name in WINDOWS_USB_OWNER_PROCESS_NAMES:
            names.add(row[0].strip())
    return sorted(names, key=str.lower)


def empty_hid_read_hint(response: Response) -> dict[str, Any] | None:
    if not sys.platform.startswith("win"):
        return None
    if response.raw_response_length or response.read_reports:
        return None

    owners = windows_usb_owner_processes()
    hint: dict[str, Any] = {
        "message": "The hub opened over USB, but no HID input reports came back. Close MyHarmony, Edge IE-mode recovery pages, Internet Explorer, and Logitech plugin services, then reconnect the hub USB cable.",
    }
    if owners:
        hint["possibleUsbOwnerProcesses"] = owners
    return hint


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


def run_probe(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    devices = bridge.enumerate_devices()
    print(pretty_json([to_jsonable(device) for device in devices]))


def run_drain(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    _, device = bridge.get_device()
    result = bridge.drain()
    print(pretty_json({"devicePath": device.path, "reports": result["reports"], "samples": result["samples"]}))


def run_preflight(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    _, device = bridge.get_device()
    sysinfo = raw_read_file(bridge, RAW_DEVICE_INFO_PATH, 50, max(args.timeout_ms, 25000))
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
        "sysinfo": raw_file_summary(sysinfo, args.show_ssids),
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
        sysinfo = raw_read_file(bridge, RAW_DEVICE_INFO_PATH, 50, max(args.timeout_ms, 25000))
        summary = {
            "complete": len(sysinfo.data) == sysinfo.size,
            "remotePath": sysinfo.remote_path,
            "reportedSize": sysinfo.size,
            "bytesRead": len(sysinfo.data),
            "readCommands": len(sysinfo.read_responses),
            "outerAttempt": outer,
        }
        results.append(summary)
        if len(sysinfo.data) == sysinfo.size:
            print(pretty_json({"ok": True, "outerAttempts": outer, "sysinfo": raw_file_summary(sysinfo, args.show_ssids), "results": results}))
            return
        if outer < args.resync_attempts:
            time.sleep(max(0.1, args.retry_delay_ms / 1000.0))
    print(pretty_json({"ok": False, "outerAttempts": args.resync_attempts, "results": results}))


def run_wifi_status(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    read = raw_read_file(bridge, RAW_WIFI_STATUS_PATH, 50, max(args.timeout_ms, 25000))
    print(pretty_json(raw_file_summary(read, args.show_ssids)))


def run_wifi_scan(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    read = raw_read_file(bridge, RAW_WIFI_NETWORKS_PATH, 100, max(args.timeout_ms, 60000))
    print(pretty_json(raw_file_summary(read, args.show_ssids)))


def ssid_label(args: argparse.Namespace) -> str:
    return args.ssid if args.show_ssids else "<ssid>"


def run_wifi_connect(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    if not args.ssid.strip():
        raise UsbBridgeError("--ssid is required for --action wifi-connect/provision-wifi.")
    encryption = args.encryption.strip() or "WPA2-PSK"
    if encryption.upper() not in {"NONE", "OPEN"} and args.wifi_password == "":
        raise UsbBridgeError("--wifi-password is required unless --encryption is NONE or OPEN.")
    print(f"Provisioning Wi-Fi over USB: ssid={ssid_label(args)} encryption={encryption} save={str(not args.no_save).lower()}")
    payload = wifi_connect_payload(args)
    handle, device = bridge.open_handle()
    try:
        handle_id = raw_open_write_file_on_handle(bridge, handle, device, RAW_WIFI_CONNECT_PATH, len(payload), 60000)
        bridge.raw_write_data_on_handle(handle, device, handle_id, payload, max(args.timeout_ms, 100000), packets_per_chunk=50, packet_count_width="byte", label=RAW_WIFI_CONNECT_PATH)
        raw_close_file_on_handle(bridge, handle, device, handle_id, RAW_WIFI_CONNECT_PATH, 30000)
    finally:
        handle.close()
    print(pretty_json({"ok": True, "action": "provision-wifi", "remotePath": RAW_WIFI_CONNECT_PATH, "bytesWritten": len(payload), "ssid": ssid_label(args), "encryption": encryption}))
    wait_hub_lan(args)


def require_destructive_confirmation(args: argparse.Namespace, label: str) -> None:
    if args.dry_run or args.yes:
        return
    print("")
    print(label)
    print("This changes the hub over USB and can interrupt normal operation.")
    answer = input("Type YES to continue: ").strip()
    if answer != "YES":
        raise UsbBridgeError("cancelled")


def run_factory_reset(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    if args.dry_run:
        print(pretty_json({"dryRun": True, "action": "factory-reset", "steps": ["write /sys/factoryreset", "write /sys/reboot"]}))
        return

    require_destructive_confirmation(args, "Factory reset will erase the hub's local configuration and reboot it.")

    handle, device = bridge.open_handle()
    try:
        handle_id = raw_open_write_file_on_handle(bridge, handle, device, "/sys/factoryreset", None)
        bridge.raw_write_data_on_handle(handle, device, handle_id, b"1", 180000, packets_per_chunk=5, include_done=False, label="/sys/factoryreset")
        raw_close_file_on_handle(bridge, handle, device, handle_id, "/sys/factoryreset")

        handle_id = raw_open_write_file_on_handle(bridge, handle, device, "/sys/reboot", None)
        bridge.raw_write_data_on_handle(handle, device, handle_id, b"reboot", 180000, packets_per_chunk=5, include_done=False, label="/sys/reboot")
        raw_close_file_on_handle(bridge, handle, device, handle_id, "/sys/reboot", timeout_ms=180000)
    finally:
        handle.close()

    print(pretty_json({"ok": True, "action": "factory-reset", "reboot": True}))


def run_flash_firmware(bridge: HarmonyUsbBridge, args: argparse.Namespace) -> None:
    if not args.firmware_file.strip():
        raise UsbBridgeError("--firmware-file is required for --action flash-firmware.")
    bundle = parse_hfw2_bundle(args.firmware_file)
    summary = firmware_bundle_summary(bundle)
    if args.dry_run:
        print(pretty_json({"dryRun": True, "action": "flash-firmware", "bundle": summary}))
        return

    for image in bundle.images:
        if image.operation_type.lower() != "firmwareupgrade":
            raise UsbBridgeError(f"{image.name} has unsupported operation type {image.operation_type!r}")
        if not image.remote_path:
            raise UsbBridgeError(f"{image.name} has no remote PATH in Description.xml")

    require_destructive_confirmation(args, f"Firmware flash will write {bundle.path.name} to the hub and reboot it when requested by the bundle.")

    print(pretty_json({"validatedFirmware": summary}))
    handle, device = bridge.open_handle()
    try:
        raw_reset_filesystem_on_handle(bridge, handle, device)
        for image in bundle.images:
            print(f"Flashing {image.name} to {image.remote_path} ({len(image.data)} bytes)", flush=True)
            handle_id = raw_open_write_file_on_handle(bridge, handle, device, image.remote_path, len(image.data))
            bridge.raw_write_data_on_handle(
                handle,
                device,
                handle_id,
                image.data,
                30000,
                packets_per_chunk=args.firmware_packets_per_chunk,
                include_done=True,
                label=image.name,
            )
            raw_devctrl_checksum_on_handle(bridge, handle, device, handle_id, image)
            raw_flush_firmware_on_handle(bridge, handle, device, handle_id, image.name)
            raw_close_file_on_handle(bridge, handle, device, handle_id, image.name)

        if any(image.reset for image in bundle.images):
            raw_reboot_device_on_handle(bridge, handle, device)
    finally:
        handle.close()
    print(pretty_json({"ok": True, "action": "flash-firmware", "images": [image.name for image in bundle.images], "reboot": any(image.reset for image in bundle.images)}))


def dry_run(args: argparse.Namespace) -> None:
    if args.action == "factory-reset":
        print(pretty_json({"dryRun": True, "action": "factory-reset", "steps": ["write /sys/factoryreset", "write /sys/reboot"]}))
        return
    if args.action == "flash-firmware":
        if not args.firmware_file.strip():
            raise UsbBridgeError("--firmware-file is required for --action flash-firmware.")
        bundle = parse_hfw2_bundle(args.firmware_file)
        print(pretty_json({"dryRun": True, "action": "flash-firmware", "bundle": firmware_bundle_summary(bundle)}))
        return

    raw_action_paths = {
        "preflight": RAW_DEVICE_INFO_PATH,
        "resync": RAW_DEVICE_INFO_PATH,
        "sysinfo": RAW_DEVICE_INFO_PATH,
        "wifi-status": RAW_WIFI_STATUS_PATH,
        "wifi-scan": RAW_WIFI_NETWORKS_PATH,
    }
    if args.action in raw_action_paths:
        print(pretty_json({"dryRun": True, "action": args.action, "protocol": "raw-file", "remotePath": raw_action_paths[args.action], "steps": ["open", "read", "close"]}))
        return
    if args.action in {"wifi-connect", "provision-wifi"}:
        payload = wifi_connect_payload(args) if args.ssid else b"ssid,<ssid>\npassword,<redacted>\nencryption,WPA2-PSK\n"
        print(pretty_json({"dryRun": True, "action": args.action, "protocol": "raw-file", "remotePath": RAW_WIFI_CONNECT_PATH, "steps": ["open", "write", "close"], "bytes": len(payload)}))
        return

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
    assert raw_param_string("R") == b"\x80R\x00"
    assert raw_param_word(0x1234) == b"\x02\x34\x12"
    assert raw_param_dword(0x12345678) == b"\x04\x78\x56\x34\x12"
    open_frames = raw_primary_frames(0x01, 0x22, [raw_param_string("/fw/otaupdate"), raw_param_string("W"), raw_param_dword(1234)])
    assert len(open_frames) == 1
    assert open_frames[0][:4] == bytes([0xFF, 0x01, 0x22, 0x03])
    write_frames = raw_primary_frames(0x03, 0x23, [raw_param_byte(1), raw_param_word(2)])
    write_frames.extend(raw_data_frames(b"abc"))
    write_frames.append(raw_done_frame())
    assert len(write_frames) == 3
    assert write_frames[0][:4] == bytes([0xFF, 0x03, 0x23, 0x02])
    print("USB bridge self-test OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Harmony Hub USB HID/LTCP bridge")
    parser.add_argument("--action", choices=ACTION_CHOICES, default="preflight")
    parser.add_argument("--backend", choices=("auto", "hidapi", "hidraw", "winhid"), default="auto")
    parser.add_argument("--device-path", default="")
    parser.add_argument("--vendor-id", default="046D")
    parser.add_argument("--product-id", default="C129")
    parser.add_argument("--timeout-ms", type=int, default=12000)
    parser.add_argument("--retry-count", type=int, default=2)
    parser.add_argument("--retry-delay-ms", type=int, default=250)
    parser.add_argument("--drain-reports", type=int, default=32)
    parser.add_argument("--drain-wait-ms", type=int, default=40)
    parser.add_argument("--resync-attempts", type=int, default=6)
    parser.add_argument("--raw-output", action="store_true")
    parser.add_argument("--no-drain", action="store_true")
    parser.add_argument("--loose-response-match", action="store_true")
    parser.add_argument("--write-probe", action="store_true")
    parser.add_argument("--hub-ip", default="")
    parser.add_argument("--ssid", default="")
    parser.add_argument("--wifi-password", default="")
    parser.add_argument("--encryption", default="WPA2-PSK")
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--show-ssids", action="store_true")
    parser.add_argument("--wait-for-lan", action="store_true")
    parser.add_argument("--lan-port", type=int, default=8088)
    parser.add_argument("--lan-wait-seconds", type=int, default=90)
    parser.add_argument("--firmware-file", default="")
    parser.add_argument("--target-skin", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--firmware-packets-per-chunk", type=int, default=500)
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def run_action(args: argparse.Namespace) -> None:
    bridge = HarmonyUsbBridge(args)
    if args.action == "probe":
        run_probe(bridge, args)
    elif args.action == "drain":
        run_drain(bridge, args)
    elif args.action == "preflight":
        run_preflight(bridge, args)
    elif args.action == "resync":
        run_resync(bridge, args)
    elif args.action == "sysinfo":
        read = raw_read_file(bridge, RAW_DEVICE_INFO_PATH, 50, max(args.timeout_ms, 25000))
        print(pretty_json(raw_file_summary(read, args.show_ssids)))
    elif args.action == "wifi-status":
        run_wifi_status(bridge, args)
    elif args.action == "wifi-scan":
        run_wifi_scan(bridge, args)
    elif args.action in {"wifi-connect", "provision-wifi"}:
        run_wifi_connect(bridge, args)
    elif args.action == "factory-reset":
        run_factory_reset(bridge, args)
    elif args.action == "flash-firmware":
        run_flash_firmware(bridge, args)
    else:
        raise UsbBridgeError(f"Unknown action: {args.action}")


def main() -> None:
    args = parse_args()
    if args.self_test:
        self_test()
        return
    if args.dry_run:
        dry_run(args)
        return

    with usb_process_lock():
        run_action(args)


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
