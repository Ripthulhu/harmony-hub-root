"""Offline regressions only: these tests never connect to a hub."""

import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock
import zipfile

import harmony_usb_bridge as usb
import harmony_xmpp_root_shell as lan
import run_harmony_hub_tool as tool


class FakeSocket:
    def __init__(self, *chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False

    def recv(self, size):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        self.chunks.insert(0, chunk[size:]) if len(chunk) > size else None
        return chunk[:size]

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        pass

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def ws_frame(data, opcode=1, final=True):
    first = opcode | (0x80 if final else 0)
    length = len(data)
    header = bytes([first, length]) if length < 126 else struct.pack("!BBH", first, 126, length)
    return header + data


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.network = patch("socket.create_connection", side_effect=AssertionError("Tests must stay offline"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def test_lan_dispatch_preserves_relative_paths_and_process(self):
        with patch.object(lan, "main") as run, patch.object(subprocess, "run", side_effect=AssertionError):
            tool.main(["--action", "lan-root", "--host", "192.0.2.1", "--private-key", "keys/my key", "--no-shell"])
        args = lan.parse_args(run.call_args.args[0])
        self.assertEqual(args.private_key, "keys/my key")
        self.assertEqual(args.pubkey, "keys/my key.pub")
        self.assertTrue(args.no_shell)

    def test_prompted_wifi_secret_does_not_spawn_process(self):
        with patch.object(sys.stdin, "isatty", return_value=True), patch.object(tool.getpass, "getpass", return_value="test secret"), patch.object(usb, "main") as run, patch.object(subprocess, "run", side_effect=AssertionError):
            tool.main(["--action", "usb-provision-wifi", "--ssid", " test ", "--yes"])
        args = usb.parse_args(run.call_args.args[0])
        self.assertEqual(args.wifi_password, "test secret")
        self.assertEqual(args.ssid, " test ")

    def test_host_alias_conflict(self):
        with self.assertRaises(SystemExit):
            tool.lan_args(tool.parse_args(["--hub-host", "a", "--hub-ip", "b"]), False)

    def test_hub_id_read_does_not_implicitly_save(self):
        with patch.object(usb, "main") as run:
            tool.main(["--action", "usb-hub-id"])
        self.assertFalse(usb.parse_args(run.call_args.args[0]).save_hub_id)

    def test_hide_ssids_does_not_prompt(self):
        with patch("builtins.input", side_effect=AssertionError), patch.object(usb, "main"):
            tool.main(["--action", "usb-wifi-scan", "--hide-ssids"])

    def test_noninteractive_missing_input_fails(self):
        with patch.object(sys.stdin, "isatty", return_value=False), patch("builtins.input", side_effect=AssertionError):
            for argv in ([], ["--action", "lan-root"], ["--action", "usb-provision-wifi", "--yes"]):
                with self.subTest(argv=argv), self.assertRaises(SystemExit):
                    tool.main(argv)

    def test_dry_run_no_action_does_not_prompt(self):
        with patch("builtins.input", side_effect=AssertionError), self.assertRaises(SystemExit):
            tool.main(["--dry-run"])

    def test_dry_run_never_creates_keys_or_removes_cache(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(lan, "ensure_keypair", side_effect=AssertionError), patch.object(lan, "delete_saved_hub_ids", side_effect=AssertionError), patch("builtins.input", side_effect=AssertionError):
            tool.main(["--action", "lan-root", "--dry-run", "--clear-saved-hub-id", "--private-key", str(Path(temp) / "missing/key")])
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_usb_dry_runs_never_open_hardware(self):
        with patch.object(usb, "HarmonyUsbBridge", side_effect=AssertionError), patch("builtins.input", side_effect=AssertionError):
            for action in tool.ACTION_CHOICES:
                if action.startswith("usb-") and action != "usb-flash-firmware":
                    with self.subTest(action=action):
                        tool.main(["--action", action, "--dry-run"])

    def test_usb_direct_dry_runs_cover_each_action(self):
        for action in usb.ACTION_CHOICES:
            if action == "flash-firmware":
                continue
            with self.subTest(action=action):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    usb.dry_run(usb.parse_args(["--action", action, "--dry-run"]))
                self.assertEqual(json.loads(output.getvalue())["action"], action)

    def test_missing_firmware_dry_run_does_not_prompt(self):
        with patch("builtins.input", side_effect=AssertionError), self.assertRaises(usb.UsbBridgeError):
            tool.main(["--action", "usb-flash-firmware", "--dry-run"])

    def test_relative_input_paths_remain_relative_to_callers_directory(self):
        self.assertEqual(usb.resolve_local_path("firmware with spaces.hfw2"), Path("firmware with spaces.hfw2"))
        self.assertEqual(lan.resolve_input_path("custom/dropbearmulti"), Path("custom/dropbearmulti"))

    def test_invalid_options_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for parser, argv in ((tool.parse_args, ["--show-ssids", "--hide-ssids"]), (tool.parse_args, ["--force"]), (lan.parse_args, ["--ssh-wait", "0"]), (usb.parse_args, ["--lan-port", "70000"]), (usb.parse_args, ["--firmware-packets-per-chunk", "0"])):
                with self.subTest(argv=argv), self.assertRaises(SystemExit):
                    parser(argv)

    def test_keypair_mismatch_rejected_before_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            private, public = Path(temp) / "key", Path(temp) / "key.pub"
            private.write_text("private placeholder")
            public.write_text("ssh-ed25519 wrong comment")
            with patch.object(lan, "require_tool", return_value="ssh-keygen"), patch.object(subprocess, "check_output", return_value="ssh-ed25519 expected"), self.assertRaises(SystemExit):
                lan.ensure_keypair(private, public)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH not installed")
    def test_real_key_generation_custom_public_path_and_reuse(self):
        with tempfile.TemporaryDirectory() as temp:
            private, public = Path(temp) / "key with spaces", Path(temp) / "public dir/owner.pub"
            lan.ensure_keypair(private, public)
            self.assertTrue(private.is_file())
            self.assertEqual(public.read_bytes(), Path(str(private) + ".pub").read_bytes())
            lan.ensure_keypair(private, public)
            public.unlink()
            lan.ensure_keypair(private, public)
            self.assertTrue(public.is_file())

    def test_xmpp_fragmented_reply_ignores_other_requests(self):
        transport = lan.XmppTransport("unused", 5222)
        transport.sock = FakeSocket(b"<iq id='other'/><iq id='wanted'", b"><oa errorcode='200'><![CDATA[{\"ok\":true}]]></oa>", b"</iq><iq id='next'/>")
        reply = transport.receive_iq("wanted", 1)
        self.assertEqual(lan.extract_attr(reply, "errorcode"), "200")
        self.assertEqual(json.loads(lan.extract_payload(reply)), {"ok": True})
        self.assertIn("next", transport.receive_iq("next", 1))

    def test_xmpp_truncated_reply_fails(self):
        transport = lan.XmppTransport("unused", 5222)
        transport.sock = FakeSocket(b"<iq id='wanted'>")
        with self.assertRaises(ConnectionError):
            transport.receive_iq("wanted", 1)

    def test_xmpp_auth_failure_closes_socket(self):
        sock = FakeSocket(b"</stream:features>", b"<failure/>")
        with patch("socket.create_connection", return_value=sock), self.assertRaises(RuntimeError):
            lan.XmppTransport("unused", 5222).open()
        self.assertTrue(sock.closed)

    def test_ws_fragmented_text_with_ping(self):
        sock = FakeSocket(ws_frame(b'{"code":', final=False), ws_frame(b"hello", 9), ws_frame(b"200}", 0))
        result = lan.WebSocketTransport("unused", "1234", 8088, "domain")._recv_ws(sock, 1)
        self.assertEqual(json.loads(result), {"code": 200})
        self.assertEqual(sock.sent[0][0] & 15, 10)

    def test_ws_masked_frame_and_buffered_bytes(self):
        frame = lan.WebSocketTransport._frame(b'{"code":200}')
        result = lan.WebSocketTransport("unused", "1234", 8088, "domain")._recv_ws(FakeSocket(), 1, bytearray(frame))
        self.assertEqual(json.loads(result)["code"], 200)

    def test_ws_rejects_truncated_and_oversized_frames(self):
        for data in (b"\x81\x05hi", b"\x81\x7f" + struct.pack("!Q", 2_000_001)):
            with self.subTest(data=data), self.assertRaises((ConnectionError, RuntimeError)):
                lan.WebSocketTransport("unused", "1234", 8088, "domain")._recv_ws(FakeSocket(data), 1)

    def test_ws_handshake_preserves_coalesced_frame_and_skips_notifications(self):
        key = base64.b64encode(b"a" * 16).decode()
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        headers = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        replies = ws_frame(b'{"id":"other","code":200}') + ws_frame(b'{"code":200}')
        sock = FakeSocket(headers[:15], headers[15:] + replies)
        with patch("socket.create_connection", return_value=sock), patch.object(lan.os, "urandom", side_effect=lambda n: b"a" * n):
            reply = lan.WebSocketTransport("unused", "1234", 8088, "domain").call("sys.info", {})
        self.assertEqual(reply, {"code": 200})

    def test_wifi_preserves_spaces_and_rejects_property_injection(self):
        args = usb.parse_args(["--ssid", " network ", "--wifi-password", " spaced password "])
        self.assertIn(b"ssid, network \n", usb.wifi_connect_payload(args))
        self.assertIn(b"password, spaced password \n", usb.wifi_connect_payload(args))
        for field, value in (("ssid", "a\npassword,b"), ("wifi_password", "a\0b"), ("encryption", "a\rb"), ("ssid", "a" * 33)):
            args = usb.parse_args(["--ssid", "network"])
            setattr(args, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(usb.UsbBridgeError):
                usb.wifi_connect_payload(args)

    def test_firmware_requires_unambiguous_checksum(self):
        payload = b"test firmware"
        checksum = hashlib.md5(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "firmware with spaces.hfw2"
            for expected in (checksum, "", "0" * 32):
                xml = f'<ROOT><FILES><FILE NAME="ota.EzHex" PATH="/fw/otaupdate" OPERATIONTYPE="FirmwareUpgrade"><CHECKSUM TYPE="MD5" EXPECTEDVALUE="{expected}"/></FILE></FILES></ROOT>'
                with zipfile.ZipFile(bundle, "w") as archive:
                    archive.writestr("Description.xml", xml)
                    archive.writestr("ota.EzHex", payload)
                if expected == checksum:
                    self.assertEqual(usb.parse_hfw2_bundle(str(bundle)).images[0].data, payload)
                    tool.main(["--action", "usb-flash-firmware", "--firmware-file", str(bundle), "--dry-run"])
                else:
                    with self.assertRaises(usb.UsbBridgeError):
                        usb.parse_hfw2_bundle(str(bundle))
            with self.assertRaises(usb.UsbBridgeError):
                usb.find_zip_member(["one/ota.EzHex", "two/ota.EzHex"], "ota.EzHex")

    def test_usb_lock_does_not_grow(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(usb, "USB_LOCK_PATH", Path(temp) / "usb.lock"):
            for _ in range(3):
                with usb.usb_process_lock():
                    pass
            self.assertEqual(usb.USB_LOCK_PATH.stat().st_size, 1)

    def test_hub_id_raw_output_honors_hide_ssids(self):
        read = usb.RawFileRead("device", "/rf/deviceinfo", 44, b"ssid,SecretNetwork\npassword,secret\n", None, [], None)
        output = io.StringIO()
        with patch.object(usb, "raw_read_file", return_value=read), contextlib.redirect_stdout(output):
            usb.run_hub_id(Mock(), usb.parse_args(["--action", "hub-id", "--raw-output", "--hide-ssids"]))
        self.assertNotIn("SecretNetwork", output.getvalue())
        self.assertNotIn("secret", output.getvalue().lower().replace("<redacted>", ""))

    def test_failed_firmware_handoff_skips_reboot_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "firmware.hfw2"
            path.write_bytes(b"payload")
            image = usb.FirmwareImage("ota.EzHex", "/fw/other", "FirmwareUpgrade", b"payload", "MD5", 0, 0, 7, hashlib.md5(b"payload").hexdigest(), True)
            bundle = usb.FirmwareBundle(path, [], [image])
            handle, device, bridge = Mock(), Mock(), Mock()
            bridge.open_handle.return_value = (handle, device)
            args = usb.parse_args(["--action", "flash-firmware", "--firmware-file", str(path), "--yes", "--firmware-checksum-settle-ms", "0"])
            with patch.object(usb, "parse_hfw2_bundle", return_value=bundle), patch.object(usb, "raw_reset_filesystem_on_handle"), patch.object(usb, "raw_open_write_file_on_handle", return_value=2), patch.object(usb, "raw_devctrl_checksum_on_handle", return_value=usb.FirmwareChecksumOutcome(None, ord("u"), False, 1, [])), patch.object(usb, "raw_close_file_on_handle"), patch.object(usb, "raw_reboot_device_on_handle") as reboot, self.assertRaises(usb.UsbBridgeError):
                usb.run_flash_firmware(bridge, args)
            reboot.assert_not_called()
            handle.close.assert_called_once()

    def test_backend_selection_and_missing_macos_dependency(self):
        with patch.object(usb.sys, "platform", "win32"), patch.object(usb, "WindowsNativeBackend", return_value="winhid"), patch.object(usb, "HidApiBackend", side_effect=usb.UsbBridgeError):
            self.assertEqual(usb.make_backends("auto"), ["winhid"])
        with patch.object(usb.sys, "platform", "darwin"), patch.object(usb, "HidApiBackend", side_effect=usb.UsbBridgeError), self.assertRaisesRegex(usb.UsbBridgeError, "requires hidapi"):
            usb.make_backends("auto")

    def test_usb_self_test(self):
        usb.self_test()

    def test_checksum_case_variants_keep_descriptor_first(self):
        expected = [("descriptor", "aB"), ("upper", "AB"), ("lower", "ab")]
        self.assertEqual(usb.checksum_case_variants("aB", "auto", "case"), expected)
        self.assertEqual(usb.checksum_case_variants("aB", "auto", "type"), expected)


class LauncherTests(unittest.TestCase):
    def invoke(self, prefix, args, cwd=None):
        return subprocess.run(prefix + args, cwd=cwd, input="", capture_output=True, text=True, timeout=30, env={**os.environ, "HARMONY_NO_PAUSE": "1"})

    def test_python_cli_from_another_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = self.invoke([sys.executable, str(tool.SCRIPT_DIR / "run_harmony_hub_tool.py")], ["--action", "lan-root", "--dry-run", "--private-key", "relative key"], temp)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_platform_launchers_preserve_exit_codes(self):
        if os.name == "nt":
            prefixes = [["cmd.exe", "/d", "/c", str(tool.SCRIPT_DIR / "Start_Harmony_Hub_Tool.cmd")]]
        else:
            prefixes = [["sh", str(tool.SCRIPT_DIR / "run_harmony_hub_tool.sh")]]
        for prefix in prefixes:
            for args, expected in ((["--help"], 0), (["--invalid-option"], 2), (["--action", "usb-sysinfo", "--dry-run"], 0)):
                with self.subTest(prefix=prefix, args=args):
                    proc = self.invoke(prefix, args)
                    self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
