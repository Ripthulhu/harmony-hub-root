"""Offline framing and isolation tests for fresh-hub root transports."""
import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch

import harmony_usb_bridge as usb
import harmony_xmpp_root_shell as lan
import run_harmony_hub_tool as tool


class HbusTransportTests(unittest.TestCase):
    def test_explicit_hidapi_path_is_bytes(self):
        backend = object.__new__(usb.HidApiBackend)
        backend._raw_paths = {}
        backend._hid = Mock()
        device = usb.DeviceInfo(backend="hidapi", path="chosen", vendor_id=0x046D, product_id=0xC129)
        with patch.object(usb, "HidApiHandle") as opened:
            backend.open(device)
        opened.assert_called_once_with(backend._hid, b"chosen")

    def test_post_framing_and_close(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"id":"6161616161616161","code":200,"data":{}}'
        with patch.object(lan.http.client, "HTTPConnection", return_value=connection) as factory, patch.object(lan.os, "urandom", return_value=b"a" * 8):
            reply = lan.HttpPostTransport("192.0.2.1").call("harmony.log?put", {"resource": []}, 30)
        self.assertEqual(reply["code"], 200)
        factory.assert_called_once_with("192.0.2.1", 8088, timeout=38)
        method, path, body, headers = connection.request.call_args.args
        self.assertEqual((method, path), ("POST", "/"))
        self.assertEqual(json.loads(body), {"id": "6161616161616161", "cmd": "harmony.log?put", "params": {"resource": []}, "timeout": 30})
        self.assertEqual(headers["Origin"], "http://sl.dhg.myharmony.com")
        connection.close.assert_called_once()

    def test_post_rejects_status_mismatch_truncation_without_retry(self):
        for status, raw in ((302, b"redirect"), (200, b'{"id":"other","code":200}'), (200, b'{'), (200, b"x" * 2_000_001)):
            connection = Mock()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.read.return_value = raw
            with self.subTest(status=status, size=len(raw)), patch.object(lan.http.client, "HTTPConnection", return_value=connection), self.assertRaises((RuntimeError, ValueError)):
                lan.HttpPostTransport("192.0.2.1").call("test", {})
            connection.request.assert_called_once()
            connection.close.assert_called_once()

    def test_json_adapter_preserves_raw_content_and_engine_errors(self):
        backend = Mock()
        backend.call.return_value = {"code": 200, "data": {"errorCode": "594", "errorString": "production"}}
        adapter = lan.JsonRootTransport(backend)
        response = adapter.call("connect.jsonfiletransfer?put", lan.jft_put_body("../../pkg/test", "manifest.json", 'a&b="☃"'))
        self.assertEqual(response.code, "594")
        self.assertEqual(backend.call.call_args.args[1], {"path": "../../pkg/test", "file": "manifest.json", "content": 'a&b="☃"'})
        backend.call.return_value = {"id": "x", "code": 417, "msg": "not allowed", "data": {}}
        self.assertEqual(adapter.call("test", {}).code, "417")

    def test_command_framing_and_fragmented_response(self):
        for size in (1, 50, 60, 64, 200, 1400):
            message = {"id": "wanted", "code": 200, "data": "x" * size}
            frames = usb.hbus_command_frames(message, 7)
            self.assertTrue(all(len(frame) == 64 for frame in frames))
            self.assertEqual(frames[0][:5], bytes([255, 8, 7, 1, 2]))
            raw = b"".join(frames)
            self.assertEqual(usb.hbus_response_messages(raw), [message])
            for end in range(0, len(raw), 64):
                self.assertEqual(usb.hbus_response_messages(raw[:end]), [])

    def test_separately_padded_primary_and_notifications(self):
        message = {"id": "wanted", "code": 200}
        frames = usb.hbus_command_frames(message, 4)
        raw = b"".join(frames)
        payload = json.dumps(message, separators=(",", ":")).encode()
        packed = bytes([255, 8, 0x84, 1, 1, 2, 1, 0x80 | len(payload)]) + payload
        self.assertEqual(usb.hbus_response_messages(packed.ljust(64, b"\x00")), [message])
        self.assertEqual(usb.hbus_response_messages(raw + raw), [message, message])
        with self.assertRaises(usb.UsbBridgeError):
            usb.hbus_response_messages(bytes([255, 8, 255, 1]).ljust(64, b"\x00"))

    def test_command_bounds(self):
        for message, sequence in (({"data": "x" * 16384}, 1), ({}, 64), ({}, -1)):
            with self.assertRaises(usb.UsbBridgeError):
                usb.hbus_command_frames(message, sequence)

    def test_usb_transport_matches_json_id_not_notifications(self):
        handle = Mock()
        device = usb.DeviceInfo(backend="hidapi", path="chosen", vendor_id=0x046D, product_id=0xC129)
        transport = usb.UsbHbusTransport(usb.parse_args(["--device-path", "chosen"]))
        def exchange(handle, device, frames, timeout, expect, stop):
            request = usb.hbus_response_messages(b"".join(frames))[0]
            notification = b"".join(usb.hbus_command_frames({"id": "other", "code": 200}, 0))
            response = b"".join(usb.hbus_command_frames({"id": request["id"], "code": 200, "data": {}}, 0))
            self.assertFalse(stop(notification))
            self.assertTrue(stop(notification + response))
            return notification + response, []
        with patch.object(transport.bridge, "open_handle", return_value=(handle, device)), patch.object(transport.bridge, "exchange_reports", side_effect=exchange), patch.object(usb, "usb_process_lock", return_value=contextlib.nullcontext()):
            self.assertEqual(transport.call("connect.sysinfo?get", {})["code"], 200)
        handle.close.assert_called_once()

    def test_usb_ambiguous_device_fails_before_open(self):
        transport = usb.UsbHbusTransport(usb.parse_args([]))
        with patch.object(transport.bridge, "enumerate_devices", return_value=[Mock(), Mock()]), patch.object(transport.bridge, "open_handle") as opened, patch.object(usb, "usb_process_lock", return_value=contextlib.nullcontext()), self.assertRaises(usb.UsbBridgeError):
            transport.call("connect.sysinfo?get", {})
        opened.assert_not_called()

    def test_json_root_never_refreshes_xmpp_or_uses_fallback_for_tde(self):
        adapter = lan.JsonRootTransport(Mock())
        with patch.object(lan, "wait_for_port", side_effect=AssertionError):
            lan.refresh_xmpp_session(adapter, "unused", 5222, "unused")
        with patch.object(lan, "log_put"), patch.object(lan.time, "sleep"), patch.object(lan, "tde_readback", return_value=(False, lan.XmppResponse("", "594", "production", ""))), patch.object(lan, "collect_hub_ids", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            lan.open_tde_gate(adapter, "unused", 5222, 8088, "domain", "")

    def test_unified_cli_forwards_transport_and_dry_run_stays_offline(self):
        for name in ("post", "usb"):
            with patch.object(lan, "main") as run, contextlib.redirect_stdout(io.StringIO()):
                tool.main(["--action", "lan-root", "--transport", name, "--dry-run", "--ignore-saved-hub-id"])
            args = lan.parse_args(run.call_args.args[0])
            self.assertEqual(args.transport, name)
            self.assertTrue(args.ignore_saved_hub_id)
            with patch("socket.create_connection", side_effect=AssertionError), patch.object(usb, "HarmonyUsbBridge", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
                lan.main(run.call_args.args[0])

    def test_json_upload_chain_never_uses_lan_fallback_or_hub_ids(self):
        backend = Mock()
        def reply(cmd, params, timeout):
            data = {}
            if cmd.endswith("?get"):
                data = {"tdeenable": "1", "manifest.json": 'testpkg /data/test_stage rootssh-lan-xmpp', "testpkg.lua": "/data/test_stage", "result.json": {"ok": True}}.get(params["file"], {})
            return {"id": "x", "code": 200, "data": data}
        backend.call.side_effect = reply
        adapter = lan.JsonRootTransport(backend)
        with patch.object(lan, "WebSocketTransport", side_effect=AssertionError), patch.object(lan, "collect_hub_ids", side_effect=AssertionError), patch.object(lan, "refresh_xmpp_session", side_effect=lambda *a: None), patch.object(lan.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(lan.upload_and_install(adapter, "unused", 5222, 8088, "domain", "testpkg", "/data/test_stage", {"version": "rootssh-lan-xmpp"}, {"f1.1": "YWJj"}, ""), ("", []))
        calls = [call.args[0] for call in backend.call.call_args_list]
        self.assertIn("harmony.log?put", calls)
        self.assertIn("connect.jsonfiletransfer?put", calls)
        self.assertIn("harmony.automation?discover", calls)
