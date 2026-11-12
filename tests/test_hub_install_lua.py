"""The hub-side installer's file helpers, run with a host Lua when one exists.

The Lua runs inside the hub's Lua runtime; these tests lift its file helpers
(writeAll, sameBytes, stageFile, replaceFiles) out of STAGER_LUA and drive
them against temporary files. Skipped where no Lua 5.1-compatible
interpreter is on PATH (set HUB_ROOT_LUA to pick one).
"""
import base64
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import harmony_xmpp_root_shell as tool  # noqa: E402


def find_lua():
    env = os.environ.get("HUB_ROOT_LUA")
    if env:
        return env
    for name in ("lua5.1", "luajit", "lua"):
        path = shutil.which(name)
        if path:
            return path
    return None


LUA = find_lua()


def helpers():
    src = tool.STAGER_LUA
    start = src.index("local function shellQuote")
    end = src.index("local function b64decode")
    return src[start:end]


# Reads a plan (JSON lines: path, source file or "FAIL", mode) and runs
# replaceFiles on it. A "FAIL" source is a file whose load() raises, as a
# corrupt chunk would.
RUNNER = r'''
local plan = {}
for line in io.lines(arg[1]) do
  local path, src, mode = line:match("^(.-)\t(.-)\t(.*)$")
  local entry = {path = path, mode = mode ~= "" and mode or nil}
  if src == "FAIL" then
    entry.load = function() error("size mismatch for " .. path) end
  else
    local f = assert(io.open(src, "rb")); entry.data = f:read("*a"); f:close()
  end
  table.insert(plan, entry)
end
local ok, res = pcall(replaceFiles, plan)
if ok then print("replaced " .. res) else print("error: " .. tostring(res)); os.exit(1) end
'''


@unittest.skipUnless(LUA and os.name == "posix", "no Lua interpreter on PATH")
class ReplaceFilesTests(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="hubroot-lua-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.n = 0

    def lua(self, body, *args):
        script = self.dir / "run.lua"
        script.write_text(helpers() + body)
        p = subprocess.run([LUA, str(script), *map(str, args)], capture_output=True, text=True)
        return p.stdout.strip(), p.returncode

    def replace(self, *entries):
        """entries: (path, bytes or None for a failing load, mode or None)."""
        lines = []
        for path, data, mode in entries:
            if data is None:
                src = "FAIL"
            else:
                self.n += 1
                src = self.dir / f"src{self.n}.bin"
                src.write_bytes(data)
            lines.append(f"{path}\t{src}\t{mode or ''}")
        plan = self.dir / "plan.txt"
        plan.write_text("\n".join(lines) + "\n")
        return self.lua(RUNNER, plan)

    def temps(self):
        return sorted(str(p.relative_to(self.dir)) for p in self.dir.rglob("*.rootssh-new"))

    def test_creates_a_missing_file_and_its_directory(self):
        path = self.dir / "a" / "b" / "dropbearmulti"
        self.assertEqual(self.replace((path, b"\x7fELF new", "755")), ("replaced 1", 0))
        self.assertEqual(path.read_bytes(), b"\x7fELF new")
        self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.temps(), [])

    def test_new_bytes_replace_the_file_and_leave_a_hard_link_alone(self):
        # Melodious hard-links its Dropbear to the root tool's copy; SSH runs
        # it from the other path. That copy must keep its bytes.
        path = self.dir / "rootssh" / "dropbearmulti"
        other = self.dir / "codex" / "dropbearmulti"
        path.parent.mkdir()
        other.parent.mkdir()
        path.write_bytes(b"old build")
        os.link(path, other)
        self.assertEqual(self.replace((path, b"new build, smaller", "755")), ("replaced 1", 0))
        self.assertEqual(path.read_bytes(), b"new build, smaller")
        self.assertEqual(other.read_bytes(), b"old build")
        self.assertNotEqual(path.stat().st_ino, other.stat().st_ino)
        self.assertEqual(self.temps(), [])

    def test_same_bytes_are_not_rewritten(self):
        path = self.dir / "dropbearmulti"
        other = self.dir / "linked"
        data = os.urandom(200000)  # more than one 64 KB compare block
        path.write_bytes(data)
        os.link(path, other)
        before = path.stat()
        self.assertEqual(self.replace((path, data, "755")), ("replaced 0", 0))
        after = path.stat()
        self.assertEqual(after.st_ino, before.st_ino)
        self.assertEqual(after.st_nlink, 2)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

    def test_same_size_different_bytes_are_replaced(self):
        path = self.dir / "dropbearmulti"
        data = os.urandom(200000)
        path.write_bytes(data)
        changed = data[:150000] + bytes([data[150000] ^ 1]) + data[150001:]  # in the third block
        self.assertEqual(self.replace((path, changed, None)), ("replaced 1", 0))
        self.assertEqual(path.read_bytes(), changed)

    def test_a_failed_chmod_leaves_the_old_file_in_place(self):
        # The mode is set on the staged copy, before anything is renamed:
        # Dropbear is never in place without its execute bits.
        path = self.dir / "dropbearmulti"
        path.write_bytes(b"old build")
        out, rc = self.replace((path, b"new build", "999"))
        self.assertEqual(rc, 1)
        self.assertIn("chmod failed", out)
        self.assertEqual(path.read_bytes(), b"old build")
        self.assertEqual(self.temps(), [])

    def test_a_failed_write_leaves_the_old_file_whole(self):
        path = self.dir / "dropbearmulti"
        path.write_bytes(b"old build")
        # The temporary name is taken by a directory that can't be removed.
        blocker = self.dir / "dropbearmulti.rootssh-new"
        blocker.mkdir()
        (blocker / "x").write_text("x")
        out, rc = self.replace((path, b"new build", "755"))
        self.assertEqual(rc, 1)
        self.assertIn("write failed", out)
        self.assertEqual(path.read_bytes(), b"old build")

    def test_any_failure_while_staging_changes_nothing(self):
        # The wrapper must never be installed without the binary it runs, and
        # nothing may be half-installed when a later file fails.
        binary = self.dir / "bin" / "dropbearmulti"
        wrapper = self.dir / "sbin" / "dropbear"
        binary.parent.mkdir()
        wrapper.parent.mkdir()
        binary.write_bytes(b"old build")
        wrapper.write_bytes(b"#!/bin/sh\nexec old\n")
        out, rc = self.replace((binary, b"new build", "755"),
                               (wrapper, b"#!/bin/sh\nexec new\n", "755"),
                               (self.dir / "keys", None, "600"))
        self.assertEqual(rc, 1)
        self.assertIn("size mismatch", out)
        self.assertEqual(binary.read_bytes(), b"old build")
        self.assertEqual(wrapper.read_bytes(), b"#!/bin/sh\nexec old\n")
        self.assertFalse((self.dir / "keys").exists())
        self.assertEqual(self.temps(), [])

    def test_a_failed_rename_leaves_no_staged_copies(self):
        path = self.dir / "dropbearmulti"
        path.mkdir()  # a non-empty directory can't be renamed over
        (path / "x").write_text("x")
        later = self.dir / "later"
        out, rc = self.replace((path, b"new build", None), (later, b"later", None))
        self.assertEqual(rc, 1)
        self.assertIn("rename failed", out)
        self.assertTrue(path.is_dir())
        self.assertFalse(later.exists())
        self.assertEqual(self.temps(), [])

    @unittest.skipUnless(os.path.exists("/dev/full"), "no /dev/full")
    def test_write_all_reports_a_full_device(self):
        # A short write (ENOSPC, at write or at close) is an error, not a
        # silently truncated file.
        for size in (10, 1 << 20):
            out, rc = self.lua("local ok, err = pcall(writeAll, '/dev/full', string.rep('x', %d))\n"
                               "print(ok and 'ok' or err)\n" % size)
            self.assertIn("write failed /dev/full", out)


def lua_str(s):
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


@unittest.skipUnless(LUA and os.name == "posix", "no Lua interpreter on PATH")
class DiscoverEndToEndTests(unittest.TestCase):
    """The whole STAGER_LUA: chunks are decoded, files installed all or
    nothing, commands run only after, and the result is recorded. The hub's
    json module is stubbed; paths and commands point into a temp dir."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="hubroot-e2e-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.stage = self.dir / "stage"
        (self.stage / "chunks").mkdir(parents=True)

    def run_discover(self, files, chunk_size=64):
        entries = []
        for ident, (path, data, mode, claimed) in enumerate(files, 1):
            enc = base64.b64encode(data).decode()
            parts = [enc[i:i + chunk_size] for i in range(0, len(enc), chunk_size)]
            for n, part in enumerate(parts, 1):
                (self.stage / "chunks" / f"f{ident}.{n}").write_text(part)
            entries.append("{id=%s, path=%s, mode=%s, bytes=%d, chunks=%d}" % (
                lua_str(f"f{ident}"), lua_str(path), lua_str(mode), claimed if claimed is not None else len(data), len(parts)))
        (self.stage / "manifest.json").write_text("{}")
        marker = self.dir / "commands-ran"
        manifest = "{files={%s}, commands={%s}}" % (", ".join(entries), lua_str(f"touch {marker}"))
        prelude = ("package.preload['json'] = function() return {decode = function() return %s end, "
                   "encode = function(t) return t.ok and 'ok' or ('fail: ' .. tostring(t.error)) end} end\n" % manifest)
        # The hub loads the script as a module (module(..., package.seeall)).
        (self.dir / "rootstage.lua").write_text(tool.STAGER_LUA.replace("__STAGE_JSON__", lua_str(self.stage)))
        script = self.dir / "run.lua"
        script.write_text(prelude + "package.path = %s .. '/?.lua;' .. package.path\n"
                          "local m = require('rootstage')\n"
                          "local r = m.discover(m)\n"
                          "print(r.rootssh and 'rootssh' or 'none')\n" % lua_str(self.dir))
        p = subprocess.run([LUA, str(script)], capture_output=True, text=True)
        self.assertEqual(p.stderr, "")
        result = (self.stage / "result.json").read_text() if (self.stage / "result.json").exists() else ""
        return p.stdout.strip(), result, marker.exists()

    def test_installs_every_file_then_runs_the_commands(self):
        binary = self.dir / "bin" / "dropbearmulti"
        wrapper = self.dir / "sbin" / "dropbear"
        data = os.urandom(3000)
        out, result, ran = self.run_discover([(binary, data, "755", None),
                                              (wrapper, b"#!/bin/sh\nexec it\n", "755", None)])
        self.assertEqual((out, result, ran), ("rootssh", "ok", True))
        self.assertEqual(binary.read_bytes(), data)
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        self.assertEqual(wrapper.read_bytes(), b"#!/bin/sh\nexec it\n")

    def test_a_bad_file_installs_nothing_and_runs_no_commands(self):
        binary = self.dir / "bin" / "dropbearmulti"
        binary.parent.mkdir()
        binary.write_bytes(b"old build")
        out, result, ran = self.run_discover([(binary, b"new build", "755", None),
                                              (self.dir / "keys", b"key\n", "600", 999)])
        self.assertEqual(out, "none")
        self.assertTrue(result.startswith("fail: "), result)
        self.assertIn("size mismatch", result)
        self.assertFalse(ran, "commands ran after a failed install")
        self.assertEqual(binary.read_bytes(), b"old build")
        self.assertFalse((self.dir / "keys").exists())
        self.assertEqual(list(self.dir.rglob("*.rootssh-new")), [])


class InstallUsesReplaceFilesTests(unittest.TestCase):
    def test_install_does_not_write_files_in_place(self):
        src = tool.STAGER_LUA
        body = src[src.index("local function install()"):src.index("function discover(self)")]
        self.assertIn("replaceFiles(files)", body)
        self.assertNotIn("writeAll(file.path", body)

    def test_discover_records_a_failure_without_throwing(self):
        src = tool.STAGER_LUA
        body = src[src.index("function discover(self)"):]
        self.assertIn("pcall(saveResult, false", body)


if __name__ == "__main__":
    unittest.main()
