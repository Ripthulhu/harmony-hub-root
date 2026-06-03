# Harmony Hub LAN Root SSH Tool

For an owned Logitech Harmony Hub on the same LAN as your computer. The tool
gains root access, installs Dropbear, and starts persistent SSH access.

## Files

- `Start_XMPP_Root_Shell.cmd` - double-click launcher
- `run_xmpp_root_shell.ps1` - PowerShell wrapper
- `run_xmpp_root_shell.sh` - Linux/macOS shell wrapper
- `harmony_xmpp_root_shell.py` - LAN installer
- `dropbearmulti` - MIPS Dropbear binary for Harmony Hub
- `SHA256SUMS.txt` - integrity hashes

## Requirements

- Windows 10/11, Linux, or macOS
- Python 3.10 or newer
- OpenSSH client tools: `ssh` and `ssh-keygen`
- Harmony Hub IP address
- PC and hub on the same LAN
- The hub has completed normal first-time setup in the Harmony phone app
- XMPP/local network control is enabled in the Harmony phone app

## Run

Finish setup in the Harmony phone app first. The hub must already be joined to
Wi-Fi, linked to the app, and reachable on the local network with XMPP enabled.

### Windows

Double-click:

```text
Start_XMPP_Root_Shell.cmd
```

Enter the hub IP address when prompted.

The tool creates or reuses an SSH key at:

```text
%USERPROFILE%\.ssh\harmony_owner_ed25519
```

### Linux/macOS

From the repository root:

```bash
./run_xmpp_root_shell.sh --host <hub-ip>
```

Or call Python directly:

```bash
python3 harmony_xmpp_root_shell.py --host <hub-ip>
```

The tool creates or reuses an SSH key at:

```text
~/.ssh/harmony_owner_ed25519
```

It installs persistent root SSH and then opens a root shell:

```text
ssh -i %USERPROFILE%\.ssh\harmony_owner_ed25519 root@<hub-ip>
ssh -i ~/.ssh/harmony_owner_ed25519 root@<hub-ip>
```

## Tested Firmware

This tool was tested on Logitech Harmony Hub firmware `4.15.600`.

## Why This Exploit Works

This is a LAN-only post-setup exploit chain. It depends on the hub already being
provisioned through the Harmony phone app because normal setup joins the hub to
Wi-Fi and enables Logitech's local XMPP/HBus control interface. Without that
local service, there is nothing on the network for this tool to talk to.

The chain works because several legacy/debug features trust each other too much:

1. The local XMPP service accepts a legacy local-client login.

   The hub exposes XMPP on TCP port `5222` for older Harmony local control
   clients. After opening an XMPP stream, the tool authenticates with SASL PLAIN
   as a local client identity. On affected firmware this is accepted by the
   local service and gives access to the internal HBus command bridge.

2. XMPP forwards commands into privileged HBus handlers.

   XMPP messages contain `<oa>` command stanzas such as `connect.sysinfo?get`,
   `harmony.log?put`, and `connect.jsonfiletransfer?get`. The hub forwards those
   into the Harmony application layer. That application layer is not a tiny
   unprivileged web API; it has access to internal configuration paths and the
   vendor debug/update plumbing.

3. `harmony.log?put` has a path traversal bug.

   The log-write API accepts a client supplied `fileName` and `data`. It should
   restrict writes to the intended log/cache directory, but affected firmware
   does not sufficiently canonicalize or sandbox the filename before writing.
   Supplying a filename like `../etc/tdeenable` makes the log writer escape its
   normal directory and create `/etc/tdeenable` with controlled contents.

4. `/etc/tdeenable` is a real vendor debug-mode switch.

   This is not a made-up marker. Harmony firmware checks `/etc/tdeenable`
   through its own TDE/development-mode logic. In production mode, sensitive APIs
   such as JSON file transfer are blocked with errors like `594 Cannot access
   this API in production mode`. Once `/etc/tdeenable` exists and the Harmony app
   refreshes or restarts, those same APIs become available.

5. TDE mode unlocks file staging.

   With TDE enabled, `connect.jsonfiletransfer?put` can write structured files
   into locations the Harmony app later reads. The tool uses this to stage a
   temporary automation package manifest, a Lua loader, a Lua installer, and
   base64 chunks of the Dropbear SSH payload. Large binary data is split into
   small chunks because the log/file-write path can silently truncate larger
   writes.

6. `harmony.automation?discover` loads and executes the staged Lua package.

   The automation discovery path takes a `gatewayType` value and looks for a
   matching package. By staging a package with a fresh random name, then calling
   `harmony.automation?discover` with that name, the tool causes the Harmony app
   to load the staged Lua code. The Lua code runs in the hub-side automation
   environment, which has enough privilege to write files, chmod them, and run
   shell commands.

7. The Lua installer turns the temporary write primitive into persistent SSH.

   The installer reconstructs the uploaded files from base64 chunks, verifies
   hashes, writes the MIPS `dropbearmulti` binary, installs wrapper commands at
   `/usr/sbin/dropbear` and `/usr/sbin/dropbearkey`, creates
   `/home/root/.ssh/authorized_keys`, fixes permissions, generates host keys if
   needed, kills any old Dropbear process, and starts Dropbear on TCP port `22`.

8. SSH persists because the firmware already has a TDE boot hook.

   The installed `/etc/tdeenable` file is also the persistence mechanism. On a
   real boot, the stock Harmony init path sees TDE enabled and invokes
   `/usr/sbin/dropbear`. Because the tool replaces that path with a wrapper that
   launches the installed Dropbear binary, SSH comes back after power cycles
   without needing to rerun the exploit.

In short: the bug is not just "one command gives root." The chain is:

```text
local XMPP access
  -> privileged HBus command bridge
  -> path traversal in harmony.log?put
  -> create /etc/tdeenable
  -> unlock vendor TDE file-transfer/debug APIs
  -> stage Lua automation package
  -> trigger package through automation discovery
  -> install and start persistent Dropbear SSH
```

The exploit fails if the hub is not fully set up, if XMPP/local network control
is disabled, if the PC cannot reach the hub on the LAN, or if the firmware has
patched either the log-write traversal or the TDE-gated automation/file-transfer
behavior.

## What It Installs

```text
/etc/tdeenable
/data/rootssh/bin/dropbearmulti
/usr/sbin/dropbear
/usr/sbin/dropbearkey
/home/root/.ssh/authorized_keys
```

SSH persists after reboot through the stock `/etc/tdeenable` boot path.

## Notes

If SSH warns that the host key changed, remove the old hub entry from
`%USERPROFILE%\.ssh\known_hosts` on Windows or `~/.ssh/known_hosts` on
Linux/macOS and reconnect. This is expected if the hub was previously rooted or
reset.
