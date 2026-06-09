# Harmony Hub Tool

For an owned Logitech Harmony Hub. One tool provides the LAN XMPP/HBus root SSH
flow, XMPP enable flow, USB diagnostics, USB Wi-Fi provisioning, and the
advanced USB root SSH install path on Windows, Linux, and macOS.

## Files

- `Start_Harmony_Hub_Tool.cmd` - double-click Windows launcher
- `run_harmony_hub_tool.ps1` - unified Windows runner and interactive menu
- `run_harmony_hub_tool.py` - unified cross-platform runner and interactive menu
- `run_harmony_hub_tool.sh` - Linux/macOS shell wrapper for the Python runner
- `harmony_xmpp_root_shell.py` - internal LAN XMPP/HBus engine
- `harmony_usb_bridge.py` - cross-platform internal USB HID/LTCP bridge engine
- `harmony_usb_bridge.ps1` - Windows-native internal USB HID/LTCP bridge engine
- `harmony_usb_hid_probe.ps1` - Windows HID enumerator used by the USB bridge
- `requirements-usb.txt` - optional hidapi dependency for macOS/Linux USB
- `rootsshusb.lua` - temporary hub-side USB root SSH installer
- `dropbearmulti` - MIPS Dropbear binary for Harmony Hub
- `SHA256SUMS.txt` - integrity hashes

## Requirements

- Python 3.10 or newer
- Windows 10/11, Linux, or macOS
- OpenSSH client tools: `ssh` and `ssh-keygen`
- For LAN root SSH or XMPP enable: Harmony Hub IP address, PC and hub on the same LAN, and the
  hub completed normal first-time setup in the Harmony phone app.
- For USB actions: a USB cable connected to the hub.
- For macOS USB actions: install hidapi with `python3 -m pip install -r requirements-usb.txt`.
- For Linux USB actions: the tool can use `/dev/hidraw*` directly. If your user
  cannot open the hub, run once with `sudo` or add a udev rule for `046d:c129`.
  hidapi is also supported with `python3 -m pip install -r requirements-usb.txt`.
- For LAN actions, local hub control must be reachable. If XMPP on `5222` is
  disabled, the tool will try to turn it on through the hub's `8088` WebSocket
  config path.

## Usage

On Windows, double-click:

```text
Start_Harmony_Hub_Tool.cmd
```

Or open PowerShell in the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_harmony_hub_tool.ps1
```

On Linux/macOS, run:

```bash
python3 run_harmony_hub_tool.py
```

or:

```bash
sh ./run_harmony_hub_tool.sh
```

All paths show one interactive menu:

```text
1. LAN root SSH install
2. Enable XMPP over LAN
3. USB preflight
4. USB sysinfo
5. Wi-Fi status over USB
6. Wi-Fi scan over USB
7. Provision Wi-Fi over USB
8. USB root SSH install
```

You can also call one action directly on Windows:

```powershell
.\run_harmony_hub_tool.ps1 -Action lan-root -HubHost "<hub-ip>"
.\run_harmony_hub_tool.ps1 -Action enable-xmpp -HubHost "<hub-ip>"
.\run_harmony_hub_tool.ps1 -Action usb-preflight
.\run_harmony_hub_tool.ps1 -Action usb-sysinfo
.\run_harmony_hub_tool.ps1 -Action usb-wifi-status
.\run_harmony_hub_tool.ps1 -Action usb-wifi-scan -ShowSsids
.\run_harmony_hub_tool.ps1 -Action usb-provision-wifi -Ssid "<ssid>" -WifiPassword "<password>" -Encryption "WPA2-PSK"
.\run_harmony_hub_tool.ps1 -Action usb-root-ssh -HubIp "<hub-ip>"
```

Direct Linux/macOS examples:

```bash
python3 run_harmony_hub_tool.py --action lan-root --hub-host "<hub-ip>"
python3 run_harmony_hub_tool.py --action enable-xmpp --hub-host "<hub-ip>"
python3 run_harmony_hub_tool.py --action usb-preflight
python3 run_harmony_hub_tool.py --action usb-sysinfo
python3 run_harmony_hub_tool.py --action usb-wifi-status
python3 run_harmony_hub_tool.py --action usb-wifi-scan --show-ssids
python3 run_harmony_hub_tool.py --action usb-provision-wifi --ssid "<ssid>" --wifi-password "<password>" --encryption "WPA2-PSK"
python3 run_harmony_hub_tool.py --action usb-root-ssh --hub-ip "<hub-ip>"
```

Windows can also exercise the cross-platform USB backend through PowerShell:

```powershell
.\run_harmony_hub_tool.ps1 -Action usb-preflight -UsbBackend python
```

USB Wi-Fi provisioning persists by default, matching MyHarmony's
`savewifinetwork` flow. Add `-NoSave` for a temporary association. Password
input from the interactive runners is hidden and is not written to disk by the
runners.

The LAN root SSH flow creates or reuses an SSH key at:

```text
%USERPROFILE%\.ssh\harmony_owner_ed25519
```

When LAN root SSH completes, the tool prints the detected Harmony Hub ID and
writes handoff files for the post-root web UI installer:

```text
%USERPROFILE%\.harmony-hub\hub_id.txt
%USERPROFILE%\.harmony-hub\last_root.json
%USERPROFILE%\.harmony-hub\known_hubs.json
```

The Hub ID is required by Harmony's local WebSocket/HBus API. Do not substitute
a guessed value.

For LAN-only scripting you can still call the internal Python engine directly:

```bash
python3 harmony_xmpp_root_shell.py --host <hub-ip>
```

If the tool cannot infer the hub ID while XMPP is disabled, pass a known ID with
`--hub-id <numeric-id>`. To only enable XMPP and skip root SSH, pass
`--enable-xmpp-only`.

## Tested Firmware

This tool was tested on Logitech Harmony Hub firmware `4.15.600`.

## Why This Exploit Works

This is a LAN-only post-setup exploit chain. It depends on the hub already being
provisioned through the Harmony phone app because normal setup joins the hub to
Wi-Fi and exposes Logitech's local HBus control interface. If XMPP is disabled,
the tool first attempts the same developer-option toggle used by the Harmony
mobile setup bundle: it writes `enableXMPP = 1` to
`dynamite://HomeAutomationService/Config/` through `proxy.resource?get` and
`proxy.resource?put` on the local WebSocket service.

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

The exploit fails if the hub is not fully set up, if neither XMPP nor the local
WebSocket config path is reachable, if the PC cannot reach the hub on the LAN,
or if the firmware has patched either the log-write traversal or the TDE-gated
automation/file-transfer behavior.

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
