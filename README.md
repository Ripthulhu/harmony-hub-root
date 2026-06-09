# Harmony Hub Root

Tools for an owned Logitech Harmony Hub.

The main tool can:

- enable local XMPP
- install root SSH over LAN
- check the hub over USB
- provision Wi-Fi over USB
- install root SSH over USB
- factory reset over USB
- flash a `.hfw2` firmware bundle over USB

Only use this on your own hub.

## Quick Start

### Windows

Double-click:

```text
Start_Harmony_Hub_Tool.cmd
```

Or run it from PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_harmony_hub_tool.ps1
```

### Linux or macOS

Run:

```bash
python3 run_harmony_hub_tool.py
```

or:

```bash
sh ./run_harmony_hub_tool.sh
```

You will see this menu:

```text
1. LAN root SSH install
2. Enable XMPP over LAN
3. USB preflight
4. USB sysinfo
5. Wi-Fi status over USB
6. Wi-Fi scan over USB
7. Provision Wi-Fi over USB
8. USB root SSH install
9. Factory reset over USB
10. Flash firmware over USB (.hfw2)
```

## What To Pick

- Choose `1` if the hub is already on your LAN and you want root SSH.
- Choose `2` if you only want to turn local XMPP back on.
- Choose `3` first when testing USB. It is read-only.
- Choose `4` to print hub info over USB.
- Choose `5` or `6` to check Wi-Fi over USB.
- Choose `7` to put the hub on Wi-Fi over USB, similar to MyHarmony setup.
- Choose `8` for the USB root SSH path.
- Choose `9` to factory reset the hub over USB.
- Choose `10` to flash a Logitech `.hfw2` firmware bundle over USB.

If you are not sure where to start, use `3. USB preflight` for USB work or
`2. Enable XMPP over LAN` for LAN work.

## Requirements

- Python 3.10 or newer
- OpenSSH client tools: `ssh` and `ssh-keygen`
- A Harmony Hub you own
- For LAN actions: the hub IP address, with your computer and hub on the same network
- For USB actions: a USB cable connected to the hub

The hub should already have completed normal first-time setup at least once.

## USB On Linux And macOS

Windows uses a native HID backend and does not need hidapi.

Linux can usually use `/dev/hidraw*` directly. If the tool finds the hub but
cannot open it, run once with `sudo` or add a udev rule:

```text
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="046d", ATTRS{idProduct}=="c129", MODE="0660", TAG+="uaccess"
```

Then reload udev rules and reconnect the hub.

macOS needs the Python hidapi package:

```bash
python3 -m pip install -r requirements-usb.txt
```

Linux can also use hidapi if you prefer:

```bash
python3 -m pip install -r requirements-usb.txt
```

## Direct Commands

Windows:

```powershell
.\run_harmony_hub_tool.ps1 -Action lan-root -HubHost "<hub-ip>"
.\run_harmony_hub_tool.ps1 -Action enable-xmpp -HubHost "<hub-ip>"
.\run_harmony_hub_tool.ps1 -Action usb-preflight
.\run_harmony_hub_tool.ps1 -Action usb-provision-wifi -Ssid "<ssid>" -WifiPassword "<password>"
.\run_harmony_hub_tool.ps1 -Action usb-factory-reset
.\run_harmony_hub_tool.ps1 -Action usb-flash-firmware -FirmwareFile "C:\path\to\firmware.hfw2"
```

Linux/macOS:

```bash
python3 run_harmony_hub_tool.py --action lan-root --hub-host "<hub-ip>"
python3 run_harmony_hub_tool.py --action enable-xmpp --hub-host "<hub-ip>"
python3 run_harmony_hub_tool.py --action usb-preflight
python3 run_harmony_hub_tool.py --action usb-provision-wifi --ssid "<ssid>" --wifi-password "<password>"
python3 run_harmony_hub_tool.py --action usb-factory-reset
python3 run_harmony_hub_tool.py --action usb-flash-firmware --firmware-file "/path/to/firmware.hfw2"
```

Wi-Fi provisioning saves the network by default. Add `-NoSave` on PowerShell or
`--no-save` with Python for a temporary connection.

Factory reset and firmware flashing ask for confirmation before writing to the
hub. For unattended use, add `-Yes` on PowerShell or `--yes` with Python.

The flasher reads `Description.xml` inside the `.hfw2` to find the firmware
image, remote path, checksum command, and reboot flag. It does not try to detect
the connected hub's SKIN and it does not block firmware based on `INTENDED/SKIN`
metadata.

## After LAN Root

The LAN root flow creates or reuses this SSH key:

```text
%USERPROFILE%\.ssh\harmony_owner_ed25519
```

On Linux/macOS this is:

```text
~/.ssh/harmony_owner_ed25519
```

When it finishes, it writes hub ID handoff files for the web UI installer:

```text
%USERPROFILE%\.harmony-hub\hub_id.txt
%USERPROFILE%\.harmony-hub\last_root.json
%USERPROFILE%\.harmony-hub\known_hubs.json
```

On Linux/macOS these live under:

```text
~/.harmony-hub/
```

Do not guess the hub ID. Use the one printed by the tool.

## What Root SSH Installs

```text
/etc/tdeenable
/data/rootssh/bin/dropbearmulti
/usr/sbin/dropbear
/usr/sbin/dropbearkey
/home/root/.ssh/authorized_keys
```

SSH should survive power cycles through the hub's own TDE boot path.

## Root Vulnerability

The LAN root path uses old local-control plumbing that Logitech left in the
Harmony Hub firmware.

The important pieces are:

- The hub can expose a local XMPP service on port `5222`.
- That XMPP service can pass commands into the hub's internal HBus API.
- One HBus command, `harmony.log?put`, writes log files using a caller-supplied
  filename.
- On affected firmware, that filename is not locked down properly.

Because of that filename bug, a request can escape the normal log directory and
write `/etc/tdeenable`.

`/etc/tdeenable` matters because it is a real Logitech debug/development-mode
switch. Once the file exists, APIs that are normally blocked in production mode
become usable, including the JSON file-transfer path.

The tool then uses those newly available APIs to stage a small Lua package on
the hub. When `harmony.automation?discover` is called with the package name, the
hub loads the package and runs the Lua code. The Lua installer writes Dropbear,
sets permissions, installs your SSH public key, and starts SSH as root.

The short version:

```text
XMPP/HBus access
  -> harmony.log?put path traversal
  -> write /etc/tdeenable
  -> unlock TDE file-transfer APIs
  -> stage Lua package
  -> trigger harmony.automation?discover
  -> install Dropbear SSH
```

SSH persists because the stock firmware already checks `/etc/tdeenable` during
boot and starts `/usr/sbin/dropbear` in that mode. This tool installs a wrapper
there that launches the bundled Dropbear binary.

If XMPP is off, the tool first tries to turn it on through the local WebSocket
service on port `8088` by updating the hub's home automation config.

The USB path uses the same hub-side APIs, but reaches them through the hub's USB
HID interface instead of the LAN XMPP socket. The USB device is `046d:c129`, and
normal commands are sent as LTCP-framed JSON, matching Logitech's desktop tools.
Factory reset and firmware flashing use the lower-level LTCP file protocol from
the MyHarmony USB templates.

## Troubleshooting

If SSH says the host key changed, remove the old hub entry from
`known_hosts` and reconnect.

If USB does not work:

- run `usb-preflight` first
- reconnect the hub
- on Linux, check hidraw permissions or try `sudo`
- on macOS, install `requirements-usb.txt`

If LAN rooting fails, check that the hub is already set up, the IP address is
right, and your computer can reach the hub on the same network.

## Files

- `Start_Harmony_Hub_Tool.cmd` - Windows launcher
- `run_harmony_hub_tool.ps1` - Windows runner
- `run_harmony_hub_tool.py` - cross-platform runner
- `run_harmony_hub_tool.sh` - Linux/macOS wrapper
- `harmony_xmpp_root_shell.py` - LAN XMPP/HBus code
- `harmony_usb_bridge.py` - cross-platform USB code
- `harmony_usb_bridge.ps1` - Windows USB code
- `harmony_usb_hid_probe.ps1` - Windows HID probe
- `rootsshusb.lua` - hub-side USB SSH installer
- `dropbearmulti` - MIPS Dropbear binary
- `requirements-usb.txt` - optional hidapi dependency
- `SHA256SUMS.txt` - file hashes

## Tested Firmware

Tested on Harmony Hub firmware `4.15.600`.
