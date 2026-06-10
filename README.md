# Harmony Hub Root

The tool can:

- enable local XMPP when needed
- install persistent root SSH over LAN
- test the Harmony Hub USB HID connection
- read USB sysinfo and Wi-Fi state
- scan and change Wi-Fi over USB
- factory reset over USB
- flash a Logitech `.hfw2` firmware bundle over USB

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
./run_harmony_hub_tool.sh
```

or:

```bash
python3 run_harmony_hub_tool.py
```

You will see this menu:

```text
1. Give me root! (roots the device over LAN and enables SSH)
2. USB connection test / diagnostics
3. USB sysinfo
4. Wi-Fi status over USB
5. Wi-Fi scan over USB
6. Change Wi-Fi over USB
7. Factory reset over USB (requires Harmony app setup afterwards)
8. Flash firmware over USB (.hfw2)
```

## What To Pick

- Choose `1` if the hub is already on your LAN and you want root SSH. This also handles the XMPP-enable step when possible.
- Choose `2` first when testing USB. It is read-only unless you explicitly pass the advanced `--write-probe` flag to the USB bridge directly.
- Choose `3` to print hub information over USB.
- Choose `4` or `5` to inspect Wi-Fi over USB.
- Choose `6` to put the hub on Wi-Fi over USB, similar to MyHarmony setup.
- Choose `7` to factory reset the hub over USB. After a factory reset, set the hub up again with the Harmony app before normal use.
- Choose `8` to flash a Logitech `.hfw2` firmware bundle over USB.

If you are not sure where to start, use `2. USB connection test / diagnostics` for USB work or `1. Give me root!` for LAN root work.

## Requirements

- Python 3.10 or newer
- OpenSSH client tools: `ssh` and `ssh-keygen`
- A Harmony Hub you own
- For LAN actions: the hub IP address, with your computer and hub on the same network
- For USB actions: a USB cable connected to the hub

The hub should already have completed normal first-time setup at least once. A freshly factory-reset hub can be provisioned over USB, but normal account-backed setup still needs the Harmony app.

## USB On Linux And macOS (untested)

Windows uses the native `winhid` backend and does not need hidapi.

Linux can usually use `/dev/hidraw*` directly without extra Python packages. If the tool finds the hub but cannot open it, run once with `sudo` or add a udev rule:

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

Windows PowerShell:

```powershell
.\run_harmony_hub_tool.ps1 -Action lan-root -HubHost "<hub-ip>"
.\run_harmony_hub_tool.ps1 -Action usb-preflight
.\run_harmony_hub_tool.ps1 -Action usb-provision-wifi -Ssid "<ssid>" -WifiPassword "<password>"
.\run_harmony_hub_tool.ps1 -Action usb-factory-reset
.\run_harmony_hub_tool.ps1 -Action usb-flash-firmware -FirmwareFile "C:\path\to\firmware.hfw2"
```

Linux/macOS:

```bash
python3 run_harmony_hub_tool.py --action lan-root --hub-host "<hub-ip>"
python3 run_harmony_hub_tool.py --action usb-preflight
python3 run_harmony_hub_tool.py --action usb-provision-wifi --ssid "<ssid>" --wifi-password "<password>"
python3 run_harmony_hub_tool.py --action usb-factory-reset
python3 run_harmony_hub_tool.py --action usb-flash-firmware --firmware-file "/path/to/firmware.hfw2"
```

Advanced CLI-only actions are still available for scripting and diagnostics, including `--action enable-xmpp` and `--action usb-hub-id`, but they are not shown in the interactive menu.

Wi-Fi provisioning saves the network by default. Add `-NoSave` on PowerShell or `--no-save` with Python for a temporary connection.

The USB actions use the same HID file protocol as MyHarmony. Sysinfo reads `/rf/deviceinfo`, Wi-Fi status reads `/sys/wifi/connect`, network scan reads `/sys/wifi/networks`, and provisioning writes `/sys/wifi/connect`.

Factory reset and firmware flashing ask for confirmation before writing to the hub. For unattended use, add `-Yes` on PowerShell or `--yes` with Python. After factory reset, the hub must be set up again with the Harmony app before normal use.

The flasher reads `Description.xml` inside the `.hfw2` to find the firmware image, remote path, checksum command, and reboot flag. It extracts and writes the contained `ota-update.EzHex` payload to `/fw/otaupdate`; it does not write the `.hfw2` zip bytes directly and it does not write a fully extracted filesystem folder.

A successful firmware handoff may report USB checksum result `0x75/'u'`. For the firmware upgrade path this is not fatal: the bridge closes `/fw/otaupdate`, reboots the hub, and the boot updater consumes `/cache/ota-update.zip`. Validate success after reboot with:

```sh
cat /cache/ota-update.log
cat /etc/version
```

The expected OTA log includes `sha1 verified` for `uImage.bin` and `harmony-image.squashfs`, followed by `Done!`.

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

After a factory reset, cached hub IDs may be stale. If 8088 returns `Wrong hubId`, run with:

```bash
python3 run_harmony_hub_tool.py --action lan-root --hub-host "<hub-ip>" --clear-saved-hub-id --ignore-saved-hub-id
```

Do not guess the hub ID. Use the one printed by the tool or recovered from the hub after account setup.

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

The USB path is for setup, recovery, and diagnostics. It reaches the hub through
the USB HID interface instead of the LAN XMPP socket. The USB device is
`046d:c129`, and the tool uses the lower-level LTCP file protocol from the
MyHarmony USB templates for reads, Wi-Fi provisioning, factory reset, and
firmware flashing.

## Troubleshooting

If SSH says the host key changed, remove the old hub entry from
`known_hosts` and reconnect.

If USB does not work:

- run `usb-preflight` first
- reconnect the hub
- on Windows, close MyHarmony, Internet Explorer, Edge IE-mode recovery pages,
  and Logitech plugin services before running USB actions
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
- `harmony_usb_bridge.py` - cross-platform USB code used by the unified runner
- `harmony_usb_hid_probe.ps1` - Windows HID probe
- `dropbearmulti` - MIPS Dropbear binary
- `requirements-usb.txt` - optional hidapi dependency
- `SHA256SUMS.txt` - file hashes

## Tested Firmware

Tested on Harmony Hub firmware `4.15.600`.
