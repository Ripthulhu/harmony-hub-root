# Harmony Hub Root

Install persistent, key-only root SSH on a Logitech Harmony Hub over LAN.
The same Python tool includes USB diagnostics, Wi-Fi setup, factory reset, and
firmware upload. MyHarmony, a build server, SCP, and TFTP are not required to
run it. Use it only on hubs you own or have permission to modify.

The root procedure was tested on firmware **4.15.600**. Other firmware versions
and hardware revisions are not confirmed. USB-only rooting is not implemented;
USB can put a hub on Wi-Fi, but rooting still uses the LAN connection.

## Before you start

1. Download and extract the whole repository. Keep the Python files and
   `dropbearmulti` together; do not run from inside the ZIP viewer.
2. Install Python 3.10 or newer. LAN rooting also needs the OpenSSH client tools
   `ssh` and `ssh-keygen` in your PATH.
3. Complete the hub's initial setup in the Harmony phone app and enable XMPP
   there. The computer must be able to reach the hub on the local network.
4. Find the hub's IP address in your router or the Harmony app.

The tool can try to enable XMPP through port 8088 when port 5222 is closed.
That attempt depends on the hub's configuration and does not replace initial
setup. A factory-reset hub needs setup again, even if USB Wi-Fi provisioning
succeeds.

Keep the SSH private key. Anyone who has it can log in as root. Keep the hub's
SSH and control ports off the public internet.

## Run the tool

`run_harmony_hub_tool.py` is the entry point on every OS. It opens a menu when
started without arguments in a terminal.

Windows:

```powershell
python run_harmony_hub_tool.py
```

You can also double-click `Start_Harmony_Hub_Tool.cmd`. It keeps the window open
after an interactive run. When called with arguments, it returns the tool's exit
code without pausing. `HARMONY_NO_PAUSE=1` disables the pause for all runs.

Linux and macOS:

```sh
python3 run_harmony_hub_tool.py
```

`sh run_harmony_hub_tool.sh` is an optional launcher that also checks for a local
`.venv`. On Windows, `Start_Harmony_Hub_Tool.cmd` provides the same convenience.
Both launchers accept the Python CLI options, including `--action` and
`--hub-host`.

## LAN root and SSH

The examples below use `python3`. On Windows, use `python` or `py -3` instead.
Replace `<hub-ip>` with your hub's address.

```sh
python3 run_harmony_hub_tool.py --action lan-root --hub-host "<hub-ip>"
```

The tool creates or reuses `~/.ssh/harmony_owner_ed25519`, installs its public
key, starts Dropbear, waits for port 22, and opens an SSH session. `~` means the
current user's home directory, including `%USERPROFILE%` on Windows.

Use `--private-key "path/to/key"` to choose another key. Its public key defaults
to the same path with `.pub` appended. `--pubkey` accepts a different public-key
path, but it must match the private key. Quote paths containing spaces. Relative
paths are resolved from the directory where you run the command.

Use `--no-shell` to install SSH without opening an interactive session, or
`--ssh-wait 180` to allow more time for SSH to start. To reconnect:

```sh
ssh -i ~/.ssh/harmony_owner_ed25519 -o IdentitiesOnly=yes root@<hub-ip>
```

A changed SSH host key does not undo the installation. Verify that the IP still
belongs to your hub before replacing its old `known_hosts` entry. The tool leaves
that entry alone and prints a warning if the final SSH client fails.

### Files changed on the hub

```text
/etc/tdeenable
/data/rootssh/bin/dropbearmulti
/data/rootssh/bin/dropbear       (symlink)
/data/rootssh/bin/dropbearkey    (symlink)
/usr/sbin/dropbear              (wrapper)
/usr/sbin/dropbearkey           (wrapper)
/home/root/.ssh/authorized_keys
/etc/dropbear/dropbear_rsa_host_key  (created if missing)
```

The stock TDE boot path starts the installed wrapper after a power cycle.
Firmware replacement or a reset can affect this setup; persistence has not been
verified across those operations. Re-running the installer replaces
`authorized_keys` with the selected public key and restarts Dropbear. Back up
existing SSH access before using it on an already modified hub.

This tool does not install the web UI, MQTT service, or cloud blocker. Those are
in [harmony-hub-control](https://github.com/Ripthulhu/harmony-hub-control).

### Hub ID handoff

When the hub reports its ID, the tool prints it and saves these files for the
control installer:

```text
~/.harmony-hub/hub_id.txt
~/.harmony-hub/last_root.json
~/.harmony-hub/known_hubs.json
```

The ID is specific to the hub's provisioning. Do not substitute another hub's
ID. The default lookup uses host-scoped records; `--hub-id` supplies a known ID
explicitly. After a reset, use this to ignore and clear stale records:

```sh
python3 run_harmony_hub_tool.py --action lan-root --hub-host "<hub-ip>" --ignore-saved-hub-id --clear-saved-hub-id
```

Clearing removes the last/global handoff files and this host's entry in
`known_hubs.json`. Other host entries remain. `--use-global-saved-hub-id` opts
into legacy records that are not tied to an IP; leave it off when using multiple
hubs.

## USB setup and diagnostics

Use a data-capable USB cable. The cable also powers the hub, so reconnecting it
causes a cold boot. Wait for the hub to finish booting. Close MyHarmony and any
other process using the hub before running a USB action.

Windows uses the native HID backend without extra Python packages. Linux can
use `/dev/hidraw*`. If Linux reports a permission error, give your local user
access through a udev rule such as:

```text
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="046d", ATTRS{idProduct}=="c129", MODE="0660", TAG+="uaccess"
```

Install the rule under `/etc/udev/rules.d/`, reload the rules, then reconnect the
hub. Headless sessions may need a device-access group instead of `uaccess`.
Avoid running the whole tool as root: that uses root's SSH keys and handoff
directory rather than yours.

macOS needs `hidapi`. It is optional on Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-usb.txt
.venv/bin/python run_harmony_hub_tool.py --action usb-preflight
```

| Action | What it does |
| --- | --- |
| `usb-preflight` | Reads device information over USB to check the connection |
| `usb-sysinfo` | Reads `/rf/deviceinfo` |
| `usb-hub-id` | Reads the provisioned hub ID; add `--save-hub-id` to save it locally |
| `usb-wifi-status` | Reads the current Wi-Fi state |
| `usb-wifi-scan` | Lists nearby networks; add `--show-ssids` to show names |
| `usb-provision-wifi` | Writes Wi-Fi settings |
| `usb-factory-reset` | Requests a factory reset and reboot |
| `usb-flash-firmware` | Uploads a supplied `.hfw2` firmware bundle |

Start with a read-only check:

```sh
python3 run_harmony_hub_tool.py --action usb-preflight
python3 run_harmony_hub_tool.py --action usb-wifi-status
python3 run_harmony_hub_tool.py --action usb-wifi-scan --show-ssids
```

Preflight uses the hub's raw USB file protocol. It does not test file writes or
enable SSH. To list detected USB interfaces without sending a hub command:

```sh
python3 harmony_usb_bridge.py --action probe
```

To change Wi-Fi, leave the password out of the command and enter it at the
hidden prompt:

```sh
python3 run_harmony_hub_tool.py --action usb-provision-wifi --ssid "Your Wi-Fi"
```

Settings are saved unless you add `--no-save`. `--encryption OPEN` permits an
open network. `--hide-ssids` hides network names in output. Passwords are
redacted from normal status output, but review diagnostic logs before sharing
them: device IDs and other details can still identify your hub.

`--wifi-password` remains available for scripts. A password passed on the
command line may appear in shell history and process listings. A password
entered at the prompt stays within the Python process.

### Reset and firmware upload

Both actions ask you to type `YES`. `--yes` skips that confirmation for scripts;
it does not supply missing options.

```sh
python3 run_harmony_hub_tool.py --action usb-factory-reset
python3 run_harmony_hub_tool.py --action usb-flash-firmware --firmware-file "firmware.hfw2"
```

A factory reset clears configuration; it is not proof that all custom files
were removed. Complete setup in the phone app before attempting LAN root again.

Supply a firmware bundle intended for your exact hub. The tool reads
`Description.xml` and verifies each image's declared MD5 before uploading it.
MD5 checks integrity, not Logitech authenticity. The bundle's intended hardware
IDs are displayed but are not automatically checked against the connected hub.

For the tested OTA path, the tool writes the contained `ota-update.EzHex` to
`/fw/otaupdate`. USB checksum result `0x75` (`u`) can mean the boot updater still
needs to process the upload. A transfer or reboot alone does not confirm that
the firmware was installed. Do not interrupt power. Check the firmware version
after boot and, if SSH is still available, inspect `/cache/ota-update.log` for
verified images and `Done!`. USB recovery on Linux/macOS needs hardware testing.

## How LAN rooting works

The affected firmware exposes an XMPP service on port 5222. The tool uses the
local SASL PLAIN login accepted by that service to send HBus commands. This does
not require the owner's Logitech cloud password.

`harmony.log?put` accepts a caller-supplied filename. On the tested firmware,
directory traversal lets that write escape the log directory and create
`/etc/tdeenable`. The hub's privileged service performs the write, so normal
filesystem permissions do not protect the destination from this API.

The firmware treats that file as its test/development-mode switch. Once the
service recognizes it, the JSON file-transfer APIs become available. The tool
checks the gate, refreshes the service session when needed, and stages a Lua
package through those APIs. A successful log-write response alone is not proof
that the gate is open.

Calling `harmony.automation?discover` with the staged package name makes the hub
load its Lua code. The installer runs with the service's root privileges, writes
the MIPS Dropbear binary and wrappers, sets permissions, installs the supplied
SSH public key, and starts Dropbear. At the next boot, the stock TDE startup
code sees `/etc/tdeenable` and starts `/usr/sbin/dropbear` again.

The chain depends on local API access, a privileged path-traversal write, a
file-controlled development gate, and a Lua loader that accepts the staged
package. Matching firmware versions alone do not guarantee matching behavior:
provisioning, XMPP availability, and existing modifications also affect the
result.

## Troubleshooting and tests

- Port 5222 closed: finish app setup, enable XMPP in the app, and check local
  network access. `--action enable-xmpp --hub-host "<hub-ip>"` runs only the
  optional 8088 toggle. `--no-enable-xmpp` skips it during rooting.
- `Wrong hubId`: ignore stale saved IDs as shown above; do not guess an ID.
- Production-mode errors: keep the full error output. A reboot alone is not
  evidence that the TDE gate opened.
- USB unavailable: check the data cable, boot time, competing apps, permissions,
  and the selected Python environment. `--usb-backend` can select `winhid`,
  `hidraw`, or `hidapi` explicitly.
- Running without a terminal: supply `--action` and required settings. Missing
  input exits with an error rather than waiting for a prompt. Use `--no-shell`
  for unattended LAN installation.

Check local inputs without contacting the hub or changing keys/cache files:

```sh
python3 run_harmony_hub_tool.py --action lan-root --dry-run
python3 run_harmony_hub_tool.py --action usb-flash-firmware --firmware-file "firmware.hfw2" --dry-run
```

A LAN dry run checks the binary and builds the payload if a public key exists.
It does not generate keys, verify a key pair, or prove that a hub is vulnerable.
A USB dry run does not load a USB backend or open hardware.

Offline regression tests run with Python's standard library:

```sh
python3 -m unittest discover -s tests -v
```

These tests cover CLI dispatch, launchers, file paths, dry runs, SSH keys, reply
framing, Wi-Fi validation, USB locking, and firmware parsing. They have been run
locally on Windows and Linux/WSL. The CI workflow also includes macOS. Offline
tests do not prove that rooting, reset, or flashing works on a particular hub.

The transport implementations are in `harmony_xmpp_root_shell.py` and
`harmony_usb_bridge.py`. `SHA256SUMS.txt` records the distributed files; it is
an integrity list, not a signed release.
