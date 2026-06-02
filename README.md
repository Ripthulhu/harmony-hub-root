# Harmony Hub LAN Root SSH Tool

For an owned Logitech Harmony Hub on the same LAN as a Windows PC.

## Files

- `Start_XMPP_Root_Shell.cmd` - double-click launcher
- `run_xmpp_root_shell.ps1` - PowerShell wrapper
- `harmony_xmpp_root_shell.py` - LAN installer
- `dropbearmulti` - MIPS Dropbear binary for Harmony Hub
- `SHA256SUMS.txt` - integrity hashes

## Requirements

- Windows 10/11
- Python 3.10 or newer
- Windows OpenSSH client
- Harmony Hub IP address
- PC and hub on the same LAN
- The hub has completed normal first-time setup in the Harmony phone app
- XMPP/local network control is enabled in the Harmony phone app

## Run

Finish setup in the Harmony phone app first. The hub must already be joined to
Wi-Fi, linked to the app, and reachable on the local network with XMPP enabled.

Double-click:

```text
Start_XMPP_Root_Shell.cmd
```

Enter the hub IP address when prompted.

The tool creates an SSH key at:

```text
%USERPROFILE%\.ssh\harmony_owner_ed25519
```

It installs persistent root SSH and then opens a root shell:

```text
ssh -i %USERPROFILE%\.ssh\harmony_owner_ed25519 root@<hub-ip>
```

## How It Works

The tool uses the hub's local LAN control surface after the hub has been
provisioned normally. The phone app setup is important because it joins the hub
to Wi-Fi and enables the local XMPP/HBus service used by older Harmony control
clients.

At a high level, the installer does this:

1. Connects to the hub's local XMPP service on port `5222`.
2. Calls `connect.sysinfo?get` to confirm the hub is reachable and to collect
   identifiers used by the local HBus/WebSocket path.
3. Uses `harmony.log?put` with a path traversal filename to write
   `/etc/tdeenable`.
4. Restarts or refreshes the Harmony application layer so the hub sees TDE mode.
5. Uses the now-unlocked JSON file transfer APIs to stage a small Lua installer
   package and the Dropbear SSH payload under writable storage.
6. Triggers the staged Lua installer through `harmony.automation?discover`.
7. The Lua installer creates the root SSH directory, installs the generated
   public key into `/home/root/.ssh/authorized_keys`, installs the MIPS
   `dropbearmulti` binary, creates the Dropbear wrapper symlinks, generates host
   keys if needed, and starts Dropbear on port `22`.

Persistence comes from `/etc/tdeenable`. On boot, the stock Harmony init path
checks that file and runs `/usr/sbin/dropbear`, so the wrapper installed by this
tool starts SSH again after a power cycle. The script also starts Dropbear
immediately, so a reboot is not required after a successful run.

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
`%USERPROFILE%\.ssh\known_hosts` and reconnect. This is expected if the hub was
previously rooted or reset.
