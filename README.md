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
