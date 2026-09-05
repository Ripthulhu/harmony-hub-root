# contrib: keeping a rooted hub alive, and getting your IR codes off it

Two things that turned out useful once the hub was rooted.

## wswatch.sh, an application watchdog

The hub runs XMPP, the websocket Home Assistant uses, activities and IR sending in
**one single-threaded Lua process** (`/opt/luaworks/luaworks`). `rcS` starts it once,
nothing respawns it, and `/usr/bin/watchdog` only checks that the kernel is alive.
When luaworks *hangs* rather than dies (process up, port 8088 still LISTENING, but
`accept()` never called) the hub is dead until you pull the plug. Mine sat like that
for 86 minutes once.

`wswatch.sh` polls every 60 s and relaunches luaworks when it sees that. The reliable
signal is the `rx_queue` of the 8088 listening socket in `/proc/net/tcp`: `00000000`
when healthy, non-zero when connections pile up unanswered. The header of the script
lists the other checks and the busybox limitations you will hit (no `tail`, `head`,
`pgrep`, `grep -E`...).

Install:

```sh
scp wswatch.sh root@HUB:/data/
ssh root@HUB 'chmod +x /data/wswatch.sh; echo "(sleep 90; /data/wswatch.sh) &" >> /etc/init.d/rcS.local'
```

It logs to `/data/wswatch.log` (self-rotating, jffs2 is small). The hub clock reads
1970 until NTP catches up after a reboot, so a 1970 line means the hub rebooted.

This does **not** fix the short (30 s to 3 min) `unavailable` blips in Home Assistant.
Those happen with the process alive and the port open; the thread is just too busy to
answer the websocket ping in time. Still looking at that one.

## harmony-ir-extract.py, your IR codes as ESPHome YAML

Logitech shut down the members site in May 2025, so a hub can't be reconfigured any
more and the IR codes it holds are the only copy you have. The config you get from the
Harmony API (`aioharmony`, the HA integration, etc.) only has command *references*.
The actual codes are in two files on the hub:

```sh
scp root@HUB:/data/resources/DeviceList.json root@HUB:/data/resources/ProtocolList.json .
python3 harmony-ir-extract.py DeviceList.json ProtocolList.json            # readable table
python3 harmony-ir-extract.py DeviceList.json ProtocolList.json --esphome  # transmit_raw YAML
```

Each command has a `KeyCode` like `G:Pioneer 32 Bit Dual:()(0xA55AEA15_0xA55A807F)():3`
and `ProtocolList.json` has the header/bit/trailer timings and carrier frequency per
protocol, so the script rebuilds the raw pulse train. Bit order was checked against a
Samsung TV whose codes are public. Bluetooth and HID profiles (Fire TV, "Windows PC")
have no IR and are skipped. I have not flashed the ESP32 yet, so verify one code with
a receiver before trusting a whole device.

## Bonus: the remote's button presses are in syslog

```
he.m.device [9]: device: [ id: 82434888 ] [ name: Amazon Fire TV ] [ command: directionup ] [ modifier: press ]
```

`logread -f` over SSH piped into a Home Assistant webhook turns the physical remote
into a generic HA trigger. Forward only `modifier: press`, or everything counts twice.
Button-to-command mapping (including long and double press) is in
`/data/resources/MapList.json`.
