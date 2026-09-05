#!/bin/sh
# Application watchdog for a rooted Harmony Hub.
#
# The hub runs everything (XMPP 5222, websocket 8088, activities, IR) in one
# single-threaded Lua process, "luaworks". rcS starts it once and nothing
# respawns it; /usr/bin/watchdog only watches the system. If luaworks hangs
# (process alive, socket LISTENING, nobody calling accept()) the hub stays
# dead until someone power-cycles it. This script notices and relaunches it.
#
# Install: copy to /data/wswatch.sh, chmod +x, and add to /etc/init.d/rcS.local:
#   (sleep 90; /data/wswatch.sh) &
#
# The hub's busybox is very stripped: no tail/head/wc/pgrep/find/nohup/sort,
# no grep -E. Only use what's here: awk sed grep cut expr pidof killall md5sum logread.
#
# Checks, once a minute:
#   1. pidof lua                       -> process gone
#   2. 8088 in LISTEN in /proc/net/tcp -> socket gone
#   3. rx_queue of that listening socket (field 5, after ':') is 00000000.
#      Non-zero for 2 cycles = connections queued, accept() not called = hung.
#      This is the real signal; the others are backups.
#   4. last "luaworks" syslog line unchanged for 3 cycles = probably stuck.
#      Never conclude anything from an EMPTY log: md5 of "" is a constant and
#      you will restart in a loop at boot.
#   5. hal flooding "wifi.status" (normal ~1 every 10 s; seen 45/s once, which
#      starved the websocket). Two consecutive fast cycles = restart.
#
# Restart = killall (SIGTERM), kill -9 if that was ignored, wait for 8088 to
# free, relaunch luaworks, verify it listens again. About 30 s.
LOG=/data/wswatch.log
FAILS=0; STALE=0; QUEUE=0; LAST=""
LASTPID=""; LASTWID=""; WIFIFAST=0

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> $LOG
  N=$(awk 'END{print NR}' $LOG 2>/dev/null)
  if [ -n "$N" ] && [ "$N" -gt 500 ]; then      # jffs2, keep it small
    sed -n '250,$p' $LOG > $LOG.tmp 2>/dev/null && mv $LOG.tmp $LOG
  fi
}

is_listen() { awk '$2 ~ /:1F98$/ && $4=="0A" {print 1}' /proc/net/tcp; }
rx_queue()  { awk '$2 ~ /:1F98$/ && $4=="0A" {split($5,a,":"); print a[2]}' /proc/net/tcp; }

restart() {
  log "RESTART luaworks (reason: $1)"
  killall lua 2>/dev/null
  sleep 3
  P=$(pidof lua)
  if [ -n "$P" ]; then
    log "SIGTERM ignored -> kill -9 $P"
    kill -9 $P 2>/dev/null
    sleep 2
  fi
  i=0
  while [ -n "$(is_listen)" ] && [ $i -lt 10 ]; do sleep 1; i=$(expr $i + 1); done
  (cd /opt/luaworks && ./luaworks --syslog --datadir=/data) &
  sleep 25
  if [ -z "$(is_listen)" ]; then
    log "relaunch FAILED: 8088 not LISTENING, will retry next cycle"
  else
    log "relaunch OK pid=$(pidof lua)"
  fi
}

log "=== watchdog started ==="
while true; do
  sleep 60
  P=$(pidof lua)
  L=$(is_listen)
  Q=$(rx_queue)
  RAW=$(logread | grep luaworks | awk 'END{print}')

  if [ "$P" != "$LASTPID" ]; then
    LASTPID="$P"; LASTWID=""; WIFIFAST=0
  fi
  WID=$(logread | grep 'cmd : wifi.status' | sed -n 's/.*\[id : \([0-9]*\)\].*/\1/p' | awk 'END{print}')
  if [ -n "$WID" ] && [ -n "$LASTWID" ]; then
    WDELTA=$(expr "$WID" - "$LASTWID")
    [ "$WDELTA" -lt 0 ] && WDELTA=$(expr "$WDELTA" + 65536)
    if [ "$WDELTA" -gt 300 ]; then
      WIFIFAST=$(expr "$WIFIFAST" + 1)
      log "ANOMALY wifi.status flood delta=$WDELTA for $WIFIFAST cycles"
      if [ "$WIFIFAST" -ge 2 ]; then
        restart "wifi.status flood delta=$WDELTA"
        LASTPID=""; LASTWID=""; WIFIFAST=0
        continue
      fi
    else
      [ "$WIFIFAST" -gt 0 ] && log "wifi.status back to normal rate"
      WIFIFAST=0
    fi
  fi
  LASTWID="$WID"

  if [ -z "$P" ]; then
    FAILS=$(expr $FAILS + 1); log "ANOMALY luaworks not running (fails=$FAILS)"
  elif [ -z "$L" ]; then
    FAILS=$(expr $FAILS + 1); log "ANOMALY 8088 not LISTENING (fails=$FAILS)"
  elif [ -n "$Q" ] && [ "$Q" != "00000000" ]; then
    QUEUE=$(expr $QUEUE + 1)
    log "ANOMALY accept queue on 8088 not empty (rx=$Q) for $QUEUE cycles"
    if [ $QUEUE -ge 2 ]; then restart "accept() stuck rx=$Q"; QUEUE=0; FAILS=0; STALE=0; fi
  elif [ -z "$RAW" ]; then
    log "luaworks log empty this cycle - no conclusion"
    LAST=""
  else
    CUR=$(echo "$RAW" | md5sum)
    if [ "$CUR" = "$LAST" ]; then
      STALE=$(expr $STALE + 1)
      log "ANOMALY luaworks log unchanged for $STALE cycles"
      if [ $STALE -ge 3 ]; then restart "log stale $STALE cycles"; STALE=0; FAILS=0; fi
    else
      if [ $FAILS -gt 0 ] || [ $STALE -gt 0 ] || [ $QUEUE -gt 0 ]; then log "back to normal"; fi
      FAILS=0; STALE=0; QUEUE=0
    fi
    LAST="$CUR"
  fi

  if [ $FAILS -ge 2 ]; then restart "fails=$FAILS"; FAILS=0; fi
done
