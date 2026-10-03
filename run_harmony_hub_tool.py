#!/usr/bin/env python3
"""Unified Harmony Hub tool for Windows, Linux, and macOS."""

from __future__ import annotations

import argparse
import getpass
import pathlib
import subprocess
import sys

if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required.")

import harmony_xmpp_root_shell as lan
import harmony_usb_bridge as usb

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
ACTION_CHOICES = (
    "",
    "lan-root",
    "enable-xmpp",
    "usb-preflight",
    "usb-sysinfo",
    "usb-hub-id",
    "usb-wifi-status",
    "usb-wifi-scan",
    "usb-provision-wifi",
    "usb-factory-reset",
    "usb-flash-firmware",
)


def read_action() -> str:
    if not sys.stdin.isatty():
        raise SystemExit("--action is required when running without an interactive terminal. See --help.")
    print("")
    print("Harmony Hub Tool")
    print("1. Give me root! (roots the device over LAN and enables SSH)")
    print("2. USB connection test / diagnostics")
    print("3. USB sysinfo")
    print("4. Wi-Fi status over USB")
    print("5. Wi-Fi scan over USB")
    print("6. Change Wi-Fi over USB")
    print("7. Factory reset over USB (requires Harmony app setup afterwards)")
    print("8. Flash firmware over USB (.hfw2)")
    print("")
    mapping = {
        "1": "lan-root",
        "2": "usb-preflight",
        "3": "usb-sysinfo",
        "4": "usb-wifi-status",
        "5": "usb-wifi-scan",
        "6": "usb-provision-wifi",
        "7": "usb-factory-reset",
        "8": "usb-flash-firmware",
    }
    while True:
        choice = input("Choose an action [1-8]: ").strip()
        if choice in mapping:
            return mapping[choice]
        print("Enter a number from 1 to 8.")


def resolve_host_alias(args: argparse.Namespace) -> None:
    if args.hub_host and args.hub_ip and args.hub_host != args.hub_ip:
        raise SystemExit("--hub-host and --hub-ip must refer to the same hub; supply only one.")
    if not args.hub_host and args.hub_ip:
        args.hub_host = args.hub_ip
    if not args.hub_ip and args.hub_host:
        args.hub_ip = args.hub_host


def prompt_value(label: str, flag: str, secret: bool = False) -> str:
    if not sys.stdin.isatty():
        raise SystemExit(f"{flag} is required without an interactive terminal.")
    value = getpass.getpass(label) if secret else input(label)
    if not value:
        raise SystemExit(f"{flag} must not be empty.")
    return value


def lan_args(args: argparse.Namespace, enable_xmpp_only: bool) -> list[str]:
    resolve_host_alias(args)
    if not args.hub_host and not args.dry_run:
        args.hub_host = prompt_value("Harmony Hub IP address: ", "--hub-host").strip()
    dropbearmulti = args.dropbearmulti or str(SCRIPT_DIR / "dropbearmulti")
    private_key = args.private_key or str(pathlib.Path.home() / ".ssh" / "harmony_owner_ed25519")
    pubkey = args.pubkey or private_key + ".pub"
    argv = [
        "--dropbearmulti",
        dropbearmulti,
        "--private-key",
        private_key,
        "--pubkey",
        pubkey,
    ]
    if args.hub_host:
        argv += ["--host", args.hub_host]
    for hub_id in args.hub_id:
        argv += ["--hub-id", hub_id]
    if args.xmpp_enable_wait != 90:
        argv += ["--xmpp-enable-wait", str(args.xmpp_enable_wait)]
    argv += ["--ssh-wait", str(args.ssh_wait)]
    if args.no_enable_xmpp:
        argv.append("--no-enable-xmpp")
    if enable_xmpp_only:
        argv.append("--enable-xmpp-only")
    if args.no_shell:
        argv.append("--no-shell")
    if args.ignore_saved_hub_id:
        argv.append("--ignore-saved-hub-id")
    if args.use_global_saved_hub_id:
        argv.append("--use-global-saved-hub-id")
    if args.clear_saved_hub_id:
        argv.append("--clear-saved-hub-id")
    if args.dry_run:
        argv.append("--dry-run")
    return argv


def usb_args(args: argparse.Namespace, usb_action: str) -> list[str]:
    resolve_host_alias(args)
    argv = [
        "--action",
        usb_action,
        "--backend",
        args.usb_backend,
    ]
    if args.hub_ip:
        argv += ["--hub-ip", args.hub_ip]
    if args.ssid:
        argv += ["--ssid", args.ssid]
    if args.wifi_password != "":
        argv += ["--wifi-password", args.wifi_password]
    if args.encryption:
        argv += ["--encryption", args.encryption]
    if args.no_save:
        argv.append("--no-save")
    if args.show_ssids:
        argv.append("--show-ssids")
    if args.hide_ssids:
        argv.append("--hide-ssids")
    if args.raw_output:
        argv.append("--raw-output")
    if args.save_hub_id:
        argv.append("--save-hub-id")
    if args.wait_for_lan:
        argv += ["--wait-for-lan", "--lan-port", str(args.lan_port), "--lan-wait-seconds", str(args.lan_wait_seconds)]
    if args.firmware_file:
        argv += ["--firmware-file", args.firmware_file]
    if args.firmware_packets_per_chunk != 500:
        argv += ["--firmware-packets-per-chunk", str(args.firmware_packets_per_chunk)]
    if args.yes:
        argv.append("--yes")
    if args.dry_run:
        argv.append("--dry-run")
    return argv


def ensure_usb_prompt_args(args: argparse.Namespace, action: str) -> None:
    if args.dry_run:
        return
    if action == "usb-wifi-scan" and not (args.show_ssids or args.hide_ssids or args.yes) and sys.stdin.isatty():
        answer = input("Show SSIDs in scan output? [y/N]: ").strip().lower()
        if answer in {"y", "yes"}:
            args.show_ssids = True
    elif action == "usb-provision-wifi":
        resolve_host_alias(args)
        if not args.ssid and not args.dry_run:
            args.ssid = prompt_value("Wi-Fi SSID: ", "--ssid")
        if not args.encryption:
            args.encryption = "WPA2-PSK"
        if args.encryption.upper() not in {"NONE", "OPEN"} and args.wifi_password == "" and not args.dry_run:
            args.wifi_password = prompt_value("Wi-Fi password: ", "--wifi-password", secret=True)
        if args.dry_run:
            return
        if not args.wait_for_lan and not args.yes and sys.stdin.isatty():
            answer = input("Wait for LAN reachability after provisioning? [y/N]: ").strip().lower()
            if answer in {"y", "yes"}:
                args.wait_for_lan = True
        if args.wait_for_lan and not args.hub_ip:
            args.hub_ip = prompt_value("Expected hub IP for LAN check: ", "--hub-ip").strip()
    elif action == "usb-flash-firmware":
        if not args.firmware_file:
            args.firmware_file = prompt_value("Path to .hfw2 firmware file: ", "--firmware-file").strip().strip('"')
    elif action == "usb-factory-reset":
        return


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified Harmony Hub tool")
    parser.add_argument("--action", choices=ACTION_CHOICES, default="")
    parser.add_argument("--hub-host", "--host", default="", help="Hub IP address or hostname for LAN actions")
    parser.add_argument("--hub-ip", default="")
    parser.add_argument("--hub-id", action="append", default=[])
    parser.add_argument("--ignore-saved-hub-id", action="store_true", help="do not use cached Hub IDs for LAN/XMPP actions")
    parser.add_argument("--use-global-saved-hub-id", action="store_true", help="allow legacy global hub_id.txt cache entries")
    parser.add_argument("--clear-saved-hub-id", action="store_true", help="clear cached Hub ID handoff files before LAN/XMPP actions")
    parser.add_argument("--private-key", default="")
    parser.add_argument("--pubkey", default="")
    parser.add_argument("--dropbearmulti", default="")
    parser.add_argument("--xmpp-enable-wait", type=int, default=90)
    parser.add_argument("--ssh-wait", type=int, default=120)
    parser.add_argument("--no-enable-xmpp", action="store_true")
    parser.add_argument("--no-shell", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Validate locally without contacting a hub, prompting, or changing files")
    parser.add_argument("--usb-backend", choices=("auto", "hidapi", "hidraw", "winhid"), default="auto")
    parser.add_argument("--ssid", default="")
    parser.add_argument("--wifi-password", default="", help="Prefer the hidden interactive prompt; command-line secrets may be visible to other processes")
    parser.add_argument("--encryption", default="WPA2-PSK")
    parser.add_argument("--no-save", action="store_true")
    ssids = parser.add_mutually_exclusive_group()
    ssids.add_argument("--show-ssids", action="store_true")
    ssids.add_argument("--hide-ssids", action="store_true")
    parser.add_argument("--raw-output", action="store_true")
    parser.add_argument("--save-hub-id", action="store_true", help="save a USB-discovered Hub ID for LAN/XMPP actions")
    parser.add_argument("--wait-for-lan", action="store_true")
    parser.add_argument("--lan-port", type=int, default=8088)
    parser.add_argument("--lan-wait-seconds", type=int, default=90)
    parser.add_argument("--firmware-file", default="")
    parser.add_argument("--firmware-packets-per-chunk", type=int, default=500)
    parser.add_argument("--yes", action="store_true", help="Confirm USB reset/flash; does not supply missing settings")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.dry_run and not args.action:
        raise SystemExit("--dry-run requires an explicit --action.")
    action = args.action or read_action()
    if action == "lan-root":
        print("Running Harmony Hub LAN root installer...", flush=True)
        lan.main(lan_args(args, False))
    elif action == "enable-xmpp":
        print("Running Harmony Hub XMPP enable flow...", flush=True)
        lan.main(lan_args(args, True))
    elif action.startswith("usb-"):
        ensure_usb_prompt_args(args, action)
        usb_action = action.removeprefix("usb-")
        print(f"Running Harmony Hub USB action: {usb_action}", flush=True)
        # Keep prompted credentials in this process, not a child process command line.
        usb.main(usb_args(args, usb_action))
    else:
        raise SystemExit(f"Unknown action: {action}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        raise SystemExit(130)
    except (EOFError, OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
