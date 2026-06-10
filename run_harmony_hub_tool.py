#!/usr/bin/env python3
"""Unified Harmony Hub tool for Windows, Linux, and macOS."""

from __future__ import annotations

import argparse
import getpass
import pathlib
import subprocess
import sys


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
LAN_TOOL_PATH = SCRIPT_DIR / "harmony_xmpp_root_shell.py"
USB_BRIDGE_PATH = SCRIPT_DIR / "harmony_usb_bridge.py"
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
    if not args.hub_host and args.hub_ip:
        args.hub_host = args.hub_ip
    if not args.hub_ip and args.hub_host:
        args.hub_ip = args.hub_host


def run_subprocess(argv: list[str]) -> None:
    proc = subprocess.run(argv, cwd=SCRIPT_DIR, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def lan_args(args: argparse.Namespace, enable_xmpp_only: bool) -> list[str]:
    resolve_host_alias(args)
    if not args.hub_host and not args.dry_run:
        args.hub_host = input("Harmony Hub IP address: ").strip()
    dropbearmulti = args.dropbearmulti or str(SCRIPT_DIR / "dropbearmulti")
    private_key = args.private_key or str(pathlib.Path.home() / ".ssh" / "harmony_owner_ed25519")
    pubkey = args.pubkey or private_key + ".pub"
    argv = [
        sys.executable,
        str(LAN_TOOL_PATH),
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
        sys.executable,
        str(USB_BRIDGE_PATH),
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
    if action == "usb-wifi-scan" and not args.show_ssids and not args.dry_run and not args.yes:
        answer = input("Show SSIDs in scan output? [y/N]: ").strip().lower()
        if answer in {"y", "yes"}:
            args.show_ssids = True
    elif action == "usb-provision-wifi":
        resolve_host_alias(args)
        if not args.ssid and not args.dry_run:
            args.ssid = input("Wi-Fi SSID: ").strip()
        if not args.encryption:
            args.encryption = "WPA2-PSK"
        if args.encryption.upper() not in {"NONE", "OPEN"} and args.wifi_password == "" and not args.dry_run:
            args.wifi_password = getpass.getpass("Wi-Fi password: ")
        if args.dry_run:
            return
        if not args.wait_for_lan and not args.yes:
            answer = input("Wait for LAN reachability after provisioning? [y/N]: ").strip().lower()
            if answer in {"y", "yes"}:
                args.wait_for_lan = True
        if args.wait_for_lan and not args.hub_ip:
            args.hub_ip = input("Expected hub IP for LAN check: ").strip()
    elif action == "usb-flash-firmware":
        if not args.firmware_file:
            args.firmware_file = input("Path to .hfw2 firmware file: ").strip().strip('"')
    elif action == "usb-factory-reset":
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified Harmony Hub tool")
    parser.add_argument("--action", choices=ACTION_CHOICES, default="")
    parser.add_argument("--hub-host", default="")
    parser.add_argument("--hub-ip", default="")
    parser.add_argument("--hub-id", action="append", default=[])
    parser.add_argument("--ignore-saved-hub-id", action="store_true", help="do not use cached Hub IDs for LAN/XMPP actions")
    parser.add_argument("--use-global-saved-hub-id", action="store_true", help="allow legacy global hub_id.txt cache entries")
    parser.add_argument("--clear-saved-hub-id", action="store_true", help="clear cached Hub ID handoff files before LAN/XMPP actions")
    parser.add_argument("--private-key", default="")
    parser.add_argument("--pubkey", default="")
    parser.add_argument("--dropbearmulti", default="")
    parser.add_argument("--xmpp-enable-wait", type=int, default=90)
    parser.add_argument("--no-enable-xmpp", action="store_true")
    parser.add_argument("--no-shell", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--usb-backend", choices=("auto", "hidapi", "hidraw", "winhid"), default="auto")
    parser.add_argument("--ssid", default="")
    parser.add_argument("--wifi-password", default="")
    parser.add_argument("--encryption", default="WPA2-PSK")
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--show-ssids", action="store_true")
    parser.add_argument("--hide-ssids", action="store_true")
    parser.add_argument("--raw-output", action="store_true")
    parser.add_argument("--save-hub-id", action="store_true", help="save a USB-discovered Hub ID for LAN/XMPP actions")
    parser.add_argument("--wait-for-lan", action="store_true")
    parser.add_argument("--lan-port", type=int, default=8088)
    parser.add_argument("--lan-wait-seconds", type=int, default=90)
    parser.add_argument("--firmware-file", default="")
    parser.add_argument("--target-skin", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--firmware-packets-per-chunk", type=int, default=500)
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    action = args.action or read_action()
    if action == "lan-root":
        print("Running Harmony Hub Give me root! LAN flow...", flush=True)
        run_subprocess(lan_args(args, False))
    elif action == "enable-xmpp":
        print("Running Harmony Hub XMPP enable flow...", flush=True)
        run_subprocess(lan_args(args, True))
    elif action == "usb-preflight":
        print("Running Harmony Hub USB bridge action: preflight", flush=True)
        run_subprocess(usb_args(args, "preflight"))
    elif action == "usb-sysinfo":
        print("Running Harmony Hub USB bridge action: sysinfo", flush=True)
        run_subprocess(usb_args(args, "sysinfo"))
    elif action == "usb-hub-id":
        print("Running Harmony Hub USB bridge action: hub-id", flush=True)
        args.save_hub_id = True
        run_subprocess(usb_args(args, "hub-id"))
    elif action == "usb-wifi-status":
        print("Running Harmony Hub USB bridge action: wifi-status", flush=True)
        run_subprocess(usb_args(args, "wifi-status"))
    elif action == "usb-wifi-scan":
        ensure_usb_prompt_args(args, action)
        print("Running Harmony Hub USB bridge action: wifi-scan", flush=True)
        run_subprocess(usb_args(args, "wifi-scan"))
    elif action == "usb-provision-wifi":
        ensure_usb_prompt_args(args, action)
        print("Running Harmony Hub USB bridge action: change-wifi", flush=True)
        run_subprocess(usb_args(args, "provision-wifi"))
    elif action == "usb-factory-reset":
        ensure_usb_prompt_args(args, action)
        print("Running Harmony Hub USB bridge action: factory-reset", flush=True)
        print("After factory reset, set the hub up again with the Harmony app before normal use.", flush=True)
        run_subprocess(usb_args(args, "factory-reset"))
    elif action == "usb-flash-firmware":
        ensure_usb_prompt_args(args, action)
        print("Running Harmony Hub USB bridge action: flash-firmware", flush=True)
        run_subprocess(usb_args(args, "flash-firmware"))
    else:
        raise SystemExit(f"Unknown action: {action}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("\nInterrupted")
