#!/usr/bin/env python3
"""Pull the real IR codes out of a rooted Harmony Hub and print them as
ESPHome remote_transmitter.transmit_raw calls (or a plain table).

Input: /data/resources/DeviceList.json and ProtocolList.json from the hub.
The config export you get from the Harmony API only has command *references*;
the actual codes live in these two files.

Usage:
  harmony-ir-extract.py DeviceList.json ProtocolList.json            # table
  harmony-ir-extract.py DeviceList.json ProtocolList.json --esphome  # YAML

Bit order: the KeyCode hex is sent MSB first. Checked against a Samsung TV
whose codes are public (0xE0E019E6 = power off). Bluetooth/HID device
profiles have no IR segments and are skipped.
"""
import json, re, sys

KEYCODE = re.compile(r'^G:(?P<proto>.+?):\(\)\((?P<hex>[0-9A-Fa-fx_]+)\)\(\):\d+$')

def pulses(seg, value_hex):
    """One IR segment (header + bits + trailer) as [+mark, -space, ...] microseconds."""
    out = []
    def atoms(a):
        for x in a:
            out.append(x['Value'] if x['Type'] == 1 else -x['Value'])
    atoms(seg.get('Header') or [])
    p = seg['Payload']
    enc = {e['BitType']: e['Atoms'] for e in p['Encodings']}
    v = int(value_hex, 16)
    for i in range(p['NumberOfBits'] - 1, -1, -1):
        atoms(enc[(v >> i) & 1])
    atoms(seg.get('Trailer') or [])
    return out

def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    devs = json.load(open(sys.argv[1]))['DevicesWithFeatures']
    protos = {p['Id-']: p for p in json.load(open(sys.argv[2]))['Protocols']}
    esphome = '--esphome' in sys.argv
    n = 0
    for d in devs:
        dev = d['Device']
        label = dev.get('Label') or dev.get('Name') or str(dev.get('Id-'))
        head = f"{label} ({dev.get('Manufacturer')} {dev.get('Model')})"
        print(f"# ---- {head}" if esphome else f"\n== {head}")
        for c in d['Commands']:
            m = KEYCODE.match(c.get('KeyCode') or '')
            proto = protos.get(c.get('ProtocolId'))
            if not m or not proto or not proto.get('IRSegments'):
                continue
            segs, values = proto['IRSegments'], m['hex'].split('_')
            if len(segs) == 1 and len(values) > 1:   # "Dual" codes: two frames, one segment definition
                segs = segs * len(values)
            raw = []
            for seg, h in zip(segs, values):
                raw += pulses(seg, h)
            n += 1
            if esphome:
                print(f"  - remote_transmitter.transmit_raw:  # {c['Name']}")
                print(f"      carrier_frequency: {proto['CarrierFrequency']}Hz")
                print(f"      code: {raw}")
            else:
                print(f"  {c['Name']:<24} {m['proto']:<28} {m['hex']:<24} {proto['CarrierFrequency']} Hz  {len(raw)} pulses")
    print(f"# {n} IR commands", file=sys.stderr)

if __name__ == '__main__':
    main()
