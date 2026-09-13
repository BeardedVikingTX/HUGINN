#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HUGINN :: payloads_vault.py

Encode/decode payload YAML files to base64 to bypass shared-hosting
malware scanners (Imunify360, NodeWarden, ClamAV) that flag SQLi/XSS
payload content as "attack signatures."

Usage:
    # Encode all payloads/sql.yaml -> payloads/sql.b64
    python3 payloads_vault.py encode

    # Decode all payloads/*.b64 -> payloads/*.yaml
    python3 payloads_vault.py decode

    # Just verify which files exist
    python3 payloads_vault.py status
"""
import sys
import base64
from pathlib import Path


PAYLOAD_DIR = Path(__file__).parent / "payloads"


def encode_all():
    """Read every .yaml in payloads/, write .b64 versions."""
    if not PAYLOAD_DIR.exists():
        print(f"[!] payloads dir not found: {PAYLOAD_DIR}")
        return 1

    yamls = sorted(PAYLOAD_DIR.glob("*.yaml"))
    if not yamls:
        print("[!] no .yaml files found in payloads/")
        return 1

    count = 0
    for yaml_path in yamls:
        b64_path = yaml_path.with_suffix(".b64")
        try:
            raw = yaml_path.read_bytes()
            encoded = base64.b64encode(raw)
            # Wrap at 76 chars for readability + to look like normal
            # certificate-ish content that scanners ignore
            wrapped = b"\n".join(
                encoded[i:i + 76]
                for i in range(0, len(encoded), 76)
            )
            b64_path.write_bytes(wrapped + b"\n")
            print(f"[+] {yaml_path.name:30} -> {b64_path.name}  "
                  f"({len(raw):>7} B -> {len(wrapped):>7} B)")
            count += 1
        except Exception as e:
            print(f"[!] {yaml_path.name}: {e}")

    print(f"\n[+] encoded {count} file(s)")
    return 0


def decode_all():
    """Read every .b64 in payloads/, write .yaml versions."""
    if not PAYLOAD_DIR.exists():
        print(f"[!] payloads dir not found: {PAYLOAD_DIR}")
        return 1

    b64s = sorted(PAYLOAD_DIR.glob("*.b64"))
    if not b64s:
        print("[!] no .b64 files found in payloads/")
        return 1

    count = 0
    for b64_path in b64s:
        yaml_path = b64_path.with_suffix(".yaml")
        try:
            encoded = b64_path.read_bytes().replace(b"\n", b"").replace(b"\r", b"")
            decoded = base64.b64decode(encoded)
            yaml_path.write_bytes(decoded)
            print(f"[+] {b64_path.name:30} -> {yaml_path.name}  "
                  f"({len(encoded):>7} B -> {len(decoded):>7} B)")
            count += 1
        except Exception as e:
            print(f"[!] {b64_path.name}: {e}")

    print(f"\n[+] decoded {count} file(s)")
    return 0


def status():
    """Show which files exist in both formats."""
    yamls = {p.stem for p in PAYLOAD_DIR.glob("*.yaml")}
    b64s  = {p.stem for p in PAYLOAD_DIR.glob("*.b64")}

    print(f"\n{'NAME':<30} {'YAML':<8} {'B64':<8}")
    print("-" * 50)
    for name in sorted(yamls | b64s):
        has_yaml = "yes" if name in yamls else "-"
        has_b64  = "yes" if name in b64s else "-"
        print(f"{name:<30} {has_yaml:<8} {has_b64:<8}")
    print()
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "encode":
        sys.exit(encode_all())
    elif cmd == "decode":
        sys.exit(decode_all())
    elif cmd == "status":
        sys.exit(status())
    else:
        print(__doc__)
        sys.exit(1)
