#!/usr/bin/env python3
"""Convert Ethereum private key to public key and address."""

import hashlib
import sys
import argparse


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

try:
    from Crypto.Hash import keccak
    def keccak256(data: bytes) -> bytes:
        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
except ImportError:
    print("Error: pycryptodome required for Keccak-256. Install with: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


def modinv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1) * modinv(2 * y1, SECP256K1_P) % SECP256K1_P
    elif x1 == x2:
        return None
    else:
        lam = (y2 - y1) * modinv(x2 - x1, SECP256K1_P) % SECP256K1_P
    x3 = (lam * lam - x1 - x2) % SECP256K1_P
    y3 = (lam * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)


def point_mul(k: int, point):
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def private_to_public(key_bytes: bytes) -> tuple[bytes, tuple[int, int]]:
    """Derive compressed public key and (x, y) point from private key."""
    G = (SECP256K1_Gx, SECP256K1_Gy)
    k = int.from_bytes(key_bytes, "big")
    x, y = point_mul(k, G)
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    pub_compressed = prefix + x.to_bytes(32, "big")
    return pub_compressed, (x, y)


def public_key_to_address(pub: bytes) -> str:
    """Derive EIP-55 checksummed Ethereum address from compressed public key."""
    if len(pub) == 33:
        # Decompress for keccak (uncompressed is 65 bytes: 04 + x + y)
        prefix = pub[0]
        x = int.from_bytes(pub[1:], "big")
        # Recover y from x using secp256k1 curve equation: y^2 = x^3 + 7
        y_sq = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
        y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
        if y % 2 != (prefix - 0x02):
            y = SECP256K1_P - y
        pub_uncompressed = b'\x04' + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    else:
        pub_uncompressed = pub
    # Keccak-256 of public key (without 04 prefix)
    addr_bytes = keccak256(pub_uncompressed[1:])[-20:]
    # EIP-55 checksum
    addr_hex = addr_bytes.hex()
    keccak_hash = keccak256(addr_hex.encode()).hex()
    checksummed = ""
    for i, char in enumerate(addr_hex):
        if char in "0123456789":
            checksummed += char
        elif int(keccak_hash[i], 16) > 7:
            checksummed += char.upper()
        else:
            checksummed += char.lower()
    return "0x" + checksummed


def main():
    parser = argparse.ArgumentParser(description="Convert ETH private key to public key and address")
    parser.add_argument("private_key", help="Hex private key (with or without 0x prefix)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    hex_key = args.private_key.lower().replace("0x", "")
    if len(hex_key) != 64:
        print("Error: Private key must be 64 hex characters", file=sys.stderr)
        sys.exit(1)

    try:
        key_int = int(hex_key, 16)
    except ValueError:
        print("Error: Invalid hex characters", file=sys.stderr)
        sys.exit(1)

    if key_int == 0 or key_int >= SECP256K1_N:
        print("Error: Private key out of valid range", file=sys.stderr)
        sys.exit(1)

    key_bytes = bytes.fromhex(hex_key)
    pub_compressed, (pub_x, pub_y) = private_to_public(key_bytes)
    address = public_key_to_address(pub_compressed)

    if args.json:
        import json
        print(json.dumps({
            "private_key": "0x" + hex_key,
            "public_key_compressed": pub_compressed.hex(),
            "public_key_x": hex(pub_x),
            "public_key_y": hex(pub_y),
            "address": address,
        }, indent=2))
    else:
        print(f"  Private key:     0x{hex_key}")
        print(f"  Public key (x):  {hex(pub_x)}")
        print(f"  Public key (y):  {hex(pub_y)}")
        print(f"  Address:         {address}")


if __name__ == "__main__":
    main()
