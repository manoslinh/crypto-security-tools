#!/usr/bin/env python3
"""Convert Bitcoin private key to public key and addresses."""

import hashlib
import struct
import sys
import argparse


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CHARSET_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


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


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    result = ""
    while n > 0:
        n, remainder = divmod(n, 58)
        result = ALPHABET[remainder] + result
    for byte in data:
        if byte == 0:
            result = ALPHABET[0] + result
        else:
            break
    return result


def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand HRP for bech32 encoding per BIP173."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(values) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp, witver, witprog):
    data = [witver] + convertbits(witprog, 8, 5)
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET_BECH32[d] for d in combined)


def private_to_btc_addresses(key_bytes: bytes) -> dict:
    """Derive Bitcoin addresses from private key."""
    pub, _ = private_to_public(key_bytes)
    h160 = hash160(pub)

    # P2PKH (legacy): version 0x00
    p2pkh = base58_encode(b'\x00' + h160 + sha256(sha256(b'\x00' + h160))[:4])

    # P2SH-P2WPKH (segwit wrapped): version 0x05
    redeem_script = b'\x00\x14' + h160
    p2sh_hash = hash160(redeem_script)
    p2sh = base58_encode(b'\x05' + p2sh_hash + sha256(sha256(b'\x05' + p2sh_hash))[:4])

    # P2WPKH (native segwit / bech32)
    bech32 = bech32_encode("bc", 0, h160)

    return {
        "p2pkh": p2pkh,
        "p2sh": p2sh,
        "bech32": bech32,
    }


def wif_encode(key_bytes: bytes, compressed: bool = True) -> str:
    """Encode private key as WIF."""
    payload = b'\x80' + key_bytes
    if compressed:
        payload += b'\x01'
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)


def main():
    parser = argparse.ArgumentParser(description="Convert BTC private key to public key and addresses")
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
    pub, (pub_x, pub_y) = private_to_public(key_bytes)
    addresses = private_to_btc_addresses(key_bytes)
    wif = wif_encode(key_bytes, compressed=True)

    if args.json:
        import json
        print(json.dumps({
            "private_key": "0x" + hex_key,
            "wif": wif,
            "public_key_compressed": pub.hex(),
            "public_key_x": hex(pub_x),
            "public_key_y": hex(pub_y),
            "address_p2pkh": addresses["p2pkh"],
            "address_p2sh": addresses["p2sh"],
            "address_bech32": addresses["bech32"],
        }, indent=2))
    else:
        print(f"  Private key:     0x{hex_key}")
        print(f"  WIF:             {wif}")
        print(f"  Public key (x):  {hex(pub_x)}")
        print(f"  Public key (y):  {hex(pub_y)}")
        print(f"  P2PKH (legacy):  {addresses['p2pkh']}")
        print(f"  P2SH (segwit):   {addresses['p2sh']}")
        print(f"  Bech32 (native): {addresses['bech32']}")


if __name__ == "__main__":
    main()
