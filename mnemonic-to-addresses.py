#!/usr/bin/env python3
"""Convert BIP39 mnemonic phrase to Bitcoin and Ethereum addresses."""

import hashlib
import hmac
import json
import struct
import sys
import argparse
import urllib.request


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CHARSET_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BIP39_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"

try:
    from Crypto.Hash import keccak
    def keccak256(data: bytes) -> bytes:
        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
except ImportError:
    print("Error: pycryptodome required for Keccak-256. Install with: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


# ── Helpers ──────────────────────────────────────────────────────────────────

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


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


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


# ── BIP39 ────────────────────────────────────────────────────────────────────

def load_wordlist() -> list[str]:
    try:
        req = urllib.request.Request(BIP39_WORDLIST_URL, headers={"User-Agent": "mnemonic-tool"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return [w.strip() for w in resp.read().decode().splitlines() if w.strip()]
    except Exception:
        print("Error: Could not load BIP39 wordlist", file=sys.stderr)
        sys.exit(1)


def validate_mnemonic(phrase: str, wordlist: list[str]) -> bool:
    words = phrase.strip().split()
    if len(words) not in (12, 24):
        return False
    if not all(w.lower() in wordlist for w in words):
        return False
    # Validate checksum
    word_indices = [wordlist.index(w.lower()) for w in words]
    bits = ""
    for idx in word_indices:
        bits += format(idx, "011b")
    entropy_bits = 128 if len(words) == 12 else 256
    checksum_bits = len(bits) - entropy_bits
    entropy = int(bits[:entropy_bits], 2)
    checksum = int(bits[entropy_bits:entropy_bits + checksum_bits], 2)
    expected = int.from_bytes(sha256(entropy.to_bytes(entropy_bits // 8, "big")), "big")
    expected = expected >> (256 - checksum_bits)
    return checksum == expected


def mnemonic_to_seed(phrase: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac("sha512", phrase.strip().encode("utf-8"), ("mnemonic" + passphrase).encode("utf-8"), 2048)


# ── HD Key ───────────────────────────────────────────────────────────────────

class HDKey:
    def __init__(self, key: bytes, chain_code: bytes, depth: int = 0, parent_fingerprint: bytes = b'\x00' * 4, index: int = 0):
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.index = index

    def fingerprint(self) -> bytes:
        return ripemd160(sha256(self.get_compressed_pub()))[:4]

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDKey":
        I = hmac_sha512(b"Bitcoin seed", seed)
        return cls(I[:32], I[32:])

    def derive_child(self, index: int) -> "HDKey":
        if index >= 0x80000000:
            data = b'\x00' + self.key + struct.pack(">I", index)
        else:
            data = self.get_compressed_pub() + struct.pack(">I", index)
        I = hmac_sha512(self.chain_code, data)
        child_key = (int.from_bytes(I[:32], "big") + int.from_bytes(self.key, "big")) % SECP256K1_N
        child_key = child_key.to_bytes(32, "big")
        return HDKey(child_key, I[32:], self.depth + 1, self.fingerprint(), index)

    def derive_path(self, path: str) -> "HDKey":
        key = self
        for part in path.split("/"):
            if part == "m":
                continue
            hardened = part.endswith("'")
            if hardened:
                part = part[:-1]
            index = int(part) + 0x80000000 if hardened else int(part)
            key = key.derive_child(index)
        return key

    def get_compressed_pub(self) -> bytes:
        G = (SECP256K1_Gx, SECP256K1_Gy)
        k = int.from_bytes(self.key, "big")
        x, y = point_mul(k, G)
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, "big")


# ── Address derivation ───────────────────────────────────────────────────────

def get_btc_addresses(hd: HDKey) -> dict:
    # P2PKH (legacy) - m/44'/0'/0'/0/0
    child = hd.derive_path("m/44'/0'/0'/0/0")
    pub = child.get_compressed_pub()
    h160 = hash160(pub)
    p2pkh = base58_encode(b'\x00' + h160 + sha256(sha256(b'\x00' + h160))[:4])

    # P2SH (segwit wrapped) - m/49'/0'/0'/0/0
    child = hd.derive_path("m/49'/0'/0'/0/0")
    pub = child.get_compressed_pub()
    h160 = hash160(pub)
    redeem = b'\x00\x14' + h160
    p2sh_hash = hash160(redeem)
    p2sh = base58_encode(b'\x05' + p2sh_hash + sha256(sha256(b'\x05' + p2sh_hash))[:4])

    # Bech32 (native segwit) - m/84'/0'/0'/0/0
    child = hd.derive_path("m/84'/0'/0'/0/0")
    pub = child.get_compressed_pub()
    h160 = hash160(pub)
    bech32 = bech32_encode("bc", 0, h160)

    return {"p2pkh": p2pkh, "p2sh": p2sh, "bech32": bech32}


def get_eth_address(hd: HDKey) -> str:
    child = hd.derive_path("m/44'/60'/0'/0/0")
    pub = child.get_compressed_pub()
    # Decompress
    prefix = pub[0]
    x = int.from_bytes(pub[1:], "big")
    y_sq = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if y % 2 != (prefix - 0x02):
        y = SECP256K1_P - y
    pub_uncompressed = b'\x04' + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    addr_bytes = keccak256(pub_uncompressed[1:])[-20:]
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


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Convert BIP39 mnemonic to BTC and ETH addresses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  %(prog)s "your 24 word mnemonic phrase here ..." --json
""",
    )
    parser.add_argument("mnemonic", help="BIP39 mnemonic phrase (12 or 24 words)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    wordlist = load_wordlist()
    if not validate_mnemonic(args.mnemonic, wordlist):
        print("Error: Invalid mnemonic phrase", file=sys.stderr)
        sys.exit(1)

    seed = mnemonic_to_seed(args.mnemonic)
    master = HDKey.from_seed(seed)
    btc = get_btc_addresses(master)
    eth = get_eth_address(master)

    if args.json:
        print(json.dumps({
            "mnemonic": args.mnemonic,
            "btc_p2pkh": btc["p2pkh"],
            "btc_p2sh": btc["p2sh"],
            "btc_bech32": btc["bech32"],
            "eth_address": eth,
        }, indent=2))
    else:
        print(f"  Mnemonic:       {args.mnemonic}")
        print(f"  BTC P2PKH:      {btc['p2pkh']}")
        print(f"  BTC P2SH:       {btc['p2sh']}")
        print(f"  BTC Bech32:     {btc['bech32']}")
        print(f"  ETH Address:    {eth}")


if __name__ == "__main__":
    main()
