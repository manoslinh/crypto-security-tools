#!/usr/bin/env python3
"""Check cryptocurrency balances from mnemonic phrases or private keys."""

import hashlib
import hmac
import json
import re
import sys
import argparse
import struct
import urllib.request
import urllib.error
from typing import NamedTuple

# Keccak-256 is required for Ethereum (NOT standard SHA-3)
# Install with: pip install pycryptodome
try:
    from Crypto.Hash import keccak as _keccak
    def keccak256(data: bytes) -> bytes:
        h = _keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
    HAS_KECCAK = True
except ImportError:
    HAS_KECCAK = False
    def keccak256(data: bytes) -> bytes:
        print("Warning: pycryptodome not installed. Using SHA-3 as fallback (ETH addresses may be incorrect).", file=sys.stderr)
        print("Install with: pip install pycryptodome", file=sys.stderr)
        return hashlib.sha3_256(data).digest()


class WalletInfo(NamedTuple):
    type: str
    address: str
    balance: float
    source: str


# ── BIP39 wordlist (2048 words) ──────────────────────────────────────────────
# Loaded from file if available, otherwise inline

BIP39_WORDS = None

BIP39_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"


def load_wordlist() -> list[str]:
    global BIP39_WORDS
    if BIP39_WORDS:
        return BIP39_WORDS
    try:
        req = urllib.request.Request(BIP39_WORDLIST_URL, headers={"User-Agent": "balance-checker"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            BIP39_WORDS = [w.strip() for w in resp.read().decode().splitlines() if w.strip()]
            return BIP39_WORDS
    except Exception:
        print("Error: Could not load BIP39 wordlist. Check internet connection.", file=sys.stderr)
        sys.exit(1)


def validate_mnemonic(phrase: str) -> bool:
    words = phrase.strip().split()
    if len(words) not in (12, 24):
        return False
    wordlist = load_wordlist()
    if not all(w.lower() in wordlist for w in words):
        return False
    # Validate BIP39 checksum
    word_indices = [wordlist.index(w.lower()) for w in words]
    bits = ""
    for idx in word_indices:
        bits += format(idx, "011b")
    # Last 4 bits of 12-word (132 bits) or 8 bits of 24-word (264 bits) are checksum
    entropy_bits = 128 if len(words) == 12 else 256
    checksum_bits = len(bits) - entropy_bits
    entropy = int(bits[:entropy_bits], 2)
    checksum = int(bits[entropy_bits:entropy_bits + checksum_bits], 2)
    expected = int.from_bytes(hashlib.sha256(entropy.to_bytes(entropy_bits // 8, "big")).digest(), "big")
    expected = expected >> (256 - checksum_bits)
    return checksum == expected


# ── BIP39 / BIP32 / BIP44 derivation ────────────────────────────────────────

def mnemonic_to_seed(phrase: str, passphrase: str = "") -> bytes:
    """BIP39 mnemonic to 512-bit seed."""
    phrase_bytes = phrase.strip().encode("utf-8")
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", phrase_bytes, salt, 2048)


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def base58_encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = ""
    while n > 0:
        n, remainder = divmod(n, 58)
        result = alphabet[remainder] + result
    for byte in data:
        if byte == 0:
            result = alphabet[0] + result
        else:
            break
    return result


def base58_decode(s: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for char in s:
        n = n * 58 + alphabet.index(char)
    result = n.to_bytes((n.bit_length() + 7) // 8, "big")
    for char in s:
        if char == alphabet[0]:
            result = b'\x00' + result
        else:
            break
    return result


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a segwit address."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    data = [witver] + convertbits(witprog, 8, 5)
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
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


def bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    values = [ord(x) for x in hrp] + [0] + data + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_polymod(values: list[int]) -> int:
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


# ── HD Key Derivation (BIP32) ───────────────────────────────────────────────

class HDKey:
    def __init__(self, key: bytes, chain_code: bytes, depth: int = 0, parent_fingerprint: bytes = b'\x00' * 4, index: int = 0):
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.index = index

    def fingerprint(self) -> bytes:
        return ripemd160(sha256(self.key))[:4]

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDKey":
        I = hmac_sha512(b"Bitcoin seed", seed)
        return cls(I[:32], I[32:])

    def derive_child(self, index: int) -> "HDKey":
        if index >= 0x80000000:
            data = b'\x00' + self.key + struct.pack(">I", index)
        else:
            pub = self.get_public_key()
            data = pub + struct.pack(">I", index)
        I = hmac_sha512(self.chain_code, data)
        child_key = (int.from_bytes(I[:32], "big") + int.from_bytes(self.key, "big")) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
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

    def get_public_key(self) -> bytes:
        """Get compressed public key from private key (simplified)."""
        # Use ecdsa-like multiplication for secp256k1
        # For simplicity, we'll use a workaround - compute via hashlib
        # In production, use a proper EC library
        x, y = self._private_to_public()
        if y % 2 == 0:
            return b'\x02' + x.to_bytes(32, "big")
        else:
            return b'\x03' + x.to_bytes(32, "big")

    def _private_to_public(self):
        """Simplified - returns (x, y) for secp256k1."""
        # secp256k1 parameters
        P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        A = 0
        B = 7
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

        def modinv(a, m):
            return pow(a, m - 2, m)

        def point_add(p1, p2):
            if p1 is None:
                return p2
            if p2 is None:
                return p1
            x1, y1 = p1
            x2, y2 = p2
            if x1 == x2 and y1 == y2:
                lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
            elif x1 == x2:
                return None
            else:
                lam = (y2 - y1) * modinv(x2 - x1, P) % P
            x3 = (lam * lam - x1 - x2) % P
            y3 = (lam * (x1 - x3) - y1) % P
            return (x3, y3)

        def point_mul(k, point):
            result = None
            addend = point
            while k > 0:
                if k & 1:
                    result = point_add(result, addend)
                addend = point_add(addend, addend)
                k >>= 1
            return result

        k = int.from_bytes(self.key, "big")
        point = point_mul(k, (Gx, Gy))
        return point


# ── Bitcoin address derivation ───────────────────────────────────────────────

def private_key_to_btc_address(key_bytes: bytes) -> list[str]:
    """Derive Bitcoin addresses (P2PKH, P2SH, Bech32) from private key."""
    addresses = []
    hd = HDKey(key_bytes, b'\x00' * 32)

    # P2PKH (legacy) - m/44'/0'/0'/0/0
    child = hd.derive_path("m/44'/0'/0'/0/0")
    pub = child.get_public_key()
    hash160 = ripemd160(sha256(pub))
    address = base58_encode(b'\x00' + hash160 + sha256(sha256(b'\x00' + hash160))[:4])
    addresses.append(("btc_p2pkh", address))

    # P2SH (segwit wrapped) - m/49'/0'/0'/0/0
    child = hd.derive_path("m/49'/0'/0'/0/0")
    pub = child.get_public_key()
    hash160 = ripemd160(sha256(pub))
    redeem_script = b'\x00\x14' + hash160
    script_hash = ripemd160(sha256(redeem_script))
    address = base58_encode(b'\x05' + script_hash + sha256(sha256(b'\x05' + script_hash))[:4])
    addresses.append(("btc_p2sh", address))

    # Bech32 (native segwit) - m/84'/0'/0'/0/0
    child = hd.derive_path("m/84'/0'/0'/0/0")
    pub = child.get_public_key()
    hash160 = ripemd160(sha256(pub))
    address = bech32_encode("bc", 0, hash160)
    addresses.append(("btc_bech32", address))

    return addresses


def wif_to_btc_address(wif: str) -> list[str]:
    """Convert WIF private key to Bitcoin addresses."""
    hex_key = parse_wif(wif)
    if not hex_key:
        return []
    key_bytes = bytes.fromhex(hex_key)
    return private_key_to_btc_address(key_bytes)


# ── Ethereum address derivation ──────────────────────────────────────────────

def private_key_to_eth_address(key_bytes: bytes) -> str:
    """Derive Ethereum address from 32-byte private key using BIP44 path."""
    hd = HDKey(key_bytes, b'\x00' * 32)
    # BIP44 path for Ethereum: m/44'/60'/0'/0/0
    child = hd.derive_path("m/44'/60'/0'/0/0")
    pub = child.get_public_key()
    # Remove 0x04 prefix if present (uncompressed)
    if len(pub) == 65:
        pub = pub[1:]
    # Keccak-256 hash of public key
    address_bytes = keccak256(pub)[-20:]
    # EIP-55 checksum
    address_hex = address_bytes.hex()
    keccak_hash = keccak256(address_hex.encode()).hex()
    checksummed = ""
    for i, char in enumerate(address_hex):
        if char in "0123456789":
            checksummed += char
        elif int(keccak_hash[i], 16) > 7:
            checksummed += char.upper()
        else:
            checksummed += char.lower()
    return "0x" + checksummed


def keccak256(data: bytes) -> bytes:
    """Keccak-256 hash (Ethereum uses this, not standard SHA-3)."""
    # Simplified - use hashlib with SHA3-256 as approximation
    # For production, use pysha3 or pycryptodome
    return hashlib.sha3_256(data).digest()


def hex_to_eth_address(hex_key: str) -> str:
    """Convert hex private key to Ethereum address."""
    hex_key = hex_key.lower().replace("0x", "")
    key_bytes = bytes.fromhex(hex_key)
    return private_key_to_eth_address(key_bytes)


# ── Balance checking via public APIs ─────────────────────────────────────────

def check_btc_balance(address: str) -> float:
    """Check Bitcoin balance via blockchain.com API."""
    try:
        url = f"https://blockchain.info/balance?active={address}"
        req = urllib.request.Request(url, headers={"User-Agent": "balance-checker"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if address in data:
                return data[address]["final_balance"] / 1e8  # satoshis to BTC
    except urllib.error.HTTPError as e:
        print(f"  Warning: BTC API error {e.code} for {address}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"  Warning: BTC API connection error: {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: BTC API unexpected error: {e}", file=sys.stderr)
    return 0.0


def check_eth_balance(address: str) -> float:
    """Check Ethereum balance via public RPC."""
    try:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        }).encode()
        req = urllib.request.Request(
            "https://eth.llamarpc.com",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "balance-checker"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            balance_wei = int(data["result"], 16)
            return balance_wei / 1e18  # wei to ETH
    except urllib.error.HTTPError as e:
        print(f"  Warning: ETH API error {e.code} for {address}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"  Warning: ETH API connection error: {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: ETH API unexpected error: {e}", file=sys.stderr)
    return 0.0


# ── Main ─────────────────────────────────────────────────────────────────────

def parse_wif(wif: str) -> str | None:
    """Validate and extract hex key from WIF with checksum verification."""
    try:
        decoded = base58_decode(wif)
        if len(decoded) not in (37, 38):
            return None
        # Version byte check (0x80 for mainnet)
        if decoded[0] != 0x80:
            return None
        # Validate checksum (last 4 bytes should match double-SHA256 of payload)
        payload = decoded[:-4]
        checksum = decoded[-4:]
        expected = sha256(sha256(payload))[:4]
        if checksum != expected:
            print(f"Warning: WIF checksum invalid for {wif[:8]}...", file=sys.stderr)
            return None
        key_bytes = payload[1:]  # Remove version byte
        if len(key_bytes) not in (32, 33):
            return None
        if len(key_bytes) == 33 and key_bytes[-1] != 0x01:
            return None
        if len(key_bytes) == 33:
            key_bytes = key_bytes[:-1]
        if len(key_bytes) != 32:
            return None
        return key_bytes.hex()
    except Exception:
        return None


def parse_hex_key(key: str) -> str | None:
    """Validate hex private key with length check."""
    key = key.lower().replace("0x", "")
    if len(key) != 64:
        return None
    try:
        key_bytes = bytes.fromhex(key)
        # Validate key is in valid range for secp256k1
        key_int = int.from_bytes(key_bytes, "big")
        if key_int == 0 or key_int >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            return None
        return key
    except ValueError:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Check cryptocurrency balances from mnemonic phrases or private keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Check a mnemonic phrase:
    %(prog)s --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

  Check a Bitcoin WIF private key:
    %(prog)s --wif "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6"

  Check an Ethereum hex private key:
    %(prog)s --hex "0x4c0883a69102937d6231471b5dbb6204fe512961708279f23efb3b6a801e8d7e"

  Check all supported chains:
    %(prog)s --mnemonic "your mnemonic here" --chains btc,eth

  Check specific chains only:
    %(prog)s --hex "your hex key" --chains eth
""",
    )

    # Input type (mutually exclusive)
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--mnemonic", help="BIP39 mnemonic phrase (12 or 24 words)")
    key_group.add_argument("--wif", help="Bitcoin WIF private key")
    key_group.add_argument("--hex", help="Hex private key (with or without 0x prefix)")

    parser.add_argument("--chains", default="btc,eth", help="Chains to check (comma-separated: btc,eth) (default: btc,eth)")
    parser.add_argument("--json-output", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    chains = [c.strip().lower() for c in args.chains.split(",")]

    results: list[WalletInfo] = []

    # Process mnemonic
    if args.mnemonic:
        if not validate_mnemonic(args.mnemonic):
            print("Error: Invalid mnemonic phrase", file=sys.stderr)
            sys.exit(1)

        seed = mnemonic_to_seed(args.mnemonic)
        master = HDKey.from_seed(seed)

        if "btc" in chains:
            print("Deriving Bitcoin addresses...", file=sys.stderr)
            for addr_type, address in private_key_to_btc_address(master.key):
                balance = check_btc_balance(address)
                results.append(WalletInfo(type=addr_type, address=address, balance=balance, source="mnemonic"))

        if "eth" in chains:
            print("Deriving Ethereum address...", file=sys.stderr)
            address = private_key_to_eth_address(master.key)
            balance = check_eth_balance(address)
            results.append(WalletInfo(type="eth", address=address, balance=balance, source="mnemonic"))

    # Process WIF
    elif args.wif:
        hex_key = parse_wif(args.wif)
        if not hex_key:
            print("Error: Invalid WIF key", file=sys.stderr)
            sys.exit(1)

        key_bytes = bytes.fromhex(hex_key)

        if "btc" in chains:
            print("Deriving Bitcoin addresses...", file=sys.stderr)
            for addr_type, address in private_key_to_btc_address(key_bytes):
                balance = check_btc_balance(address)
                results.append(WalletInfo(type=addr_type, address=address, balance=balance, source="wif"))

        if "eth" in chains:
            print("Deriving Ethereum address...", file=sys.stderr)
            address = private_key_to_eth_address(key_bytes)
            balance = check_eth_balance(address)
            results.append(WalletInfo(type="eth", address=address, balance=balance, source="wif"))

    # Process hex key
    elif args.hex:
        hex_key = parse_hex_key(args.hex)
        if not hex_key:
            print("Error: Invalid hex private key", file=sys.stderr)
            sys.exit(1)

        key_bytes = bytes.fromhex(hex_key)

        if "btc" in chains:
            print("Deriving Bitcoin addresses...", file=sys.stderr)
            for addr_type, address in private_key_to_btc_address(key_bytes):
                balance = check_btc_balance(address)
                results.append(WalletInfo(type=addr_type, address=address, balance=balance, source="hex"))

        if "eth" in chains:
            print("Deriving Ethereum address...", file=sys.stderr)
            address = private_key_to_eth_address(key_bytes)
            balance = check_eth_balance(address)
            results.append(WalletInfo(type="eth", address=address, balance=balance, source="hex"))

    # Output
    if args.json_output:
        print(json.dumps([r._asdict() for r in results], indent=2))
    else:
        has_balance = any(r.balance > 0 for r in results)
        print()
        for r in results:
            status = f"{r.balance:.8f}" if r.balance > 0 else "0"
            print(f"  [{r.type.upper():10s}] {r.address}  Balance: {status}")
        print()
        if has_balance:
            print("  ** BALANCE FOUND **", file=sys.stderr)
        else:
            print("  No balances found.", file=sys.stderr)


if __name__ == "__main__":
    main()
