#!/usr/bin/env python3
"""Parse repo-scanner output, derive wallet addresses, and check balances."""

import hashlib
import hmac
import json
import struct
import sys
import time
import argparse
import urllib.request
import urllib.error
from typing import NamedTuple


class WalletResult(NamedTuple):
    source_type: str
    source_value: str
    chain: str
    address: str
    balance: float
    repo: str
    file: str
    line: int


# ── Crypto constants ─────────────────────────────────────────────────────────

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
    print("Error: pycryptodome required. Install with: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


# ── Math / crypto primitives ─────────────────────────────────────────────────

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


# ── HD Key derivation ────────────────────────────────────────────────────────

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


# ── BIP39 ────────────────────────────────────────────────────────────────────

def load_wordlist() -> list[str]:
    try:
        req = urllib.request.Request(BIP39_WORDLIST_URL, headers={"User-Agent": "wallet-checker"})
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


# ── Address derivation ───────────────────────────────────────────────────────

def get_btc_addresses_from_key(key_bytes: bytes) -> list[str]:
    """Derive BTC addresses directly from a raw private key (no HD)."""
    G = (SECP256K1_Gx, SECP256K1_Gy)
    k = int.from_bytes(key_bytes, "big")
    x, y = point_mul(k, G)
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    pub = prefix + x.to_bytes(32, "big")
    h160 = hash160(pub)
    p2pkh = base58_encode(b'\x00' + h160 + sha256(sha256(b'\x00' + h160))[:4])
    redeem = b'\x00\x14' + h160
    p2sh_hash = hash160(redeem)
    p2sh = base58_encode(b'\x05' + p2sh_hash + sha256(sha256(b'\x05' + p2sh_hash))[:4])
    bech32 = bech32_encode("bc", 0, h160)
    return [p2pkh, p2sh, bech32]


def get_eth_address_from_key(key_bytes: bytes) -> str:
    """Derive ETH address directly from a raw private key (no HD)."""
    G = (SECP256K1_Gx, SECP256K1_Gy)
    k = int.from_bytes(key_bytes, "big")
    x, y = point_mul(k, G)
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


def get_btc_addresses_from_mnemonic(master: HDKey) -> list[str]:
    """Derive BTC addresses from HD master key via BIP44."""
    addresses = []
    for path in ["m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0"]:
        child = master.derive_path(path)
        pub = child.get_compressed_pub()
        h160 = hash160(pub)
        if path.startswith("m/44'"):
            addresses.append(base58_encode(b'\x00' + h160 + sha256(sha256(b'\x00' + h160))[:4]))
        elif path.startswith("m/49'"):
            redeem = b'\x00\x14' + h160
            p2sh_hash = hash160(redeem)
            addresses.append(base58_encode(b'\x05' + p2sh_hash + sha256(sha256(b'\x05' + p2sh_hash))[:4]))
        else:
            addresses.append(bech32_encode("bc", 0, h160))
    return addresses


def get_eth_address_from_mnemonic(master: HDKey) -> str:
    """Derive ETH address from HD master key via BIP44."""
    child = master.derive_path("m/44'/60'/0'/0/0")
    pub = child.get_compressed_pub()
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


# ── Balance checking ─────────────────────────────────────────────────────────

def check_btc_balance(address: str) -> float:
    try:
        time.sleep(0.05)  # Rate limiting
        url = f"https://blockstream.info/api/address/{address}"
        req = urllib.request.Request(url, headers={"User-Agent": "wallet-checker"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            chain = data.get("chain_stats", {})
            return (chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0)) / 1e8
    except Exception as e:
        print(f"  Warning: BTC API error for {address}: {e}", file=sys.stderr)
    return 0.0


def check_eth_balance(address: str) -> float:
    try:
        time.sleep(0.05)  # Rate limiting
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        }).encode()
        req = urllib.request.Request(
            "https://ethereum-rpc.publicnode.com",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "wallet-checker"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if "result" not in data:
                return 0.0
            balance_wei = int(data["result"], 16)
            return balance_wei / 1e18
    except Exception as e:
        print(f"  Warning: ETH API error for {address}: {e}", file=sys.stderr)
    return 0.0


ETH_RPC_ENDPOINTS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth-mainnet.public.blastapi.io",
    "https://eth.drpc.org",
]


def check_eth_balance(address: str) -> float:
    for endpoint in ETH_RPC_ENDPOINTS:
        try:
            time.sleep(0.1)  # Rate limiting
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 1
            }).encode()
            req = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "wallet-checker"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                if "result" not in data:
                    continue
                balance_wei = int(data["result"], 16)
                return balance_wei / 1e18
        except Exception:
            continue
    print(f"  Warning: ETH API error for {address}: all endpoints failed", file=sys.stderr)
    return 0.0


# ── Parse findings ───────────────────────────────────────────────────────────

def extract_hex_key(match_text: str) -> str | None:
    """Extract hex private key from match text."""
    # Handle "privateKey: '0x...'" or similar
    import re
    m = re.search(r"(?:0x)?[0-9a-fA-F]{64}", match_text)
    if m:
        hex_key = m.group()
        if not hex_key.startswith("0x"):
            hex_key = "0x" + hex_key
        return hex_key
    return None


def extract_mnemonic(match_text: str) -> str | None:
    """Extract mnemonic phrase from match text."""
    import re
    words = match_text.lower().split()
    # BIP39 words are 3-8 chars, match sequences of 12 or 24
    bip39_pattern = re.compile(r"\b[a-z]{3,8}\b")
    found_words = bip39_pattern.findall(match_text.lower())
    if len(found_words) == 12:
        return " ".join(found_words[:12])
    elif len(found_words) == 24:
        return " ".join(found_words[:24])
    return None


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Parse repo-scanner JSON output and check wallet balances",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Pipe repo-scanner output directly
  python repo-scanner.py --org my-org --json-output | python wallet-checker.py

  # Use a saved JSON file
  python wallet-checker.py --input results.json

  # Save output to file
  python wallet-checker.py --input results.json --output wallets.json
""",
    )
    parser.add_argument("--input", "-i", help="Input JSON file (default: stdin)")
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument("--redact", action="store_true", help="Redact source keys from output")

    args = parser.parse_args()

    # Load input
    try:
        if args.input:
            with open(args.input) as f:
                findings = json.load(f)
        else:
            findings = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Load BIP39 wordlist
    wordlist = load_wordlist()

    # Process findings
    results = []
    seen = set()  # Deduplicate by (source_type, source_value)

    for finding in findings:
        pattern = finding.get("pattern_name", "")
        match = finding.get("match", "")
        repo = finding.get("repo", "")
        file = finding.get("file", "")
        line = finding.get("line", 0)

        source_type = None
        source_value = None

        if pattern == "MNEMONIC":
            mnemonic = extract_mnemonic(match)
            if mnemonic and validate_mnemonic(mnemonic, wordlist):
                source_type = "mnemonic"
                source_value = mnemonic
        elif pattern in ("ETH_PRIVATE_KEY", "BTC_PRIVATE_KEY", "PRIVATE_KEY"):
            hex_key = extract_hex_key(match)
            if hex_key:
                source_type = "private_key"
                source_value = hex_key
        else:
            # Skip patterns that are unlikely to contain wallet keys
            continue

        if not source_type:
            continue

        dedup_key = (source_type, source_value)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        print(f"Processing {source_type} from {repo}/{file}:{line}", file=sys.stderr)

        if source_type == "mnemonic":
            seed = mnemonic_to_seed(source_value)
            master = HDKey.from_seed(seed)

            # BTC addresses
            btc_addrs = get_btc_addresses_from_mnemonic(master)
            for addr in btc_addrs:
                balance = check_btc_balance(addr)
                results.append(WalletResult(
                    source_type="mnemonic",
                    source_value=source_value,
                    chain="btc",
                    address=addr,
                    balance=balance,
                    repo=repo,
                    file=file,
                    line=line,
                )._asdict())

            # ETH address
            eth_addr = get_eth_address_from_mnemonic(master)
            balance = check_eth_balance(eth_addr)
            results.append(WalletResult(
                source_type="mnemonic",
                source_value=source_value,
                chain="eth",
                address=eth_addr,
                balance=balance,
                repo=repo,
                file=file,
                line=line,
            )._asdict())

        elif source_type == "private_key":
            hex_key = source_value.replace("0x", "")
            key_bytes = bytes.fromhex(hex_key)

            # Validate key
            key_int = int.from_bytes(key_bytes, "big")
            if key_int == 0 or key_int >= SECP256K1_N:
                print(f"  Skipping invalid key", file=sys.stderr)
                continue

            # BTC addresses
            btc_addrs = get_btc_addresses_from_key(key_bytes)
            for addr in btc_addrs:
                balance = check_btc_balance(addr)
                results.append(WalletResult(
                    source_type="private_key",
                    source_value=source_value,
                    chain="btc",
                    address=addr,
                    balance=balance,
                    repo=repo,
                    file=file,
                    line=line,
                )._asdict())

            # ETH address
            eth_addr = get_eth_address_from_key(key_bytes)
            balance = check_eth_balance(eth_addr)
            results.append(WalletResult(
                source_type="private_key",
                source_value=source_value,
                chain="eth",
                address=eth_addr,
                balance=balance,
                repo=repo,
                file=file,
                line=line,
            )._asdict())

    # Filter to only wallets with balance
    wallets_with_balance = [r for r in results if r["balance"] > 0]

    # Redact source values if requested
    output_results = wallets_with_balance if wallets_with_balance else results
    if args.redact:
        output_results = [{k: ("[REDACTED]" if k == "source_value" else v) for k, v in r.items()} for r in output_results]

    output = {
        "total_scanned": len(findings),
        "wallets_checked": len(results),
        "wallets_with_balance": len(wallets_with_balance),
        "results": output_results,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nResults saved to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(output, indent=2))

    # Summary
    print(f"\nScanned {len(findings)} findings, checked {len(results)} wallet addresses.", file=sys.stderr)
    if wallets_with_balance:
        print(f"\n** {len(wallets_with_balance)} WALLET(S) WITH BALANCE FOUND **", file=sys.stderr)
        for w in wallets_with_balance:
            print(f"  [{w['chain'].upper()}] {w['address']}  Balance: {w['balance']:.8f}", file=sys.stderr)
            print(f"    Source: {w['source_type']} from {w['repo']}/{w['file']}:{w['line']}", file=sys.stderr)
    else:
        print("No wallets with balance found.", file=sys.stderr)


if __name__ == "__main__":
    main()
