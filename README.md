# Crypto Security Tools

A collection of Python utilities for scanning secrets across repositories and checking cryptocurrency wallet balances.

## Prerequisites

- Python 3.10+
- `git` (for repo-scanner.py)

### Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome
```

`pycryptodome` is required for Keccak-256 (Ethereum address derivation). The BTC tools (`btc-key-to-address.py`) have no external dependencies.

---

## Quick Start: Scan Repos and Check Wallets

```bash
# 1. Scan a GitHub org for secrets
python3 repo-scanner.py --org my-company --json-output > results.json

# 2. Check if any found keys have balance
python3 wallet-checker.py -i results.json -o wallets.json

# 3. Share results safely (redacted)
python3 wallet-checker.py -i results.json --redact -o wallets-safe.json
```

**Example run** (10,079 findings from GitHub search):
```
$ python3 wallet-checker.py -i results.json -o wallets.json

Processing mnemonic from bitcoinjs/bitcoinjs-lib/test/integration/bip32.spec.ts:28
Processing private_key from bisq-network/bisq/common/src/main/java/...
Processing mnemonic from breadwallet/breadwallet-core/Swift/...
...

Results saved to wallets.json

Scanned 10079 findings, checked 376 wallet addresses.
** 1 WALLET(S) WITH BALANCE FOUND **
  [ETH] 0x296E6b249637aF0E76a0215e5bb73A31bF80F64c  Balance: 0.00000000
    Source: mnemonic from bitcoinjs/bitcoinjs-lib/test/integration/bip32.spec.ts:28
```

---

## Tools

### 1. repo-scanner.py

Batch scanner for secrets across multiple git repositories.

**Detects:** API keys, secret keys, passwords, tokens, private keys (RSA/EC/OpenSSH), AWS/GCP/Azure keys, blockchain private keys (BTC/ETH), BIP39 mnemonics, public IPs, connection strings, JWT tokens.

```bash
# Scan a local repo
python3 repo-scanner.py /path/to/repo

# Scan repos from a CSV file
python3 repo-scanner.py --csv repos.csv

# Scan all repos in a GitHub org
python3 repo-scanner.py --org my-org

# Scan GitHub code search results with date filter
python3 repo-scanner.py --search ".env" --search "bitcoin" --created-after 2024-01-01 --limit 10

# Output as JSON for wallet-checker
python3 repo-scanner.py --org my-org --json-output > results.json
```

**Options:**

| Option | Description |
|--------|-------------|
| `repo` | Local repo path (scan without cloning) |
| `--csv FILE` | CSV file with repos (column `repo` or first column) |
| `--json-file FILE` | JSON file with repos |
| `--org ORG` | Scan all repos in a GitHub organization |
| `--user USER` | Scan all repos for a GitHub user |
| `--search QUERY` | GitHub code search query (repeatable, combined with AND) |
| `--created-after DATE` | Only repos created after this date (YYYY-MM-DD) |
| `--created-before DATE` | Only repos created before this date (YYYY-MM-DD) |
| `--limit N` | Max repos to scan |
| `--token TOKEN` | GitHub personal access token (or set `GITHUB_TOKEN` env var) |
| `--keep` | Keep cloned repos after scanning |
| `--exclude PATTERN` | Regex pattern to exclude files (repeatable) |
| `-j N` | Number of parallel workers (default: 4) |
| `-v` | Verbose output (show matched content) |
| `--json-output` | Output results as JSON |

**Rate Limits:** Without authentication, GitHub API allows 60 requests/hour. Set `GITHUB_TOKEN` env var or use `--token` for 5,000 requests/hour.

---

### 2. wallet-checker.py

Parse repo-scanner JSON output, derive wallet addresses, and check balances on Bitcoin and Ethereum.

```bash
# Pipe repo-scanner output directly
python3 repo-scanner.py --org my-org --json-output | python3 wallet-checker.py

# Use a saved JSON file
python3 wallet-checker.py -i results.json

# Save output to file
python3 wallet-checker.py -i results.json -o wallets.json

# Redact sensitive data (safe to share)
python3 wallet-checker.py -i results.json --redact -o wallets-safe.json
```

**What it does:**
1. Parses findings from repo-scanner (MNEMONIC, ETH_PRIVATE_KEY, BTC_PRIVATE_KEY, PRIVATE_KEY)
2. Derives BTC addresses (P2PKH, P2SH, Bech32) and ETH address
3. Validates BIP39 checksums for mnemonics
4. Checks balances on all derived addresses via public APIs
5. Returns JSON with wallets that have balance

**Options:**

| Option | Description |
|--------|-------------|
| `-i FILE` | Input JSON file (default: stdin) |
| `-o FILE` | Output JSON file (default: stdout) |
| `--redact` | Redact source keys/mnemonics from output |

**Output format:**
```json
{
  "total_scanned": 10079,
  "wallets_checked": 376,
  "wallets_with_balance": 1,
  "results": [
    {
      "source_type": "mnemonic",
      "source_value": "praise you muffin lion enable neck grocery crumble super myself license ghost",
      "chain": "eth",
      "address": "0x296E6b249637aF0E76a0215e5bb73A31bF80F64c",
      "balance": 4e-15,
      "repo": "bitcoinjs/bitcoinjs-lib",
      "file": "test/integration/bip32.spec.ts",
      "line": 28
    }
  ]
}
```

---

### 3. balance-checker.py

Check cryptocurrency balances from mnemonic phrases or private keys directly.

```bash
# Check balance from a mnemonic
python3 balance-checker.py --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Check balance from a Bitcoin WIF key
python3 balance-checker.py --wif "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

# Check balance from a hex private key
python3 balance-checker.py --hex "0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709"

# Check specific chains only
python3 balance-checker.py --mnemonic "your mnemonic here" --chains btc,eth

# JSON output
python3 balance-checker.py --hex "your_key" --json-output
```

**Options:**

| Option | Description |
|--------|-------------|
| `--mnemonic PHRASE` | 12 or 24 word BIP39 mnemonic |
| `--wif KEY` | Bitcoin WIF private key |
| `--hex KEY` | Hex private key (with or without 0x prefix) |
| `--chains LIST` | Comma-separated chains: btc, eth (default: both) |
| `--json-output` | Output as JSON |

**Supported chains:** BTC (P2PKH, P2SH, Bech32), ETH.

---

### 4. eth-key-to-address.py

Convert an Ethereum private key to public key and EIP-55 checksummed address.

```bash
# Convert key (0x prefix optional)
python3 eth-key-to-address.py 0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709

# JSON output
python3 eth-key-to-address.py --json 0x348ce564...
```

**Output:** Private key, public key (x, y coordinates), EIP-55 checksummed address.

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

---

### 5. btc-key-to-address.py

Convert a Bitcoin private key to public key and all address formats.

```bash
# Convert key (0x prefix optional)
python3 btc-key-to-address.py 0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709

# JSON output
python3 btc-key-to-address.py --json 0x348ce564...
```

**Output:** Private key, WIF, public key (x, y), P2PKH address, P2SH-SegWit address, Bech32 (native SegWit) address.

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

No external dependencies required.

---

### 6. mnemonic-to-addresses.py

Convert a BIP39 mnemonic phrase to BTC and ETH addresses.

```bash
# Convert 12-word mnemonic
python3 mnemonic-to-addresses.py "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# JSON output
python3 mnemonic-to-addresses.py --json "your mnemonic here"
```

**Output:** BTC P2PKH, BTC P2SH, BTC Bech32, ETH address.

**BIP44 derivation paths:**

| Chain | Path |
|-------|------|
| BTC P2PKH | `m/44'/0'/0'/0/0` |
| BTC P2SH | `m/49'/0'/0'/0/0` |
| BTC Bech32 | `m/84'/0'/0'/0/0` |
| ETH | `m/44'/60'/0'/0/0` |

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

---

## Security Notes

- **Never commit secrets to version control.** Use `.gitignore` for sensitive files.
- **Private keys control funds.** Treat them like cash. Anyone with a private key can spend the associated assets.
- **These tools run locally.** No data is sent to external services except public blockchain explorers for balance checks.
- **Use `--redact` flag** when sharing wallet-checker output to hide sensitive keys.
- **Balance checks query public APIs.** Using mnemonic phrases or private keys locally does not expose them, but be aware that balance queries hit third-party services (blockstream.info, publicnode.com).

## Limitations

- Balance lookups depend on third-party APIs and may be rate-limited or unavailable.
- Only standard BIP44 derivation paths are supported (account 0, index 0).
- Supported blockchains: Bitcoin and Ethereum only.
- `repo-scanner.py` detects common patterns but cannot guarantee zero false negatives.
- BIP39 wordlist is fetched from GitHub on first run (cached in memory).
