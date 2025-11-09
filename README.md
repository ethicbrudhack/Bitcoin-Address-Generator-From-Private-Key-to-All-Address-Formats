# 💎 Bitcoin Address Generator — From Private Key to All Address Formats

This Python script demonstrates how to **derive Bitcoin addresses** (Legacy, P2SH, and Bech32) directly from a **known private key `d`** using the **secp256k1** elliptic curve.

It covers all three major Bitcoin address formats:
- **Legacy P2PKH** (`1...`)
- **Nested SegWit (P2SH-P2WPKH)** (`3...`)
- **Native SegWit (Bech32 P2WPKH)** (`bc1...`)

---

## ⚙️ Script Overview

```python
import hashlib
import ecdsa
import base58
import bech32
from ecdsa.numbertheory import inverse_mod
from ecdsa.ecdsa import generator_secp256k1

# ✅ Recovered or known private key
d = int("72706b7143da5bcb1785d7f367e337944acc2f593e8c429fa076c28220485ea3", 16)

def generate_addresses_from_private_key(d, compressed=True):
    """
    Generate multiple Bitcoin address formats:
      - Bech32 (native SegWit, bc1...)
      - P2SH (nested SegWit, 3...)
      - Legacy P2PKH (1...)
    """
    # Create ECDSA key pair
    sk = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pubkey_uncompressed = b'\x04' + vk.to_string()
    pubkey_compressed = (b'\x02' if vk.to_string()[-1] % 2 == 0 else b'\x03') + vk.to_string()[:32]
    
    pubkey = pubkey_compressed if compressed else pubkey_uncompressed
    
    # HASH160(pubkey) = RIPEMD160(SHA256(pubkey))
    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    
    # ✅ Bech32 (native SegWit)
    bech32_address = bech32.encode("bc", 0, pubkey_hash)
    
    # ✅ P2SH (nested SegWit)
    nested_script = b'\x00\x14' + pubkey_hash
    nested_hash = hashlib.new('ripemd160', hashlib.sha256(nested_script).digest()).digest()
    nested_p2sh = base58.b58encode_check(b'\x05' + nested_hash).decode()
    
    # ✅ Legacy (P2PKH)
    legacy_p2pkh = base58.b58encode_check(b'\x00' + pubkey_hash).decode()
    
    return bech32_address, nested_p2sh, legacy_p2pkh

# Generate addresses
bech32_address, p2sh_address, legacy_address = generate_addresses_from_private_key(d, compressed=True)

# Optional expected addresses (for comparison)
expected_p2sh = ""
expected_bech32 = ""
expected_legacy = ""

print("\n🚀 ✅ **Generated Bitcoin Addresses:**")
print(f"🔹 Bech32 (native segwit): {bech32_address}")
print(f"🔹 P2SH (nested segwit): {p2sh_address}")
print(f"🔹 Legacy P2PKH: {legacy_address}")
🧠 Step-by-Step Explanation

Private Key → Public Key

The script uses ecdsa with the SECP256k1 curve (Bitcoin’s cryptographic foundation).

Depending on the compressed flag:

Uncompressed key: starts with 0x04

Compressed key: starts with 0x02 or 0x03 depending on the parity of the Y coordinate

Public Key → HASH160

Applies:

HASH160 = RIPEMD160(SHA256(pubkey))


Generate Address Types

Bech32 (P2WPKH): encoded using bech32.encode("bc", 0, HASH160)

P2SH-P2WPKH (Nested SegWit):

scriptSig = OP_0 + PUSH(20 bytes) + HASH160


Then hashed and Base58Check encoded with prefix 0x05

Legacy P2PKH:

Base58Check(0x00 + HASH160)

🧾 Example Output
🚀 ✅ **Generated Bitcoin Addresses:**
🔹 Bech32 (native segwit): bc1q9k5v2ayf93d7kpx6qz6cdvyz7nyh8vvqj8t6yq
🔹 P2SH (nested segwit): 3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6
🔹 Legacy P2PKH: 1GvPMTjKjW5qLhM4vWmBwhm8z2YRcKrZ5v

🧩 Address Type Comparison
Type	Prefix	Script	Typical Use
Legacy (P2PKH)	1	OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG	Old wallets, still supported
P2SH (Nested SegWit)	3	OP_HASH160 <redeemScriptHash> OP_EQUAL	Compatibility layer for SegWit
Bech32 (Native SegWit)	bc1	OP_0 <pubKeyHash>	Modern standard; lowest fees
⚠️ Security Notes

🔒 Never share your private key (d) — anyone with it can spend your Bitcoin.
🔒 Run this script only on offline, air-gapped systems if using real keys.
🔒 All computations here are deterministic and verifiable for audit and research.

🧰 Requirements

Install dependencies:

pip install ecdsa base58 bech32


Run the script:

python3 generate_bitcoin_addresses.py

📜 License

MIT License
© 2025 — Author: [ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr

🧠 TL;DR Summary

This script converts a known private key into all valid Bitcoin address formats
— Legacy (1...), P2SH (3...), and Bech32 (bc1...) —
showing how wallet software derives addresses directly from elliptic curve keys.
