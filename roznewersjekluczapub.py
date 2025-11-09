import hashlib
import ecdsa
import base58
import bech32
from ecdsa.numbertheory import inverse_mod
from ecdsa.ecdsa import generator_secp256k1

# ✅ Dane obliczone wcześniej
d = int("72706b7143da5bcb1785d7f367e337944acc2f593e8c429fa076c28220485ea3", 16)

def generate_addresses_from_private_key(d, compressed=True):
    """
    Generowanie adresów:
      - Bech32 (native segwit, zaczynający się od "bc1")
      - P2SH (nested segwit, zaczynający się od "3")
      - Legacy P2PKH (zaczynający się od "1")
    """
    # Obliczamy klucz publiczny
    sk = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pubkey_uncompressed = b'\x04' + vk.to_string()
    # Jeśli compressed: prefix to 0x02 jeśli ostatni bajt jest parzysty, inaczej 0x03
    pubkey_compressed = (b'\x02' if vk.to_string()[-1] % 2 == 0 else b'\x03') + vk.to_string()[:32]
    
    # Wybieramy klucz publiczny zależnie od flagi compressed
    pubkey = pubkey_compressed if compressed else pubkey_uncompressed
    
    # Obliczamy HASH160 (SHA256, a następnie RIPEMD160)
    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    
    # ✅ Generowanie adresu Bech32 (native segwit, zaczyna się od bc1)
    bech32_address = bech32.encode("bc", 0, pubkey_hash)
    
    # ✅ Generowanie adresu P2SH (nested segwit, zaczyna się od 3)
    nested_script = b'\x00\x14' + pubkey_hash  # OP_0 + PUSH(20) + pubkey hash
    nested_hash = hashlib.new('ripemd160', hashlib.sha256(nested_script).digest()).digest()
    nested_p2sh = base58.b58encode_check(b'\x05' + nested_hash).decode()
    
    # ✅ Generowanie legacy adresu P2PKH (zaczyna się od 1)
    legacy_p2pkh = base58.b58encode_check(b'\x00' + pubkey_hash).decode()
    
    return bech32_address, nested_p2sh, legacy_p2pkh

# Dla klucza d generujemy adresy
# Użyjemy wersji compressed (możesz zmienić flagę na False, jeśli chcesz nieskompresowany)
bech32_address, p2sh_address, legacy_address = generate_addresses_from_private_key(d, compressed=True)

# Oczekiwane adresy (jeśli posiadasz)
expected_p2sh = ""
expected_bech32 = ""
expected_legacy = ""  # Legacy adres P2PKH zaczynający się od 1

print("\n🚀 ✅ **Obliczone adresy:**")
print(f"🔹 Bech32 (native segwit): {bech32_address}")
print(f"🔹 P2SH (nested segwit): {p2sh_address}")
print(f"🔹 Legacy P2PKH (zaczynający się od 1): {legacy_address}")
print(f"📌 Oczekiwany P2SH: {expected_p2sh}")
print(f"📌 Oczekiwany Bech32: {expected_bech32}")
print(f"📌 Oczekiwany Legacy: {expected_legacy}")

# Sprawdzamy, czy któryś z wygenerowanych adresów pasuje do oczekiwań
if (expected_p2sh in [p2sh_address]) and (expected_bech32 in [bech32_address]) and (expected_legacy in [legacy_address]):
    print("\n✅ 🔥 Klucz prywatny pasuje do jednego z adresów! To ten sam właściciel!")
else:
    print("\n❌ Adresy nie pasują! Możliwe, że użyto innego typu skryptu lub adres nie został poprawnie wygenerowany.")
