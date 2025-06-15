""" "
Concepto de "Key Pair Derivation" (Derivación de Pares de Claves)
Problema:
Aunque no es una derivación directa como en simétrica, investiga cómo se usan las semillas determinísticas
para generar pares de claves en criptografía. (Este ejercicio es más conceptual, puede que no haya una
implementación directa en bibliotecas comunes fuera de HD Wallets).

Conceptos a aplicar:
Semillas criptográficas, determinismo en generación de claves (blockchain/bitcoin si te interesa).
"""

# librerías utilizadas para la derivación de pares de claves en Bitcoin usando BIP44
from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)

# Generar mnemónico o frase de 12 palabras
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)

# semilla a partir de la frase mnemónica
semilla_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Crear contexto BIP44 para Bitcoin
bip44_ctx = Bip44.FromSeed(semilla_bytes, Bip44Coins.BITCOIN)

# Derivar la ruta m/44'/0'/0'/0/0
# (BIP44: 44' es el propósito, 0' es la moneda Bitcoin, 0 es la cuenta, 0 es el cambio, 0 es el índice de dirección)
child = (
    bip44_ctx.Purpose()  # 44'
    .Coin()  # 0'
    .Account(0)  # 0'
    .Change(Bip44Changes.CHAIN_EXT)  # 0
    .AddressIndex(0)  # 0
)

print("Mnemonic o frase de 12 palabras:", mnemonic.ToStr())
print("Clave privada :", child.PrivateKey().ToWif())
print("Clave pública :", child.PublicKey().ToAddress())
