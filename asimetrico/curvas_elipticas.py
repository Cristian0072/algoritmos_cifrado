"""
Cifrado y Descifrado con Curvas Elípticas (ECC)
Problema:
Genera un par de claves ECC. Cifra un mensaje corto utilizando la clave pública ECC (usando un esquema como ECIES si tu biblioteca lo soporta)
y luego descífralo con la clave privada.

Conceptos a aplicar:
Criptografía de Curvas Elípticas, generación de claves ECC, ECIES (opcional, pero útil).
"""

from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# genera un par de claves ECC
def generar_claves_ecc():
    c_privada = ECC.generate(curve="P-256")
    c_publica = c_privada.public_key()
    return c_privada, c_publica


# cifra un mensaje con la clave pública ECC
def cifrar_mensaje_ecies(mensaje, c_publica):
    # Generar clave efímera
    efi_priv = ECC.generate(curve=c_publica.curve)
    efi_pub = efi_priv.public_key()
    # Secreto compartido por ECDH
    punto = efi_priv.d * c_publica.pointQ
    #  Derivar clave simétrica (32 bytes) vía HKDF-SHA256
    llave = HKDF(punto.x.to_bytes(32, "big"), 32, b"", SHA256)
    # Cifrar con AES-GCM para asegurar confidencialidad e integridad
    iv = get_random_bytes(12)
    cipher = AES.new(llave, AES.MODE_GCM, nonce=iv)
    m_cifrado, etiqueta = cipher.encrypt_and_digest(mensaje)
    # Exportar la clave pública efímera en DER para compatibilidad
    pub_eph_der = efi_pub.export_key(format="DER")

    return pub_eph_der, iv, m_cifrado, etiqueta


# descifrar un mensaje con la clave privada ECC
def descifrar_mensaje_ecies(c_publica, iv, m_cifrado, etiqueta, c_privada):
    # Importar la clave pública efímera
    efi_pub = ECC.import_key(c_publica)
    # Derivar mismo secreto compartido
    punto = c_privada.d * efi_pub.pointQ
    llave = HKDF(punto.x.to_bytes(32, "big"), 32, b"", SHA256)
    # Descifrar con AES-GCM
    cipher = AES.new(llave, AES.MODE_GCM, nonce=iv)
    # Verificar la etiqueta y descifrar
    m_descifrado = cipher.decrypt_and_verify(m_cifrado, etiqueta)
    return m_descifrado.decode()


if __name__ == "__main__":
    # Generar claves ECC
    c_privada, c_publica = generar_claves_ecc()

    # Mensaje a cifrar
    mensaje = b"Estoy utilizando criptografia de curvas elipticas"

    clave, iv, m_cifrado, etiqueta = cifrar_mensaje_ecies(mensaje, c_publica)
    print("\nMensaje cifrado:", m_cifrado.hex())

    m_descifrado = descifrar_mensaje_ecies(clave, iv, m_cifrado, etiqueta, c_privada)
    print("Mensaje descifrado:", m_descifrado)

    if mensaje.decode() == m_descifrado:
        print("\nEl mensaje descifrado coincide con el original")
