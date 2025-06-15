"""
Firma y Verificación Básica con RSA
Problema:
Firma un mensaje (ej. una cadena de texto) utilizando la clave privada RSA.
Luego, verifica la firma utilizando la clave pública RSA correspondiente para confirmar que el mensaje
no ha sido alterado y proviene del firmante.

Conceptos a aplicar:
Hash del mensaje, firma digital, verificación de firma.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generar_claves():
    clave = RSA.generate(2048)  # Genera una clave RSA de 2048 bits
    clave_privada = clave.export_key()
    clave_publica = clave.publickey().export_key()

    return clave_privada, clave_publica


def firmar_mensaje(mensaje, clave_privada):
    clave = RSA.import_key(clave_privada)
    hash_mensaje = SHA256.new(mensaje)  # Crear un hash del mensaje
    firma = pkcs1_15.new(clave).sign(hash_mensaje)  # Firmar el mensaje

    return firma, hash_mensaje


def verificar_firma(mensaje, firma, clave_publica):
    clave = RSA.import_key(clave_publica)
    try:
        pkcs1_15.new(clave).verify(mensaje, firma)  # Verificar la firma
        return "Verdadero"  # La firma es válida
    except (ValueError, TypeError):
        return "Falso"  # La firma no es válida


if __name__ == "__main__":
    # Generar claves RSA
    clave_privada, clave_publica = generar_claves()

    # Mensaje a firmar
    mensaje = b"Este mensaje va a ser firmado"

    # Firmar el mensaje
    firma, hash_mensaje = firmar_mensaje(mensaje, clave_privada)

    # Verificar la firma
    es_valida = verificar_firma(hash_mensaje, firma, clave_publica)

    print("Mensaje:", mensaje.decode())
    print("Firma:", firma.hex())
    print("Hash del mensaje:", hash_mensaje.digest().hex())
    print("Firma válida:", es_valida)
