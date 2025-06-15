""" "
Uso de Algoritmos de Hashing para Firmas
Problema:
Al firmar, especifica un algoritmo de hashing diferente (ej. SHA-256 en lugar de SHA-512) y
observa cómo afecta el tamaño de la firma o la compatibilidad.

Conceptos a aplicar:
Algoritmos de hashing seguros (SHA-256, SHA-512), su importancia en firmas.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512, SHA256, SHA384, SHA224, SHA1
import time


def generar_claves():
    c_pivada = RSA.generate(2048)  # clave de 2048 bits
    c_publica = c_pivada.publickey()

    return c_pivada, c_publica


def firmar_mensaje(c_pivada, mensaje, algoritmo_hash):
    tiempo_inicio = time.time()  # Tiempo de inicio para medir duración
    if algoritmo_hash == "SHA256":
        hash_mensaje = SHA256.new(mensaje)
    elif algoritmo_hash == "SHA512":
        hash_mensaje = SHA512.new(mensaje)
    elif algoritmo_hash == "SHA384":
        hash_mensaje = SHA384.new(mensaje)
    elif algoritmo_hash == "SHA224":
        hash_mensaje = SHA224.new(mensaje)
    elif algoritmo_hash == "SHA1":
        hash_mensaje = SHA1.new(mensaje)
    else:
        raise ValueError("Algoritmo de hashing no soportado")

    # Firmar el hash con la clave privada
    firma = pkcs1_15.new(c_pivada).sign(hash_mensaje)
    tiempo_fin = time.time()  # Tiempo de fin para medir duración
    t = tiempo_fin - tiempo_inicio  # Guardar el tiempo de firma
    return firma, hash_mensaje, t


def verificar_firma(c_publica, mensaje, firma, hash_mensaje):

    try:
        # Verificar la firma con la clave pública
        pkcs1_15.new(c_publica).verify(hash_mensaje, firma)
        return "Firma válida"
    except (ValueError, TypeError):
        return "Firma no válida"


if __name__ == "__main__":
    algoritmosss_hash = ["SHA256", "SHA512", "SHA384", "SHA224", "SHA1"]
    # Generar claves
    c_pivada, c_publica = generar_claves()

    # Mensaje original
    m_original = b"Este es un mensaje importante"

    # Firmar el mensaje original con diferentes algoritmos de hashing
    for algoritmo in algoritmosss_hash:
        firma, hash_mensaje, t = firmar_mensaje(c_pivada, m_original, algoritmo)
        print(f"Firma usada ({algoritmo}): {firma.hex()}")
        print(f"Hash del mensaje ({algoritmo}): {hash_mensaje.hexdigest()}")
        print(f"Tamaño de la firma ({algoritmo}): {len(firma)} bytes")
        print(f"Tamaño del hash ({algoritmo}): {len(hash_mensaje.digest())} bytes")
        print(f"Tiempo de firma ({algoritmo}): {t:.6} segundos")
        # Verificar la firma con el mensaje original
        resultado = verificar_firma(c_publica, m_original, firma, hash_mensaje)
        print(f"Mensaje original: {m_original.decode()}")
        print(f"Resultado: {resultado}")
        print("-" * 40)
