""" "
Validación de Integridad con Firma
Problema:
Después de firmar un mensaje, modifica intencionalmente el mensaje original (ej. cambia una letra).
Intenta verificar la firma con el mensaje modificado y demuestra que la verificación falla.

Conceptos a aplicar:
Integridad de datos garantizada por la firma.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generar_claves():
    c_pivada = RSA.generate(2048)  # clave de 2048 bits
    c_publica = c_pivada.publickey()

    return c_pivada, c_publica


def firmar_mensaje(c_pivada, mensaje):
    # Crear un hash del mensaje
    hash_mensaje = SHA256.new(mensaje)

    # Firmar el hash con la clave privada
    firma = pkcs1_15.new(c_pivada).sign(hash_mensaje)

    return firma


def verificar_firma(c_publica, mensaje, firma):
    # Crear un hash del mensaje
    hash_mensaje = SHA256.new(mensaje)

    try:
        # Verificar la firma con la clave pública
        pkcs1_15.new(c_publica).verify(hash_mensaje, firma)
        return "Firma válida"
    except (ValueError, TypeError):
        return "Firma no válida"


if __name__ == "__main__":
    # Generar claves
    c_pivada, c_publica = generar_claves()

    # Mensaje original
    m_original = b"Este es un mensaje importante"

    # Firmar el mensaje original
    firma = firmar_mensaje(c_pivada, m_original)
    print(f"Firma usada: {firma.hex()}")

    # Verificar la firma con el mensaje original
    resultado = verificar_firma(c_publica, m_original, firma)
    print(f"Mensaje original: {m_original.decode()}")
    print(f"Resultado: {resultado}")

    # Modificar el mensaje original
    m_modificado = b"Este es un mensaje important"  

    # Verificar la firma con el mensaje modificado
    resultado = verificar_firma(
        c_publica, m_modificado, firma
    )
    print(f"\nMensaje modificado: {m_modificado.decode()}")
    print(f"Resultado: {resultado}")
