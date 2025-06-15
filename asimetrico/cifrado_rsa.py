"""
Cifrado y Descifrado con RSA
Problema:
Utilizando el par de claves RSA generado, cifra un mensaje corto con la clave pública.
Luego, descifra el mensaje con la clave privada. Demuestra que solo la clave privada correcta puede descifrarlo.

Conceptos a aplicar:
Cifrado asimétrico, longitud de mensaje limitada (RSA es lento para mensajes largos,
se usa para cifrar claves simétricas).
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def cifrar_mensaje(mensaje, clave_publica):
    cipher = PKCS1_OAEP.new(clave_publica)
    mensaje_cifrado = cipher.encrypt(mensaje.encode())
    return mensaje_cifrado


def descifrar_mensaje(mensaje_cifrado, clave_privada):
    try:
        cipher = PKCS1_OAEP.new(clave_privada)
        mensaje_descifrado = cipher.decrypt(mensaje_cifrado)
    except ValueError as e:
        return f"\nClave privada incorrecta: {e}"
    return mensaje_descifrado.decode()


def generar_claves():
    clave_privada = RSA.generate(2048)
    clave_publica = clave_privada.publickey()

    return clave_privada, clave_publica


if __name__ == "__main__":
    # Generar claves RSA
    clave_privada, clave_publica = generar_claves()
    clave_priv, _ = generar_claves()
    # Mensaje a cifrar
    mensaje = "Hola, hoy es un buen día para aprender sobre criptografía asimétrica"

    mensaje_cifrado = cifrar_mensaje(mensaje, clave_publica)
    print("\nMensaje cifrado:", mensaje_cifrado.hex())
    mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, clave_privada)
    print("Mensaje descifrado:", mensaje_descifrado)

    if mensaje == mensaje_descifrado:
        print("\nEl mensaje descifrado coincide con el original")

    mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, clave_priv)
    print(mensaje_descifrado)
    if mensaje != mensaje_descifrado:
        print("\nEl mensaje descifrado con clave incorrecta falló")
