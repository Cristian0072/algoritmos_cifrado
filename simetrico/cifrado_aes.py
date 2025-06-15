"""
Cifrado y Descifrado Básico con AES (GCM)
Problema:
Cifra una cadena de texto corta (ej. "Hola mundo") usando AES en modo GCM con una clave generada aleatoriamente.
Luego, descifra el mensaje para verificar que sea el mismo.

Conceptos a aplicar:
Generación de clave, IV/Nonce, cifrado, descifrado, etiqueta de autenticación (GCM).
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

llave = get_random_bytes(32)  # Genera una clave de 32 bytes (256 bits)
# Genera un IV/Nonce o vector de inicialización de 12 bytes (96 bits)
iv = get_random_bytes(12)

print(f"Clave generada: {llave.hex()}")
print(f"IV o vector de incializacion: {iv.hex()}\n")


# función para cifrar el mensaje
def cifrado_aes(mensaje):
    cipher = AES.new(llave, AES.MODE_GCM, nonce=iv)
    # cifra el mensaje y genera una etiqueta de autenticación
    cifrado, etiqueta = cipher.encrypt_and_digest(mensaje)
    print(f"Mensaje cifrado: {cifrado.hex()}")

    return cifrado, etiqueta


# función para descifrar el mensaje cifrado
def descifrado_aes(cifrado, etiqueta):
    cipher = AES.new(llave, AES.MODE_GCM, nonce=iv)
    # descifra el mensaje y verifica la etiqueta de autenticación
    mensaje_descifrado = cipher.decrypt_and_verify(cifrado, etiqueta)
    print(f"Mensaje descifrado: {mensaje_descifrado.decode()}")

    return mensaje_descifrado


if __name__ == "__main__":
    mensaje = b"Hola mundo"  # Mensaje a cifrar
    cifrado, etiqueta = cifrado_aes(mensaje)
    mensaje_descifrado = descifrado_aes(cifrado, etiqueta)

    # Verificación
    if mensaje_descifrado == mensaje:
        print("El mensaje descifrado coincide con el original")
    else:
        print("El mensaje descifrado no coincide con el original")
