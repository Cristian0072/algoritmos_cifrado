"""
Comunicación Segura Simétrica (Simulada)
Problema:
Simula una comunicación entre dos partes (Alice y Bob).
Alice genera una clave simétrica, la comparte con Bob (puedes simular esto simplemente pasándola en el código,
pero en la realidad sería un problema de intercambio de claves) y luego envía un mensaje cifrado a Bob.
Bob usa la clave para descifrar el mensaje.

Conceptos a aplicar:
Modelo emisor/receptor, intercambio de claves (simulado), cifrado/descifrado.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def generar_clave():
    clave = get_random_bytes(32)  # clave de 256 bits
    return clave


def cifrar_mensaje(clave, mensaje):
    cipher = AES.new(clave, AES.MODE_CBC)
    iv = cipher.iv
    mensaje_cifrado = cipher.encrypt(pad(mensaje.encode(), AES.block_size))
    return iv, mensaje_cifrado


def descifrar_mensaje(clave, iv, mensaje_cifrado):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    mensaje_descifrado = unpad(cipher.decrypt(mensaje_cifrado), AES.block_size)
    return mensaje_descifrado.decode()


def comunicacion_segura():
    # Alice genera una clave simétrica
    clave = generar_clave()
    print("Clave generada por Alice:", clave.hex())

    # Alice envía un mensaje a Bob
    mensaje = "Hola Bob, este es un mensaje secreto"
    iv, mensaje_cifrado = cifrar_mensaje(clave, mensaje)
    print(f"\nMensaje cifrado enviado a Bob: {mensaje_cifrado.hex()}\nIV: {iv.hex()}\n")

    # Bob recibe el mensaje y lo descifra
    mensaje_descifrado = descifrar_mensaje(clave, iv, mensaje_cifrado)
    print("Mensaje descifrado por Bob:", mensaje_descifrado)


if __name__ == "__main__":
    comunicacion_segura()
