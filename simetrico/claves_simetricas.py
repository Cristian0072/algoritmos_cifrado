""" "
Gestión de Claves Simétricas
Problema:
Genera una clave AES y guárdala de forma segura (ej. en un archivo con permisos restringidos,
o idealmente en un Key Management System simulado). Luego, carga la clave desde ese "almacén"
 para cifrar y descifrar un mensaje.

Conceptos a aplicar:
Almacenamiento seguro de claves, carga de claves, serialización/deserialización de claves.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import win32crypt  # librería para manejar claves en Windows con servicios de protección de datos (DPAPI)

clave_file = "clave_aes.key"


# generacion de clave AES y almacenamiento seguro
def generar_clave():
    # Genera una clave AES de 256 bits y la protege con DPAPI
    clave = get_random_bytes(32)
    # objeto es la clave protegida con DPAPI
    objeto = win32crypt.CryptProtectData(clave, None, None, None, None, 0)
    with open(clave_file, "wb") as f:
        f.write(objeto)

    print("Clave AES generada y guardada de forma segura (DPAPI)")
    return clave


# cargar la clave desde el archivo de almacenamiento seguro
def cargar_clave():
    with open(clave_file, "rb") as f:
        objeto = f.read()
    _, clave = win32crypt.CryptUnprotectData(objeto, None, None, None, 0)
    print("Clave AES cargada desde el almacenamiento seguro (DPAPI)")
    return clave


# cifrar mensaje con la clave AES
def cifrar_mensaje(mensaje, clave):
    iv = get_random_bytes(12)  # Genera un IV/Nonce de 12 bytes (96 bits)
    cipher = AES.new(clave, AES.MODE_GCM, nonce=iv)
    cifrado, etiqueta = cipher.encrypt_and_digest(mensaje)
    print(f"Mensaje cifrado: {cifrado.hex()}")
    return cifrado, etiqueta, iv


# descifrar mensaje con la clave AES
def descifrar_mensaje(cifrado, etiqueta, iv, clave):
    cipher = AES.new(clave, AES.MODE_GCM, nonce=iv)
    mensaje_descifrado = cipher.decrypt_and_verify(cifrado, etiqueta)
    print(f"Mensaje descifrado: {mensaje_descifrado.decode()}")
    return mensaje_descifrado


if __name__ == "__main__":
    # generar y guardar la clave
    clave = generar_clave()

    # cargar la clave desde el archivo
    clave_cargada = cargar_clave()

    # verificar que la clave cargada es la misma que la generada
    if clave == clave_cargada:
        "La clave cargada no coincide con la generada"
    else:
        print("La clave cargada coincide con la generada")

    # mensaje a cifrar
    mensaje = b"Hola mundo"

    # cifrar el mensaje
    cifrado, etiqueta, iv = cifrar_mensaje(mensaje, clave_cargada)

    # descifrar el mensaje
    mensaje_descifrado = descifrar_mensaje(cifrado, etiqueta, iv, clave_cargada)

    # verificación final
    if mensaje_descifrado == mensaje:
        print("\nEl mensaje descifrado coincide con el original")
    else:
        print("\nEl mensaje descifrado no coincide con el original")
