"""
Problema:
Implementa un mecanismo (simulado) para solicitar una contraseña al usuario al cargar la clave privada RSA
de un archivo, garantizando que la clave privada esté protegida.

Conceptos a aplicar:
Protección de clave privada, cifrado de clave privada en reposo.
"""

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from getpass import getpass  # librería para solicitar contraseñas de forma segura


def generar_claves():
    c_privada = RSA.generate(2048)
    c_publica = c_privada.publickey()
    guardar_claves(c_privada, c_publica, "clave_privada.pem", "clave_publica.pem")
    return c_privada, c_publica


def guardar_claves(c_privada, c_publica, archivo_privada, archivo_publica):
    clave = getpass("Introduce una contraseña para proteger la clave privada: ")
    with open(archivo_privada, "wb") as f:
        # se guarda la clave privada cifrada con la contraseña proporcionada
        # pkcs=8 indica que se usará el formato PKCS#8
        # protection="scryptAndAES128-CBC" indica el método de cifrado es scrypt con AES-128-CBC
        # scrypt es un algoritmo de derivación de clave que es resistente a ataques de fuerza bruta
        f.write(
            c_privada.export_key(
                format="PEM", passphrase=clave, pkcs=8, protection="scryptAndAES128-CBC"
            )
        )
    with open(archivo_publica, "wb") as f:
        f.write(c_publica.export_key(format="PEM"))


def cargar_claves(archivo):
    clave = getpass("Introduce la contraseña para cargar la clave privada: ")
    try:
        with open(archivo, "rb") as f:
            c_privada = RSA.import_key(f.read(), passphrase=clave)
        return c_privada
    except ValueError:
        print("Contraseña incorrecta")
        return None


if __name__ == "__main__":
    # Generar y guardar claves
    c_privada, c_publica = generar_claves()

    # Cargar clave privada desde el archivo
    clave_privada = cargar_claves("clave_privada.pem")
    if clave_privada:
        print("Clave privada cargada correctamente\n")
        print("Clave pública:", c_publica.export_key().decode())
        print("Clave privada:", clave_privada.export_key().decode())
    else:
        print("\nError al cargar la clave privada")
