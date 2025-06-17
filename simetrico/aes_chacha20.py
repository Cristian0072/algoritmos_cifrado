"""
Medición de Rendimiento (AES vs. ChaCha20)
Problema:
Cifra un archivo grande (ej. 10MB) tanto con AES en modo GCM como con ChaCha20.
Mide el tiempo que tarda cada algoritmo en cifrar y descifrar.

Conceptos a aplicar:
Rendimiento de algoritmos, comparación de cifradores.
"""

from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
import time


def generar_clave_aes():
    return get_random_bytes(32)  # Clave de 256 bits para AES


def generar_clave_chacha20():
    return get_random_bytes(32)  # Clave de 256 bits para ChaCha20


def cifrar_aes(clave, archivo):
    cipher = AES.new(clave, AES.MODE_GCM)
    iv = cipher.nonce
    archivo_cifrado, etiqueta = cipher.encrypt_and_digest(archivo)
    return iv, archivo_cifrado, etiqueta


def descifrar_aes(clave, iv, archivo_cifrado, etiqueta):
    cipher = AES.new(clave, AES.MODE_GCM, nonce=iv)
    datos_descifrados = cipher.decrypt_and_verify(archivo_cifrado, etiqueta)
    return datos_descifrados


def cifrar_chacha20(clave, archivo):
    cipher = ChaCha20.new(key=clave)
    archivo_cifrado = cipher.encrypt(archivo)
    return cipher.nonce, archivo_cifrado


def descifrar_chacha20(clave, iv, archivo_cifrado):
    cipher = ChaCha20.new(key=clave, nonce=iv)
    datos_descifrados = cipher.decrypt(archivo_cifrado)
    return datos_descifrados


def medir_rendimiento(algoritmo, clave, archivo):
    tiempo_inicio = time.time()

    if algoritmo == "AES":
        iv, archivo_descifrado, etiqueta = cifrar_aes(clave, archivo)
        m_descifrado = descifrar_aes(clave, iv, archivo_descifrado, etiqueta)
    elif algoritmo == "ChaCha20":
        iv, archivo_descifrado = cifrar_chacha20(clave, archivo)
        m_descifrado = descifrar_chacha20(clave, iv, archivo_descifrado)

    tiempo_fin = time.time()

    tiempo_total = tiempo_fin - tiempo_inicio

    if archivo == m_descifrado:  # Verificar que el m_descifrado es correcto
        return tiempo_total
    else:
        return ValueError(
            "El archivo descifrado no coincide con los archivo originales"
        )


if __name__ == "__main__":
    # archivo de prueba (10 MB)
    archivo = get_random_bytes(10 * 1024 * 1024)  # 10 MB de archivo aleatorios

    print("Archivo de prueba generado (10 MB)")
    # Mostrar solo los primeros 50 caracteres
    print(archivo.hex()[:50], end="\n\n")

    # Medir rendimiento de AES
    clave_aes = generar_clave_aes()
    tiempo_aes = medir_rendimiento("AES", clave_aes, archivo)
    print(f"Tiempo de cifrado/descifrado de archivo con AES: {tiempo_aes:.6f} segundos")

    # Medir rendimiento de ChaCha20
    clave_chacha20 = generar_clave_chacha20()
    tiempo_chacha20 = medir_rendimiento("ChaCha20", clave_chacha20, archivo)
    print(
        f"Tiempo de cifrado/descifrado de archivo con ChaCha20: {tiempo_chacha20:.6f} segundos\n"
    )

    diferencia_tiempo = abs(tiempo_aes - tiempo_chacha20)
    print(f"Diferencia de tiempo (AES - ChaCha20): {diferencia_tiempo:.6f} segundos")

    if tiempo_aes < tiempo_chacha20:
        print("AES es más rápido que ChaCha20 para cifrar y descifrar este archivo")
    elif tiempo_aes > tiempo_chacha20:
        print("ChaCha20 es más rápido que AES para cifrar y descifrar este archivo")
