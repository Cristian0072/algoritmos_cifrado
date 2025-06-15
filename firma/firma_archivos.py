"""
Firma de Archivos
Problema:
Firma un archivo completo (ej. un PDF o un documento de texto) utilizando la clave privada RSA.
Genera un archivo de firma separado. Luego, verifica la firma del archivo utilizando la clave pública.

Conceptos a aplicar:
Hashing de archivos, firma de datos binarios.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generar_claves():
    clave = RSA.generate(2048)  # Genera una clave RSA de 2048 bits
    clave_privada = clave.export_key()
    clave_publica = clave.publickey().export_key()

    return clave_privada, clave_publica


def firmar_archivo(ruta_archivo, clave_privada):
    clave = RSA.import_key(clave_privada)

    # Leer el archivo y crear un hash
    with open(ruta_archivo, "rb") as archivo:
        contenido = archivo.read()
        hash_archivo = SHA256.new(contenido)  # Crear un hash del contenido del archivo

    # Firmar el hash del archivo
    firma = pkcs1_15.new(clave).sign(hash_archivo)

    # Guardar la firma en un archivo separado
    with open("firma.pem", "wb") as archivo_firma:
        archivo_firma.write(firma)

    return firma, hash_archivo


def verificar_firma_archivo(ruta_archivo, clave_publica):
    clave = RSA.import_key(clave_publica)

    # Leer el archivo y crear un hash
    with open(ruta_archivo, "rb") as archivo:
        contenido = archivo.read()
        hash_archivo = SHA256.new(contenido)  # Crear un hash del contenido del archivo

    print("Contenido del archivo:", contenido.decode())
    # Leer la firma del archivo
    with open("firma.pem", "rb") as archivo_firma:
        firma = archivo_firma.read()

    # Verificar la firma
    try:
        pkcs1_15.new(clave).verify(hash_archivo, firma)
        return "Firma válida"  # La firma es válida
    except (ValueError, TypeError):
        return "Firma no válida"  # La firma no es válida


if __name__ == "__main__":
    # Generar claves RSA
    clave_privada, clave_publica = generar_claves()

    # Ruta del archivo a firmar
    ruta_archivo = "hi.txt"

    # Firmar el archivo
    firma, hash_archivo = firmar_archivo(ruta_archivo, clave_privada)

    # Verificar la firma del archivo
    es_valida = verificar_firma_archivo(
        ruta_archivo, clave_publica
    )
    print("Archivo firmado:", ruta_archivo)
    print("Clave privada:", clave_privada.decode())
    print("Clave pública:", clave_publica.decode())
    print("Firma generada y guardada en:", "firma.pem")
    print("Hash del archivo:", hash_archivo.hexdigest())
    print("Resultado de la verificación de la firma:", es_valida)
