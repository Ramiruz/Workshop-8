import threading
import hashlib
import time
import re

"""
Reto de programación número 8

A tener en cuenta para la solución:

- Digitar valores hash SHA-256 válidos, en caso contrario se solicitará nuevamente 
    hasta que se ingrese un valor válido.

- Se creará un archivo llamado resultados.txt donde se almacenarán los resultados
    
- El ganador será quien logre obtener el valor correcto en el menor tiempo posible.

Usado para la validación de la solución:

- https://xorbin.com/tools/sha256-hash-calculator (Xorbin SHA-256 Hash Calculator)
    Usado para obtener el hash SHA-256 de un texto.

- https://toolslick.com/math/bitwise/xor-calculator (Tool Slick XOR Calculator)
    Usado para obtener el XOR de dos hashes SHA-256.

En esta última herramienta se ingresan dos hashes SHA-256 y se obtiene el resultado 
de la operación XOR en diferentes valores. Bajando en la página se encuentra una 
tabla con los valores en hexadecimal, y binario. Donde el "Final Result" es el valor
que se tomó en cuenta para la solución.
"""


# Función para calcular el hash SHA-256 
def calcular_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Función para verificar si un texto es un hash SHA-256 válido
def verificacion_hash(text):
    formato_sha256 = re.compile(r'^[a-fA-F0-9]{64}$')
    return bool(formato_sha256.match(text))

# Función para calcular el XOR de dos hashes SHA-256
def xor_hash(hash1, hash2):
    int_hash1 = int(hash1, 16)
    int_hash2 = int(hash2, 16)
    resultado_xor = int_hash1 ^ int_hash2
    return format(resultado_xor, '064x') 

# Función para simular la tarea de cada participante
# se imprime el nombre del participante, la entrada de SHA-256, la salida de SHA-256 y el tiempo total
def tarea_participante(nombre, hash_inicial, barrier, ganador):
    try:
        inicio = time.time()
        hash_final = hash_inicial
        
        # Calcular el hash SHA-256 hasta que el resultado comience con cuatro ceros
        while True:
            hash_final = calcular_hash(hash_final)
            resultado_xor = xor_hash(hash_inicial, hash_final)

            # Verificar si el resultado comienza con cuatro ceros en su representación binaria
            if resultado_xor.startswith('0000'):
                final = time.time()
                tiempo_total = final - inicio

                # Escribir los resultados en un archivo
                with open("resultados.txt", "a") as file:
                    file.write("\n__________________________________________________________\n")
                    file.write(f"\nParticipante: {nombre}\n")
                    file.write(f"Entrada de SHA-256: {hash_inicial}\n")
                    file.write(f"Salida de SHA-256: {hash_final}\n")
                    file.write(f"Tiempo total: {tiempo_total} segundos\n")
                ganador.append((nombre, tiempo_total))
                break

    except Exception as e:
        print(f"Error ocurrido con el participante {nombre}: {e}")

    # Esperar a que todos los participantes terminen
    barrier.wait()

def main():
    with open("resultados.txt", "a"):
        pass

    # Solicitar al usuario que ingrese un hash SHA-256
    while True:
        hash_inicial = input("\nIngrese el hash SHA-256: ")

        # Verificar si el hash ingresado es válido
        if verificacion_hash(hash_inicial):
            break
        else:
            print("\nValor inválido! Por favor ingrese un hash SHA-256 válido.")

    # Crear una barrera para sincronizar los participantes
    barrier = threading.Barrier(3)

    ganador = []
    threads = []
    participantes = ["Hugo", "Paco", "Luis"]

    # Crear un hilo para cada participante
    for participante in participantes:
        thread = threading.Thread(target=tarea_participante, args=(participante, hash_inicial, barrier, ganador))
        threads.append(thread)
        thread.start()

    # Esperar a que todos los hilos terminen
    for thread in threads:
        thread.join()

    # Ordenar a los ganadores por tiempo
    ganador.sort(key=lambda x: x[1])
    nombre_ganador, tiempo_ganador = ganador[0]

    # Imprimir el nombre del ganador y el tiempo
    with open("resultados.txt", "a") as file:
        file.write("\n__________________________________________________________\n")
        file.write(f"\nGanador: {nombre_ganador} con un tiempo de {tiempo_ganador} segundos.\n")

    print("\nRevisar el archivo resultados.txt para ver los resultados.")
    print("Favor de revisar el primer comentario en el codigo para entender como se logró la verificacion.\n")

if __name__ == "__main__":
    main()