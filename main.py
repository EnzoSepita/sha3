from bitarray import bitarray
import sys
from operator import xor

round_constants = [
    0x0000000000000001,   0x0000000000008082,   0x800000000000808A,   0x8000000080008000,
  0x000000000000808B,   0x0000000080000001,   0x8000000080008081,   0x8000000000008009,
  0x000000000000008A,   0x0000000000000088,   0x0000000080008009,   0x000000008000000A,
  0x000000008000808B,   0x800000000000008B,   0x8000000000008089,   0x8000000000008003,
  0x8000000000008002,   0x8000000000000080,   0x000000000000800A,   0x800000008000000A,
  0x8000000080008081,   0x8000000000008080,   0x0000000080000001,   0x8000000080008008
]

def keccak_256(message_bits):
    # Étape 1: Initialisation du tableau d'état
    state = [[0] * 5 for _ in range(5)]
    print(state)
    
    # Étape 3: Ajout du padding
    message_length = len(message_bits)  # Obtenez la longueur actuelle du message en bits
    padding_bits = calculate_padding(message_length)
    message_bits += padding_bits
    
    # Étape 4: Absorption
    block_size = 1600
    for i in range(0, len(message_bits), block_size):
        block = message_bits[i:i+block_size]
    taille=len(block)
    if len(block) > block_size:
        raise ValueError("Block size mismatch")
    state_xor(block, state)
    keccak_f(state)
    
    # Étape 6: Troncature
    hash_bits = bitarray()
    for row in state:
        for value in row:
            hash_bits.extend(format(value, '08b'))

    return hash_bits[:256].tobytes()

def calculate_padding(message_length):
    # Taille du bloc (1600 bits pour Keccak-256)
    block_size = 1600
    
    # Calcul de la longueur du padding nécessaire
    padding_length = block_size - (message_length % block_size)
    
    # Ajout du bit "1"
    padding = bitarray('1')
    
    # Ajout des bits "0"
    padding.extend([0] * (padding_length - 1))
    
    return padding

def state_xor(block, state):
    for i in range(len(block)):
        row = i // 5
        col = i % 5
        row %= 5
        state[row][col] ^= block[i]

def keccak_f(state):
    for round in range(24):  # 24 rounds pour Keccak-256
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, round)

    return state

def theta(state):
    # Constantes spécifiques à Keccak-256
    row_count = 5
    column_count = 5

    c = [0] * column_count
    for i in range(column_count):
        c[i] = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ^ state[4][i]  #Opéraitons XOR

    d = [0] * column_count
    for i in range(column_count):
        d[i] = c[(i - 1) % column_count] ^ rotate_left(c[(i + 1) % column_count], 1) #Opérations cirulaires à gauche

    for i in range(row_count):
        for j in range(column_count):
            state[i][j] ^= d[j]   #Encore une opéarion XOR avec les nouvelles valeurs

    return state

def rotate_left(value, shift):
    lane_width = 64
    return ((value << shift) | (value >> (lane_width - shift))) & 0xFFFFFFFFFFFFFFFF

def rho(state):
    # Constante spécifiques à Keccak-256
    rotation_offsets = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]

    for i in range(len(rotation_offsets)):
        for j in range(len(rotation_offsets[i])):
            state[i][j] = rotate_left(state[i][j], rotation_offsets[i][j])

    return state

def pi(state):
    
    pi_offsets = [
        [0, 1, 2, 3, 4],
        [10, 7, 11, 17, 3],
        [18, 5, 24, 21, 8],
        [16, 13, 20, 14, 9],
        [7, 11, 17, 3, 10]
    ]

    new_state = [[0] * 5 for _ in range(5)]

    for i in range(len(pi_offsets)):
        for j in range(len(pi_offsets[i])):
            new_state[i][j] = state[pi_offsets[i][j] // 5][pi_offsets[i][j] % 5]

    return new_state

def chi(state):
    row_count = 5
    column_count = 5

    for i in range(row_count):
        t = [0] * column_count
        for j in range(column_count):
            t[j] = state[i][j] ^ ((state[(i + 1) % row_count][j] ^ 1) & state[(i + 2) % row_count][j])
        for j in range(column_count):
            state[i][j] = t[j]

    return state

def iota(state, round):

    state[0][0] ^= round_constants[round]

    return state

def hash_file(file_path, output_file_path="output_hash.txt"):
    # Lire le contenu du fichier
    with open(file_path, 'rb') as file:
        file_content = file.read()

    # Appeler la fonction de hachage sur le contenu du fichier
    file_hash = keccak_256(file_content)

    with open(output_file_path, 'w') as output_file:
        output_file.write(file_hash.hex())
    

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
    else:
        file_path = sys.argv[1]
        hash_file(file_path)
