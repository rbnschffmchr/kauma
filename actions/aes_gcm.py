import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from actions.gf128 import (
    POLYS,
    bytes_to_int_gcm,
    int_to_bytes_gcm,
    carryless_mul,
    gf_reduce_poly
)

BLOCK_SIZE = 16  # 128 Bit

def aes_ecb_encrypt_block(key_bytes: bytes, block16: bytes) -> bytes:
    """
    Verschlüsselt einen einzelnen 16-Byte-Block mit AES-128 im ECB-Modus.
    Rückgabe: 16 Bytes Ciphertext.
    """
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(block16) + encryptor.finalize()

def inc32(counter_block: bytes) -> bytes:
    """
    Erhöht den 32-Bit-Zähler eines 16-Byte-CTR-Blocks im Big-Endian-Format um 1.
    Layout: erste 12 Bytes = Nonce (Prefix), letzte 4 Bytes = Zähler
    Rückgabe: neuer 16-Byte-Block mit demselben Nonce und inkrementiertem Zähler.
    """
    nonce_prefix = counter_block[:12]  # feste 96-Bit Nonce (12 Bytes)
    counter_bytes = counter_block[12:]  # 32-Bit Zähler (4 Bytes)
    counter_value = int.from_bytes(counter_bytes, byteorder="big")

    new_counter_value = (counter_value + 1) & 0xFFFFFFFF
    new_counter_bytes = new_counter_value.to_bytes(4, byteorder="big")

    return nonce_prefix + new_counter_bytes

def split_blocks(b: bytes) -> Tuple[list, int]:
    """
    Teilt eine Bytefolge in 16-Byte-Blöcke auf.
    Rückgabe: (Liste der Blöcke, Gesamtlänge der Eingabe).
    """
    blocks = []
    length = len(b)
    for i in range(0, length, 16):
        blocks.append(b[i:i + 16])
    return blocks, length

def pad_to_block(b: bytes):
    """
    Paddet eine Bytefolge mit Nullbytes (0x00) auf das nächste Vielfache von 16 Bytes.
    Wenn bereits auf Blockgröße, bleibt die Eingabe unverändert.
    """
    if len(b) % 16 == 0:
        return b
    return b + bytes(16 - (len(b) % 16))

def gcm_len_block(len_a_int: int, len_c_int: int):
    """
    Erstellt den GCM-Längenblock (16 Bytes) aus den Bitlängen A (8 Byte) gefolgt von C (8 Byte)
    """
    return len_a_int.to_bytes(8, byteorder="big") + len_c_int.to_bytes(8, byteorder="big")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Führt ein byteweises XOR zwischen zwei Bytefolgen aus.
    Es werden nur so viele Bytes verarbeitet, wie die kürzere Eingabe lang ist.
    Rückgabe: neues Bytes-Objekt mit den XOR-Ergebnissen.
    """
    result_list = []
    for x, y in zip(a, b):
        result_list.append(x ^ y)
    return bytes(result_list)

def ghash(H_bytes: bytes, A: bytes, C: bytes, poly: str):
    # Startwert X_0, hier noch in GCM-Repräsentation (Umwandlung in step())
    X = bytes(BLOCK_SIZE)
    mod_poly = POLYS[poly]

    # GHASH-Schritt X = (X xor block) * H
    def step(X_bytes: bytes, ad_block_bytes: bytes):
        # GCM zu interner Polynomdarstellung
        X_int = bytes_to_int_gcm(X_bytes)
        A_int = bytes_to_int_gcm(ad_block_bytes)
        H_int = bytes_to_int_gcm(H_bytes)
        X_xor_A = X_int ^ A_int
        product = carryless_mul(X_xor_A, H_int)
        reduced = gf_reduce_poly(product, mod_poly)
        # Interne Polynomdarstellung zu GCM-Repräsentation
        return int_to_bytes_gcm(reduced)

    # A-Blöcke Null-Padding
    A_blocks, _ = split_blocks(pad_to_block(A))
    for a in A_blocks:
        X = step(X, a)

    # C-Blöcke Null-Padding
    C_blocks, _ = split_blocks(pad_to_block(C))
    for c in C_blocks:
        X = step(X, c)

    # Längenblock
    L = gcm_len_block(len(A)*8, len(C)*8)
    X = step(X, L)
    return X, L

def gcm_encrypt(arguments: dict) -> dict:
    """
    Führt die GCM-Verschlüsselung durch.
    """
    poly = arguments["poly"]
    key_bytes = base64.b64decode(arguments["key"])
    nonce_bytes = base64.b64decode(arguments["nonce"])
    plaintext_bytes = base64.b64decode(arguments["plaintext"])
    ad_bytes = base64.b64decode(arguments["ad"])

    # 1) H = AES_K(0^128) -> Auth key
    H = aes_ecb_encrypt_block(key_bytes, bytes(BLOCK_SIZE))

    # 2) Counter-Blöcke: Y0 = Nonce || 0x00000001 (für Tag-Maskierung)
    Y0 = nonce_bytes + (1).to_bytes(4, "big")
    # Y2, Y3, ... für Datenverschlüsselung (Start bei Nonce||0x00000002)
    ctr = 2
    Y = nonce_bytes + ctr.to_bytes(4, "big")

    # 3) CTR-Encryption des plaintexts
    c_chunks = []
    p_blocks, p_length = split_blocks(plaintext_bytes)
    for p in p_blocks:
        keystream = aes_ecb_encrypt_block(key_bytes, Y)
        c = xor_bytes(p, keystream[:len(p)])  # nur so viele Bytes wie p hat
        c_chunks.append(c)
        Y = inc32(Y)  # Zähler Y erhöhen, damit der nächste Block neuen Keystream erhält
    ciphertext = b"".join(c_chunks)

    # 4) GHASH über (A, C) durchführen
    S, L_block = ghash(H, ad_bytes, ciphertext, poly)

    # 5) TAG berechnen mit AES(YO) ^ outputGHASH
    E_Y0 = aes_ecb_encrypt_block(key_bytes, Y0)
    tag = xor_bytes(E_Y0, S)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "L": base64.b64encode(L_block).decode("ascii"),
        "H": base64.b64encode(H).decode("ascii"),
    }
