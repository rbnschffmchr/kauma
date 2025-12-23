import base64
import actions.padding_oracle.server_connection as sc

def split_cipher(cipher):
    """
    Teilt einen Byte-Ciphertext in 16-Byte-Blöcke und validiert die Länge
    """
    if len(cipher) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16.")
    blocks = []
    for i in range (0, len(cipher), 16):
        blocks.append(cipher[i:i+16])
    return blocks

def single_block_attack(key_id, block, prev_block, connection):
    """
    Führt einen Padding-Oracle-Angriff auf einen CBC-Block aus und gibt den 16-Byte-Klartext zurück.
    """
    try:
        connection.send_key_id(key_id)
        connection.send_ciphertext(block)
    except Exception as e:
        raise RuntimeError(f"Protocol send failed: {e}")

    plaintext = bytearray(16)

    for current_byte_index in reversed(range(16)): # von rechts nach links

        padding_value = 16 - current_byte_index
        q_count = 256

        # Q-Blöcke generieren
        q_blocks = []
        for guess in range(256):
            q_block_candidate = bytearray(16)

            # Für alle bereits gefundenen Bytes rechts vom aktuellen:
            # So setzen, dass sie ein gültiges Padding (padding_value) ergeben
            for j in range(15, current_byte_index, -1):
                q_block_candidate[j] = (plaintext[j] ^ padding_value) ^ prev_block[j]

            # Aktuelles Byte mit dem Guess so setzen, dass bei korrekter Vermutung das Padding gültig wird
            q_block_candidate[current_byte_index] = (guess ^ padding_value) ^ prev_block[current_byte_index]
            q_blocks.append(bytes(q_block_candidate))
        all_q_blocks = b"".join(q_blocks)

        # Server mit 256 Kandidaten in einem Zug abschießen
        try:
            connection.send_q_count(q_count)
            connection.send_q_blocks(all_q_blocks)
        except Exception as e:
            raise RuntimeError(f"Sending q_blocks or count failed at byte: {current_byte_index}: {e}")

        try:
            response = connection.receive_response(q_count)
        except Exception as e:
            raise RuntimeError(f"Receiving response failed at byte: {current_byte_index}: {e}")

        # Kandidaten finden, wo der Server eine 0x01 liefert
        candidates = []
        for i, r in enumerate(response):
            if r == 1:
                guess_value = i
                candidates.append(guess_value)

        # Prüfung, ob Kandidaten leer sind
        if not candidates:
            raise ValueError(f"No valid padding candidate for byte index {current_byte_index}")

        # Prüfung bei mehr als ein gefundener Kandidat
        if len(candidates) > 1:
            selected_candidate = None
            for candidate in candidates:
                q_block_candidate = bytearray(16)

                # bekannte Bytes mit aktuellem padding_value
                for i in range(15, current_byte_index, -1):
                    q_block_candidate[i] = (plaintext[i] ^ padding_value) ^ prev_block[i]

                # Kandidat für aktuelles Byte
                q_block_candidate[current_byte_index] = (candidate ^ padding_value) ^ prev_block[current_byte_index]

                # Wähle Flip Bit Index
                if current_byte_index > 0:
                    flip_index = current_byte_index - 1
                else:
                    flip_index = 1
                q_block_candidate[flip_index] ^= 0xFF

                # Zur Verifikation nur diesen einen Block senden
                try:
                    connection.send_q_count(1)
                    connection.send_q_blocks(bytes(q_block_candidate))
                    response = connection.receive_response(1)
                except Exception as e:
                    raise RuntimeError(f"Verification step failed at byte {current_byte_index}: {e}")

                # Wenn der Server erneut gültiges Padding meldet, ist dieser Kandidat korrekt
                if response and response[0] == 1:
                    selected_candidate = candidate
                    break

            if selected_candidate is None:
                raise ValueError(f"No valid candidate after verification at byte index {current_byte_index}")
        # Genau ein Kandidat
        else:
            selected_candidate = candidates[0]

        #Der gefundene Guess entspricht direkt dem Klartext-Byte
        plaintext[current_byte_index] = selected_candidate

    # Verbindung sauber schließen
    try:
        connection.send_q_count(0)
    except Exception as e:
        raise RuntimeError(f"Sending q_count (0) failed at block end: {e}")

    connection.close()
    return bytes(plaintext)

def start_attack(arguments):
    """
    Startet den Padding-Oracle-Angriff über alle CBC-Blöcke und gibt den Klartext Base64-kodiert zurück.
    """
    host = arguments["hostname"]
    port = arguments["port"]
    key_id = arguments["key_id"]
    iv = arguments["iv"]
    iv_bytes = base64.b64decode(iv)

    ciphertext = arguments["ciphertext"]
    ciphertext_blocks = split_cipher(base64.b64decode(ciphertext))

    full_plaintext = []
    prev_block = iv_bytes

    try:
    # Erster Block ist IV, danach immer vorheriger Cipherblock
        for block in ciphertext_blocks:
            connection = sc.Connection(host, port, key_id)
            connection.connect()
            plaintext_block = single_block_attack(key_id, block, prev_block, connection)
            full_plaintext += plaintext_block
            prev_block = block
    except Exception as e:
        return {"error": str(e)}

    result_bytes = bytes(full_plaintext)
    result_b64 = base64.b64encode(result_bytes).decode("ascii")
    return {"plaintext": result_b64}