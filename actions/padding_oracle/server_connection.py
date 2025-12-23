import socket

class Connection:
    def __init__(self, host, port, key_id, tcp_nodelay=True):
        self.host = host
        self.port = port
        self.key_id = key_id
        self.socket = None
        self.tcp_nodelay = tcp_nodelay

# Verbindung aufbauen
    def connect(self, timeout=5.0):
        self.socket = socket.create_connection((self.host, self.port), timeout=timeout)
        if self.tcp_nodelay:
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

# Exakte Anzahl erhalten für Fehlerbehebung
    def recv_exact(self, q_count):
        data = bytearray()
        while len(data) < q_count:
            chunk = self.socket.recv(q_count - len(data))
            if not chunk:
                raise ConnectionError("Connection closed before receiving bytes.")
            data.extend(chunk)
        return bytes(data)

# Key id rüberschicken 2 Bytes
    def send_key_id(self, key_id):
        key_id_bytes = key_id.to_bytes(2, byteorder="little")
        self.socket.sendall(key_id_bytes)

# Ciphertext rüberschicken 16 Bytes
    def send_ciphertext(self, ciphertext):
        self.socket.sendall(ciphertext)

# Folgende Anzahl der Blöcke rüberschicken 0 - 256 (2 Byte)
    def send_q_count(self, q_count):
        q_count_bytes = q_count.to_bytes(2, byteorder="little")
        self.socket.sendall(q_count_bytes)

# Q Blöcke abfeuern
    def send_q_blocks(self, q_block):
        self.socket.sendall(q_block)

# Antwort erhalten
    def receive_response(self, q_count):
        return self.recv_exact(q_count)

# Verbindung schließen
    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None