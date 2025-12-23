import base64
from typing import Dict, Tuple

# =============================================================================
# Konstanten

P1 = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
P2 = (1 << 128) | (1 << 98) | (1 << 69) | (1 << 33) | 1
POLYS: Dict[str, int] = {"p1": P1, "p2": P2}

# =============================================================================
# Hilfsfunktionen

def reverse_byte(b: int) -> int:
    """
    Kehrt die Bitreihenfolge eines einzelnen Bytes um (Bit 7 <-> Bit 0, usw.).
    """
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2)
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1)
    return b

REVERSE_TABLE_LIST = [reverse_byte(i) for i in range(256)]
REVERSE_TABLE = bytes(REVERSE_TABLE_LIST)

def reverse_bits_128(x: int) -> int:
    """
    Kehrt die Bitreihenfolge in einem 128-Bit-Integer blockweise um:
    - Byte-Reihenfolge wird invertiert
    - Innerhalb jedes Bytes werden die Bits gespiegelt (mithilfe von REVERSE_TABLE)
    Rückgabe ist ein Integer mit vollständig umgekehrter Bitreihenfolge (128 Bit).
    """
    b = bytearray(x.to_bytes(16, "big"))
    b.reverse()
    for i in range(16):
        b[i] = REVERSE_TABLE[b[i]]
    return int.from_bytes(b, "big")

def bytes_to_int_gcm(bs: bytes) -> int:
    """
    Konvertiert 16 GCM-Bytes (Big-Endian, bitgespiegelt) in interne Polynomdarstellung.
    """
    be_val = int.from_bytes(bs, "big")
    return reverse_bits_128(be_val)

def int_to_bytes_gcm(x: int) -> bytes:
    """
    Konvertiert interne Polynomdarstellung in 16 GCM-Bytes (Bitspiegelung + Big-Endian).
    """
    reversed_bits = reverse_bits_128(x)
    return reversed_bits.to_bytes(16, "big")

def carryless_mul(a: int, b: int) -> int:
    """
    Carryless-Multiplikation (Polynomultiplikation über GF(2)) ohne Reduktion.
    Rückgabe: Produktpolynom als Integer (Grad bis < 256).
    """
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result

def gf_reduce_poly(product: int, r: int) -> int:
    """
    Reduziert ein Polynom 'product' modulo x^128 + r auf einen Grad < 128.
    r ist der niedergradige Teil.
    """
    while product.bit_length() > 128:
        highest_bit = product.bit_length() - 1
        shift = highest_bit - 128
        product ^= (1 << highest_bit) | (r << shift)
    return product & ((1 << 128) - 1)

def poly_divmod(a: int, b: int) -> Tuple[int, int]:
    """
    Polynomdivision in GF(2)[x]: Berechne (q, r) mit a = q*b + r und deg(r) < deg(b).
    """
    if b == 0:
        raise ZeroDivisionError("Division by zero polynomial")
    q = 0
    r = a
    deg_b = b.bit_length() - 1
    while r != 0 and (r.bit_length() - 1) >= deg_b:
        shift = (r.bit_length() - 1) - deg_b
        q ^= (1 << shift)
        r ^= (b << shift)
    return q, r

def poly_inv(a: int, mod_poly: int) -> int:
    """
    Berechnet das multiplikative Inverse von a.
    Nutzt den divmod-basierten erweiterten euklidischen Algorithmus.
    """
    if a == 0:
        raise ValueError("Element is not invertible")

    m = (1 << 128) | mod_poly
    u, v = m, a
    s, t = 0, 1 # Koeffizienten für u und v: s*m + t*a

    while v != 0:
        q, r = poly_divmod(u, v) # u = q*v + r
        u, v = v, r
        s, t = t, s ^ carryless_mul(q, t) # s, t = t, s + q*t
    return s & ((1 << 128) - 1)

def gf_square_and_multiply(x: int, base: int, exponent: int, mod_poly: int) -> int:
    """
    Exponentiation in GF(2^128) mit Square-and-Multiply.
    """
    while exponent > 0:
        if exponent & 1:
            x = carryless_mul(x, base)
            x = gf_reduce_poly(x, mod_poly)
        exponent >>= 1
        if exponent:
            base = carryless_mul(base, base)
            base = gf_reduce_poly(base, mod_poly)
    return x

def parse_exponent(exponent: int):
    """
    Konvertiert einen Integer oder String in einen Integer.
    """
    if isinstance(exponent, int):
        return exponent
    if isinstance(exponent, str):
        return int(exponent, 0)

# =============================================================================
# GF128 Klasse

class GF128:
    """
    Repräsentiert ein Element aus GF(2^128) mit festem Reduktionspolynom, intern in Polynomdarstellung.
    """
    __slots__ = ('value', 'poly')  # value: interne Polynomdarstellung als Integer

    def __init__(self, value: int, poly: str):
        poly_norm = str(poly).strip().lower()
        if poly_norm not in POLYS:
            raise ValueError(f'poly must be p1 or p2, got {str(poly)}')
        self.value = value & ((1 << 128) - 1)
        self.poly = poly_norm

    # Umrechnungen
    @staticmethod
    def from_bytes(b: bytes, poly: str) -> 'GF128':
        """
        Erzeugt ein Element aus 16 GCM-Bytes und wandelt in interne Polynomdarstellung um.
        """
        val = bytes_to_int_gcm(b)
        return GF128(val, poly)

    @staticmethod
    def from_b64(s: str, poly: str) -> 'GF128':
        """
        Erzeugt ein GF128-Element aus einem Base64-kodierten 16-Byte-Wert.
        """
        b = base64.b64decode(s)
        return GF128.from_bytes(b, poly)

    # Ausgabe
    def to_bytes(self) -> bytes:
        """
        Gibt das Element als 16 GCM-Bytes (intern -> GCM) zurück.
        """
        return int_to_bytes_gcm(self.value)

    def to_b64(self) -> str:
        """
        Gibt das Element Base64-kodiert (16 Bytes) zurück.
        """
        return base64.b64encode(self.to_bytes()).decode('ascii')

    def assert_same_poly(self, other: 'GF128'):
        """
        Stellt sicher, dass Operationen nur zwischen Elementen mit demselben Reduktionspolynom erfolgen.
        """
        if self.poly != other.poly:
            raise ValueError("Polynomials must match for GF operations.")

    # Grundoperationen
    def mul(self, other: 'GF128') -> 'GF128':
        """
        Multipliziert zwei GF(2^128)-Elemente und reduziert modulo x^128 + POLYS[self.poly].
        Rückgabe: neues GF128-Element.
        """
        self.assert_same_poly(other)
        product = carryless_mul(self.value, other.value)
        reduced = gf_reduce_poly(product, POLYS[self.poly])
        return GF128(reduced, self.poly)

    def inv(self) -> 'GF128':
        """
        Berechnet das multiplikative Inverse des Elements in GF(2^128).
        Rückgabe: neues GF128-Element (Inverse).
        """
        inv_val = poly_inv(self.value, POLYS[self.poly])
        return GF128(inv_val, self.poly)

    def div(self, other: 'GF128') -> 'GF128':
        """
        Teilt zwei GF(2^128)-Elemente: self / other = self * other^{-1}.
        Rückgabe: neues GF128-Element.
        """
        self.assert_same_poly(other)
        return self.mul(other.inv())

    def pow(self, exponent: int) -> 'GF128':
        """
        Potenziert das Element mit einem ganzzahligen Exponenten in GF(2^128).
        Rückgabe: neues GF128-Element.
        """
        base = gf_reduce_poly(self.value, POLYS[self.poly])
        y_int = 1
        result = gf_square_and_multiply(y_int, base, exponent, POLYS[self.poly])
        return GF128(result, self.poly)

    def sqrt(self) -> 'GF128':
        """
        Berechnet die Quadratwurzel in GF(2^128) als Potenz mit 2^127.
        Rückgabe: neues GF128-Element.
        """
        exponent = 1 << 127
        return self.pow(exponent)

    def __eq__(self, other: object) -> bool:
        """
        Vergleicht zwei GF128-Elemente auf Gleichheit von Polynom und internem Wert.
        """
        if not isinstance(other, GF128):
            return NotImplemented
        return self.poly == other.poly and self.value == other.value

    # Operator-Weiterleitungen (* -> mul(), / -> div(), ** -> pow())
    def __mul__(self, other: 'GF128') -> 'GF128':
        return self.mul(other)

    def __truediv__(self, other: 'GF128') -> 'GF128':
        return self.div(other)

    def __pow__(self, exponent: int, modulo=None) -> 'GF128':
        return self.pow(exponent)

# =============================================================================
# Funktionsaufrufe

def gf_mul(arguments: dict) -> dict:
    """
    Multipliziert zwei Base64-kodierte GF128-Elemente unter Angabe des Polynoms.
    Rückgabe: {"y": base64}, wobei y das Produkt ist.
    """
    a = GF128.from_b64(arguments["a"], arguments["poly"])
    b = GF128.from_b64(arguments["b"], arguments["poly"])
    y = a * b
    return {"y": y.to_b64()}

# Funktionsaufrufe: Ein-/Ausgabe in GCM, Rechenlogik intern
def gf_divmod(arguments: dict) -> dict:
    """
    Führt Polynomdivision auf internen Integers aus und gibt q, r als Base64-GCM zurück (keine Felddivision).
    """
    # GCM zu interner Polynomdarstellung umwandeln
    a_int = bytes_to_int_gcm(base64.b64decode(arguments["a"]))
    b_int = bytes_to_int_gcm(base64.b64decode(arguments["b"]))
    q_int, r_int = poly_divmod(a_int, b_int)
    # Interne Polynomdarstellung in GCM-Repräsentation umwandeln
    q_bytes = int_to_bytes_gcm(q_int)
    r_bytes = int_to_bytes_gcm(r_int)
    return {"q": base64.b64encode(q_bytes).decode("ascii"), "r": base64.b64encode(r_bytes).decode("ascii")}

def gf_inv(arguments: dict) -> dict:
    """
    Invertiert ein Base64-kodiertes GF128-Element unter Angabe des Polynoms.
    Rückgabe: {"y": base64} mit dem Inversen.
    """
    x = GF128.from_b64(arguments["x"], arguments["poly"])
    y = x.inv()
    return {"y": y.to_b64()}

def gf_div(arguments: dict) -> dict:
    """
    Teilt zwei Base64-kodierte GF128-Elemente (a / b) unter Angabe des Polynoms.
    Rückgabe: {"q": base64} mit dem Quotienten.
    """
    a = GF128.from_b64(arguments["a"], arguments["poly"])
    b = GF128.from_b64(arguments["b"], arguments["poly"])
    q = a / b
    return {"q": q.to_b64()}

def gf_pow(arguments: dict) -> dict:
    """
    Potenziert ein Base64-kodiertes GF128-Element mit einem ganzzahligen Exponenten.
    Rückgabe: {"y": base64} mit dem Potenzergebnis.
    """
    e = parse_exponent(arguments["e"])
    b = GF128.from_b64(arguments["b"], arguments["poly"])
    y = b ** e
    return {"y": y.to_b64()}

def gf_sqrt(arguments: dict) -> dict:
    """
    Berechnet die Quadratwurzel eines Base64-kodierten GF128-Elements.
    Rückgabe: {"y": base64} mit der Quadratwurzel (Potenz 2^127).
    """
    x = GF128.from_b64(arguments["x"], arguments["poly"])
    y = x.sqrt()
    return {"y": y.to_b64()}