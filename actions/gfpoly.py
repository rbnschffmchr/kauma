from typing import List, Iterable, Tuple
from actions import gf128
import random

GFElement = gf128.GF128  # Alias für bessere Lesbarkeit

def normalize(coeffs: List[GFElement]) -> List[GFElement]:
    """Entfernt führende Nullkoeffizienten und kürzt die Koeffizientenliste entsprechend."""
    i = len(coeffs) - 1
    while i > 0 and coeffs[i].value == 0:
        i -= 1
    return coeffs[:i + 1]

class GFPoly:
    """Polynom über GF(2^128) mit Koeffizientenliste in aufsteigender Gradordnung (konstantes Glied zuerst)."""
    __slots__ = ('coeffs', 'poly')

    def __init__(self, coeffs: Iterable[GFElement], poly: str):
        """Initialisiert ein Polynom mit Koeffizienten im selben Feld (p1/p2) und normalisiert führende Nullen."""
        coeffs = list(coeffs)
        # leere Liste als 0-Polynom interpretieren
        if len(coeffs) == 0:
            coeffs = [GFElement(0, poly)]

        poly_norm = str(poly).strip().lower()
        if poly_norm not in gf128.POLYS:
            raise ValueError(f'poly must be p1 or p2, got {poly}')
        # alle Koeffizienten müssen in demselben Körper sein
        for c in coeffs:
            if c.poly != poly_norm:
                raise ValueError("All coefficients must use the same reduction polynomial")
        self.poly = poly_norm
        self.coeffs = normalize(coeffs)  # führende Nullen entfernen

    @classmethod
    def from_b64(cls, arr: Iterable[str], poly: str) -> 'GFPoly':
        """Erzeugt ein Polynom aus Base64-kodierten Koeffizienten im Feld poly."""
        elements = [GFElement.from_b64(s, poly) for s in arr]
        return cls(elements, poly)

    @staticmethod
    def zero(poly: str) -> 'GFPoly':
        """Gibt das Nullpolynom im Feld poly zurück."""
        return GFPoly([GFElement(0, poly)], poly)

    @staticmethod
    def one(poly: str) -> 'GFPoly':
        """Gibt das Einspolynom (1) im Feld poly zurück."""
        return GFPoly([GFElement(1, poly)], poly)

    @staticmethod
    def X(poly: str) -> 'GFPoly':
        """Gibt das Polynom X im Feld poly zurück."""
        # [0, 1] entspricht 0 + 1*X
        return GFPoly([GFElement(0, poly), GFElement(1, poly)], poly)

    def deg(self) -> int:
        """Gibt den Grad des Polynoms zurück."""
        return len(self.coeffs) - 1

    def is_zero(self) -> bool:
        """Prüft, ob das Polynom das Nullpolynom ist."""
        return len(self.coeffs) == 1 and self.coeffs[0].value == 0

    def is_one(self) -> bool:
        """Prüft, ob das Polynom das Einspolynom ist."""
        return len(self.coeffs) == 1 and self.coeffs[0].value == 1

    def leading_coeff(self) -> GFElement:
        """Gibt den führenden Koeffizienten (höchster Grad) zurück."""
        return self.coeffs[-1]

    def to_b64(self) -> List[str]:
        """Serialisiert die Koeffizientenliste Base64-kodiert."""
        return [c.to_b64() for c in self.coeffs]

    def as_list(self) -> List[GFElement]:
        """Gibt eine Kopie der Koeffizientenliste zurück."""
        return list(self.coeffs)

    def _assert_same_poly(self, other: 'GFPoly'):
        """Stellt sicher, dass beide Polynome im selben Feld (poly) liegen."""
        if self.poly != other.poly:
            raise ValueError("Polynomial fields must match")

    def monic(self) -> 'GFPoly':
        """Skaliert das Polynom so, dass der führende Koeffizient 1 ist, Nullpolynom bleibt Null."""
        if self.is_zero():
            return GFPoly.zero(self.poly)
        lead_coeff = self.leading_coeff()
        # wenn führender Koeffizient bereits 1 ist, keine Skalierung nötig
        if lead_coeff.value == 1:
            return self
        inv_lead_coeff = lead_coeff.inv()  # Inverses im Körper berechnen
        return GFPoly([c * inv_lead_coeff for c in self.coeffs], self.poly)

    def __eq__(self, other: object) -> bool:
        """Vergleicht auf Gleichheit von Feld und Koeffizientenliste."""
        return isinstance(other, GFPoly) and self.poly == other.poly and self.coeffs == other.coeffs

    def __lt__(self, other: 'GFPoly') -> bool:
        """Vergleicht Polynome lexikographisch nach Grad und führenden Koeffizientenwerten."""
        self._assert_same_poly(other)
        deg_A = self.deg()
        deg_B = other.deg()
        # zuerst nach Grad vergleichen
        if deg_A != deg_B:
            return deg_A < deg_B
        # bei gleichem Grad die Koeffizienten von oben nach unten vergleichen
        for i in range(deg_A, -1, -1):
            a = self.coeffs[i].value
            b = other.coeffs[i].value
            if a != b:
                return a < b
        return False

    # =============================================================================
    # Polynom-Arithmetik

    def mod(self, other: 'GFPoly') -> 'GFPoly':
        """Gibt den Rest der Polynomdivision self div other zurück."""
        _, r = self.divmod(other)
        return r

    def add(self, other: 'GFPoly') -> 'GFPoly':
        """Addiert zwei Polynome Koeffizient-weise in GF(2^128)."""
        self._assert_same_poly(other)
        n = max(len(self.coeffs), len(other.coeffs))
        out = []
        for i in range(n):
            a = self.coeffs[i] if i < len(self.coeffs) else GFElement(0, self.poly)
            b = other.coeffs[i] if i < len(other.coeffs) else GFElement(0, self.poly)
            out.append(GFElement(a.value ^ b.value, self.poly))
        return GFPoly(out, self.poly)

    def sub(self, other: 'GFPoly') -> 'GFPoly':
        """Subtrahiert zwei Polynome, identisch zur Addition in GF(2^128)."""
        return self.add(other)

    def mul(self, other: 'GFPoly') -> 'GFPoly':
        """Multipliziert zwei Polynome und gibt das Ergebnis zurück."""
        self._assert_same_poly(other)
        deg_A = self.deg()
        deg_B = other.deg()

        out = [GFElement(0, self.poly) for _ in range(deg_A + deg_B + 1)]

        for i, ai in enumerate(self.coeffs):
            for j, bj in enumerate(other.coeffs):
                product = ai * bj
                out_ij = out[i+j].value ^ product.value
                out[i+j] = GFElement(out_ij, self.poly)
        return GFPoly(out, self.poly)

    def divmod(self, other: 'GFPoly') -> Tuple['GFPoly', 'GFPoly']:
        """Berechnet Quotient und Rest der Polynomdivision self durch other."""
        self._assert_same_poly(other)
        quotient_length = max(0, self.deg() - other.deg()) + 1
        deg_divisor = other.deg()
        inv_leading_divisor = other.leading_coeff().inv()  # für Monizierung des Divisors

        Q = [GFElement(0, self.poly) for _ in range(quotient_length)]
        R = normalize(self.as_list())  # aktueller Rest
        # Divisionsalgorithmus: führe den führenden Term des Restes gegen den des Divisors aus
        while (len(R) - 1) >= deg_divisor and any(c.value != 0 for c in R):
            shift_degree = (len(R) - 1) - deg_divisor
            scale_factor = R[-1] * inv_leading_divisor  # Faktor zum Eliminieren des führenden Terms
            Q[shift_degree] = GFElement(Q[shift_degree].value ^ scale_factor.value, self.poly)
            # skalierten Divisor entsprechend Gradverschiebung ausrichten
            scaled_shifted_divisor = [GFElement(0, self.poly) for _ in range(shift_degree)]
            for coeff_b in other.coeffs:
                scaled_shifted_divisor.append(coeff_b * scale_factor)
            # neuen Rest via XOR bilden
            max_len = max(len(R), len(scaled_shifted_divisor))
            new_remainder = []
            for i in range(max_len):
                coeff_r = R[i] if i < len(R) else GFElement(0, self.poly)
                coeff_t = scaled_shifted_divisor[i] if i < len(scaled_shifted_divisor) else GFElement(0, self.poly)
                new_remainder.append(GFElement(coeff_r.value ^ coeff_t.value, self.poly))
            R = normalize(new_remainder)  # führende Nullen nach Subtraktion entfernen
        return GFPoly(Q, self.poly), GFPoly(R, self.poly)

    def gcd(self, other: 'GFPoly') -> 'GFPoly':
        """Berechnet den größten gemeinsamen Teiler mittels wiederholter Division und Monizierung."""
        self._assert_same_poly(other)
        A = self
        B = other
        # Euklidischer Algorithmus
        while any(coeff.value != 0 for coeff in B.coeffs):
            Q, R = A.divmod(B)
            A, B = B, R
        # Ergebnis als monisches Polynom zurückgeben (falls nicht Null)
        return GFPoly.zero(self.poly) if A.is_zero() else A.monic()

    def pow(self, e: int) -> 'GFPoly':
        """Potenziert das Polynom mit Exponent e via Square-and-Multiply."""
        Z = GFPoly.one(self.poly)   # Akkumulator
        base = GFPoly(self.coeffs, self.poly)
        exponent = int(e)
        # Binäre Exponentiation
        while exponent > 0:
            if (exponent & 1) != 0:
                Z *= base
            exponent >>= 1
            if exponent != 0:
                base *= base
        return Z

    def powmod(self, e: int, M: 'GFPoly') -> 'GFPoly':
        """Berechnet self^e modulo M via Square-and-Multiply mit Zwischenreduktionen."""
        self._assert_same_poly(M)
        Z = GFPoly.one(self.poly)
        # Sonderfälle
        if M.is_one():
            return GFPoly.zero(self.poly)  # f^e mod 1 = 0
        exponent = int(e)
        if exponent == 0:
            return GFPoly.one(self.poly)  # f^0 mod M = 1
        if self.is_zero():
            return GFPoly.zero(self.poly)  # 0^e mod M = 0 für e > 0
        base = self % M  # initiale Reduktion
        # Binäre Exponentiation mit Modulo nach jedem Schritt
        while exponent > 0:
            if (exponent & 1) != 0:
                Z = (Z*base) % M
            exponent >>= 1
            if exponent != 0:
                base = (base*base) % M
        return Z

    def diff(self) -> 'GFPoly':
        """Berechnet die Ableitung in GF(2), wobei nur ungerade Grade erhalten bleiben."""
        if len(self.coeffs) <= 1:
            return GFPoly.zero(self.poly)
        diff = []
        for i in range(1, len(self.coeffs)):
            if (i % 2) == 1:
                diff.append(self.coeffs[i])
            else:
                diff.append(GFElement(0, self.poly))
        return GFPoly(diff, self.poly)

    def sqrt(self) -> 'GFPoly':
        """Berechnet die Quadratwurzel, indem nur Koeffizienten gerader Grade berücksichtigt werden."""
        max_i = (len(self.coeffs) - 1) // 2
        sqrt = []

        for i in range(max_i + 1):
            index = 2 * i
            c = self.coeffs[index] if index < len(self.coeffs) else GFElement(0, self.poly)
            sqrt.append(c.sqrt())
        return GFPoly(sqrt, self.poly)

    def square_free_factorization(self) -> List[Tuple['GFPoly', int]]:
        """Führt die Square-Free-Faktorisierung nach Algorithmus durch und gibt (Faktor, Exponent)-Paare zurück."""
        F = self.monic()
        def sff(f: 'GFPoly') -> List[Tuple['GFPoly', int]]:
            df = f.diff()
            c = f.gcd(df)
            f_div_c, _ = f.divmod(c)
            z = []
            e = 1
            f_current = f_div_c
            c_current = c

            while not f_current.is_one():
                y = f_current.gcd(c_current)
                if f_current != y:
                    q, _ = f_current.divmod(y)
                    z.append((q.monic(), e))
                f_current = y
                c_current, _ = c_current.divmod(y)
                e += 1

            if not c_current.is_one():
                r_factors = sff(c_current.sqrt())
                for f_star, e_star in r_factors:
                    z.append((f_star, 2 * e_star))
            return z
        factors = sff(F)
        factors_sorted = sorted(factors, key=lambda FE: FE[0])
        return factors_sorted

    def distinct_degree_factorization(self) -> List[Tuple['GFPoly', int]]:
        """Zerlegt das Polynom in Faktoren mit paarweise verschiedenen Graden mittels DDF-Verfahren."""
        f = self.monic()
        q = 2 ** 128  # Feldgröße von GF(2^128)
        z = []
        d = 1
        f_star = GFPoly(f.coeffs, f.poly)
        X = GFPoly.X(self.poly)

        while f_star.deg() >= 2 * d:
            h = X.powmod(q ** d, f_star) - X
            g = h.gcd(f_star)
            if not g.is_one():
                z.append((g.monic(), d))
                f_star, _ = f_star.divmod(g)
                f_star = f_star.monic()
            d += 1

        if not f_star.is_one():
            z.append((f_star.monic(), f_star.deg()))
        elif len(z) == 0:
            z.append((f, 1))
        z_sorted = sorted(z, key=lambda FE: FE[0])
        return z_sorted

    def equal_degree_factorization(self, d: int) -> List['GFPoly']:
        """Faktorisierung in gleichgradige Faktoren d mittels randomisierter EDF über GF(2^128)."""
        f = self.monic()
        n, r = divmod(f.deg(), d)
        if r != 0:
            raise ValueError("deg(f) ist kein Vielfaches von d")
        q = 2 ** 128
        exponent = (q ** d - 1) // 3
        z = [f]
        while len(z) < n:
            # zufälliges h mit Grad 1..deg(f)-1 erzeugen
            deg_h = random.randrange(1, max(2, f.deg()))
            coeffs = [GFElement(random.getrandbits(128), f.poly) for _ in range(deg_h + 1)]
            # sicherstellen, dass h nicht das Nullpolynom ist
            if all(c.value == 0 for c in coeffs):
                coeffs[0] = GFElement(1, f.poly)
            h = GFPoly(coeffs, f.poly)
            h_pow_e = h.powmod(exponent, f)
            g = h_pow_e - GFPoly.one(f.poly)
            snapshot = list(z)
            for u in snapshot:
                if u.deg() > d:
                    j = u.gcd(g)
                    if not j.is_one() and j != u:
                        q_div, _ = u.divmod(j)
                        z.remove(u)
                        j_monic = j.monic()
                        q_monic = q_div.monic()
                        # nur Faktoren mit Grad >= d wieder aufnehmen
                        if j_monic.deg() >= d:
                            z.append(j_monic)
                        if q_monic.deg() >= d:
                            z.append(q_monic)

        z = [p.monic() for p in z if p.deg() == d and not p.is_one() and not p.is_zero()]
        z.sort()
        return z

    # =============================================================================
    # Operator-Weiterleitungen

    def __add__(self, other: 'GFPoly') -> 'GFPoly':
        return self.add(other)

    def __sub__(self, other: 'GFPoly') -> 'GFPoly':
        return self.sub(other)

    def __mul__(self, other: 'GFPoly') -> 'GFPoly':
        return self.mul(other)

    def __pow__(self, exponent: int, modulo=None) -> 'GFPoly':
        return self.pow(exponent)

    def __mod__(self, other: 'GFPoly') -> 'GFPoly':
        return self.mod(other)

# =============================================================================
# Funktionsaufrufe

def gfpoly_sort(arguments: dict) -> dict:
    """Sortiert Polynome anhand __lt__ und gibt die Base64-kodierten Koeffizientenlisten zurück."""
    polys_b64 = arguments["polys"]
    placeholder_poly = "p1"  # Platzhalter-Poly, nur für Konstruktion (Feldprüfung intern ungenutzt beim Sortieren)
    polys = [GFPoly.from_b64(arr, placeholder_poly) for arr in polys_b64]
    polys_sorted = sorted(polys)  # nutzt __lt__ für Ordnung
    out_sorted = [P.to_b64() for P in polys_sorted]
    return {"sorted": out_sorted}

def gfpoly_monic(arguments: dict) -> dict:
    """Monisiert ein Polynom und gibt die Base64-kodierte Koeffizientenliste zurück."""
    A = GFPoly.from_b64(arguments["A"], arguments["poly"])
    return {"A*": A.monic().to_b64()}

def gfpoly_add(arguments: dict) -> dict:
    """Addiert zwei Polynome und gibt die Summe Base64-kodiert zurück."""
    A = GFPoly.from_b64(arguments["A"], arguments["poly"])
    B = GFPoly.from_b64(arguments["B"], arguments["poly"])
    S = A + B
    return {"S": S.to_b64()}

def gfpoly_mul(arguments: dict) -> dict:
    """Multipliziert zwei Polynome und gibt das Produkt Base64-kodiert zurück."""
    A = GFPoly.from_b64(arguments["A"], arguments["poly"])
    B = GFPoly.from_b64(arguments["B"], arguments["poly"])
    P = A * B
    return {"P": P.to_b64()}

def gfpoly_divmod(arguments: dict) -> dict:
    """Berechnet Quotient und Rest der Polynomdivision und gibt beide Base64-kodiert zurück."""
    A = GFPoly.from_b64(arguments["A"], arguments["poly"])
    B = GFPoly.from_b64(arguments["B"], arguments["poly"])
    Q, R = A.divmod(B)
    return {"Q": Q.to_b64(), "R": R.to_b64()}

def gfpoly_gcd(arguments: dict) -> dict:
    """Berechnet den größten gemeinsamen Teiler und gibt ihn Base64-kodiert zurück."""
    A = GFPoly.from_b64(arguments["A"], arguments["poly"])
    B = GFPoly.from_b64(arguments["B"], arguments["poly"])
    G = A.gcd(B)
    return {"G": G.to_b64()}

def gfpoly_pow(arguments: dict) -> dict:
    """Potenziert ein Polynom mit Exponent e und gibt das Ergebnis Base64-kodiert zurück."""
    B = GFPoly.from_b64(arguments["B"], arguments["poly"])
    e = gf128.parse_exponent(arguments["e"])
    Z = B ** e
    return {"Z": Z.to_b64()}

def gfpoly_powmod(arguments: dict) -> dict:
    """Berechnet B^e modulo M und gibt das Ergebnis Base64-kodiert zurück."""
    B = GFPoly.from_b64(arguments["B"], arguments["poly"])
    M = GFPoly.from_b64(arguments["M"], arguments["poly"])
    e = gf128.parse_exponent(arguments["e"])
    Z = B.powmod(e, M)
    return {"Z": Z.to_b64()}

def gfpoly_diff(arguments: dict) -> dict:
    """Berechnet die Ableitung und gibt sie Base64-kodiert zurück."""
    F = GFPoly.from_b64(arguments["F"], arguments["poly"])
    dF = F.diff()
    return {"F'": dF.to_b64()}

def gfpoly_sqrt(arguments: dict) -> dict:
    """Berechnet die Quadratwurzel des Polynoms und gibt sie Base64-kodiert zurück."""
    S = GFPoly.from_b64(arguments["S"], arguments["poly"])
    R = S.sqrt()
    return {"R": R.to_b64()}

def gfpoly_factor_sff(arguments: dict) -> dict:
    """Führt Square-Free-Faktorisierung durch und gibt Faktoren mit Exponenten zurück."""
    F = GFPoly.from_b64(arguments["F"], arguments["poly"])
    factors = F.square_free_factorization()
    result = [{"factor": fac.to_b64(), "exponent": exp} for (fac, exp) in factors]
    return {"factors": result}

def gfpoly_factor_ddf(arguments: dict) -> dict:
    """Führt die Distinct-Degree-Faktorisierung durch und gibt Faktoren mit Graden zurück."""
    F = GFPoly.from_b64(arguments["F"], arguments["poly"])
    z = F.distinct_degree_factorization()
    factors = [{"factor": fac.to_b64(), "degree": d} for (fac, d) in z]
    return {"factors": factors}

def gfpoly_factor_edf(arguments: dict) -> dict:
    """Führt die Equal-Degree-Faktorisierung mit Zielgrad d durch und gibt die Faktoren zurück."""
    F = GFPoly.from_b64(arguments["F"], arguments["poly"])
    d = int(arguments["d"])
    result = F.equal_degree_factorization(d)
    factors = [fac.to_b64() for fac in result]
    return {"factors": factors}
