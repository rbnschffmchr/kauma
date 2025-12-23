import base64
from typing import List, Tuple
from actions.gf128 import GF128
from actions.gfpoly import GFPoly
from actions.aes_gcm import split_blocks, pad_to_block, gcm_len_block, xor_bytes

BLOCK_SIZE = 16

def poly_from_block(block: bytes, poly: str) -> GFPoly:
    """
    Wandelt einen 16-Byte-Block in ein GF(2^128)-Polynom mit einem einzigen Koeffizienten um
    """
    return GFPoly([GF128.from_bytes(block, poly)], poly)

def poly_from_const(elem: GF128, poly: str) -> GFPoly:
    """
    Erzeugt ein GF(2^128)-Polynom aus einem konstanten Koeffizienten
    """
    return GFPoly([elem], poly)

def ghash_formal_poly(A: bytes, C: bytes, poly: str) -> GFPoly:
    """
    Konstruiert das formale GHASH-Polynom aus assoziierten Daten und Ciphertext gemäß GCM
    """
    X_var = GFPoly.X(poly)
    S = GFPoly.zero(poly)

    for a in split_blocks(pad_to_block(A))[0]:
        S = (S + poly_from_block(a, poly)) * X_var

    for c in split_blocks(pad_to_block(C))[0]:
        S = (S + poly_from_block(c, poly)) * X_var

    L = gcm_len_block(len(A) * 8, len(C) * 8)
    S = (S + poly_from_block(L, poly)) * X_var
    return S

def eval_poly_at(S: GFPoly, H: GF128) -> GF128:
    """
    Berechnet S(H) mittels klassischem Horner-Schema über GF(2^128)
    """
    # Klassisches Horner-schema acc = (...((a_n)*H + a_{n-1})*H + ... )*H + a_0
    acc = GF128(0, H.poly)
    coeffs = S.as_list()
    for i in range(len(coeffs) - 1, -1, -1):
        if acc.value != 0:
            acc = acc * H
        acc = GF128(acc.value ^ coeffs[i].value, acc.poly)
    return acc

def build_F(S1: GFPoly, tag1: bytes, S2: GFPoly, tag2: bytes, poly: str) -> GFPoly:
    """
    Erzeugt das Polynom F = (S1 + S2 + (T1 xor T2)) und macht es monisch
    """
    const = GF128.from_bytes(xor_bytes(tag1, tag2), poly)
    return (S1 + S2 + poly_from_const(const, poly)).monic()

def extract_linear_roots(factor: GFPoly) -> List[GF128]:
    """
    Extrahiert lineare Wurzeln (Grad 1) aus einem Polynom und normiert bei bedarf auf monisch
    """
    if factor.deg() != 1:
        return []
    c0, c1 = factor.as_list()
    if c1.value != 1:
        factor = factor.monic()
        c0, c1 = factor.as_list()
    return [c0]

def factor_and_candidates(F: GFPoly) -> List[GF128]:
    """
    Faktorisiert F via SFF/DDF/EDF und sammelt alle linearen Kandidaten für H
    """
    candidates = []
    for sqfree, _ in F.square_free_factorization():
        for prod_same_deg, d in sqfree.distinct_degree_factorization():
            if d == 1:
                for lin in prod_same_deg.equal_degree_factorization(1):
                    candidates.extend(extract_linear_roots(lin))
    return candidates

def gcm_crack(arguments: dict) -> dict:
    """
    Findet H und die Maskierung aus drei GCM-Nachrichten und erzeugt einen gültigen Tag für eine Fälschung
    """
    poly = arguments["poly"]

    def parse_msg(m: dict) -> Tuple[bytes, bytes, bytes]:
        """
        Parst eine Nachricht und gibt (A, C, T) als Bytes zurück
        """
        A = base64.b64decode(m["associated_data"]) if m.get("associated_data") else b""
        C = base64.b64decode(m["ciphertext"])
        T = base64.b64decode(m["tag"])
        return A, C, T

    A1, C1, T1 = parse_msg(arguments["m1"])
    A2, C2, T2 = parse_msg(arguments["m2"])
    A3, C3, T3 = parse_msg(arguments["m3"])

    S1_poly = ghash_formal_poly(A1, C1, poly)
    S2_poly = ghash_formal_poly(A2, C2, poly)
    S3_poly = ghash_formal_poly(A3, C3, poly)

    F_1_2 = build_F(S1_poly, T1, S2_poly, T2, poly)
    F_1_3 = build_F(S1_poly, T1, S3_poly, T3, poly)

    # GCD Berechnung
    G = F_1_2.gcd(F_1_3)
    if not G.is_one():
        H_candidates = factor_and_candidates(G)
    else:
        # Fallback, prüfe F_1_2 zuerst, dann F_1_3
        H_candidates = factor_and_candidates(F_1_2)
        if not H_candidates:
            H_candidates = factor_and_candidates(F_1_3)

    H_ok = None
    E0_ok = None
    for H_candidate in H_candidates:
        # Validiert einen H-Kandidaten mittels Tags und speichert bei Erfolg H und Maske E0
        S1_val = eval_poly_at(S1_poly, H_candidate)
        E0_bytes = xor_bytes(T1, S1_val.to_bytes())
        E0_elem = GF128.from_bytes(E0_bytes, poly)

        S3_val = eval_poly_at(S3_poly, H_candidate)
        if xor_bytes(E0_bytes, S3_val.to_bytes()) == T3:
            H_ok = H_candidate
            E0_ok = E0_elem
            break

    forgery = arguments["forgery"]
    Cfg = base64.b64decode(forgery["ciphertext"])
    Afg = base64.b64decode(forgery["associated_data"]) if forgery.get("associated_data") else b""

    Sfg_poly = ghash_formal_poly(Afg, Cfg, poly)
    Sfg_val = eval_poly_at(Sfg_poly, H_ok)
    tag_forg = xor_bytes(E0_ok.to_bytes(), Sfg_val.to_bytes())

    return {"tag": base64.b64encode(tag_forg).decode("ascii"), "H": H_ok.to_b64(), "mask": E0_ok.to_b64()}