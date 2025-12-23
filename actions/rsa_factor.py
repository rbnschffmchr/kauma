from gmpy2 import mpz, gcd, f_mod

def parse_to_int(exponent):
    """
    Konvertiert einen Integer oder String in einen Integer.
    """
    if isinstance(exponent, int):
        return exponent
    if isinstance(exponent, str):
        return int(exponent, 0)

def to_32bit_or_hex(x: int):
    """
    Gibt x zurück, wenn es in 32 Bit passt, sonst die Hex-Darstellung.
    """
    if x in range(-(2 ** 31), 2 ** 31):
        return x
    return hex(x)

def build_product_tree(leaves):
    """
    Erzeugt einen Produktbaum aus den Blättern und gibt die Ebenen von unten nach oben zurück.
    """
    if not leaves:
        return []
    level = [mpz(x) for x in leaves]
    levels = [level]
    # baue Ebenen: paarweise Produkte, letzter einsam bleibt stehen
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                nxt.append(cur[i] * cur[i + 1])
            else:
                nxt.append(cur[i])
        levels.append(nxt)
    return levels

def compute_leaf_remainders_mod_n_sq(levels):
    """
    Top-down Reduktion: liefert z_i = P mod n_i^2 für jedes Blatt i.
    levels[0] sind die Blätter (n_i), levels[-1][0] ist das Wurzelprodukt P.
    """
    if not levels or not levels[0]:
        return []

    # current enthält die Werte der Eltern auf der aktuellen Ebene (start: Wurzelprodukte)
    current = [val for val in levels[-1]]

    # von oben nach unten: pro Knoten Rest modulo n_i^2 berechnen
    for lvl in range(len(levels) - 2, -1, -1):
        parents = current
        nodes = levels[lvl]  # Produkte auf dieser Ebene (bei lvl=0 sind das die n_i)
        next_values = [mpz(0)] * len(nodes)
        for idx, node_val in enumerate(nodes):
            P = parents[idx // 2]           # Elternprodukt
            n_square = node_val ** 2        # n_i^2
            next_values[idx] = f_mod(P, n_square)  # z_i = P mod n_i^2
        current = next_values
    return current

def batch_gcd_shared_factors(moduli):
    """
    Findet gemeinsame Primfaktoren per Batch-GCD mit Fallback bei Grenzfällen.
    """
    if not moduli:
        return []

    mods_mpz = [mpz(x) for x in moduli]
    levels = build_product_tree(mods_mpz)
    z_i_list = compute_leaf_remainders_mod_n_sq(levels)

    result_pairs = []
    unresolved_indices = []

    # 1) Normalfall, gcd liefert gemeinsamen Primfaktor
    for i, (n_i, z_i) in enumerate(zip(mods_mpz, z_i_list)):
        g = gcd(z_i // n_i, n_i)
        if g > 1 and g < n_i:
            p = int(g)
            q = int(n_i // g)
            if p > q:
                p, q = q, p
            result_pairs.append((p, q))
        elif g == n_i:
            unresolved_indices.append(i)

    # 2) Fallback: paarweise GCDs für nicht aufgelöste moduli
    if unresolved_indices:
        for idx_i in unresolved_indices:
            n_i = mods_mpz[idx_i]
            for idx_j, n_j in enumerate(mods_mpz):
                if idx_j == idx_i:
                    continue
                g = gcd(n_i, n_j)
                if g > 1 and g < n_i:
                    p = int(g)
                    q = int(n_i // g)
                    if p > q:
                        p, q = q, p
                    result_pairs.append((p, q))
                    break

    # Deduplizieren und sortieren
    result_pairs = sorted(set(result_pairs), key=lambda t: (t[0], t[1]))
    return result_pairs

def rsa_factor(arguments):
    raw_moduli = arguments["moduli"]

    moduli_parsed = []
    for idx, m in enumerate(raw_moduli):
        moduli_parsed.append(parse_to_int(m))

    # Faktorisieren
    pairs = batch_gcd_shared_factors(moduli_parsed)

    factored_out = []
    for p, q in pairs:
        p_out = to_32bit_or_hex(p)
        q_out = to_32bit_or_hex(q)
        factored_out.append([p_out, q_out])

    return {"factored_moduli": factored_out}