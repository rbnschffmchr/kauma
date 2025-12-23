def parse_to_int(value, name):
    """
    Konvertiert einen Integer oder String in einen Integer und validiert Eingaben.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except Exception:
            raise ValueError(f"Invalid number format for {name}: {value}")
    raise ValueError(f"Missing argument {name}")

def divide_trunc_toward_zero(a, b):
    """
    Führt eine ganzzahlige Division mit Rundung in Richtung Null durch.
    """
    quotient, remainder = divmod(a, b)
    different_sign = (a < 0) != (b < 0)
    has_remainder = remainder != 0
    if different_sign and has_remainder:
        return quotient + 1
    return quotient

def calc(arguments):
    """
    Berechnet lhs op rhs und gibt je nach Größenordnung ein Integer oder eine Hex-Darstellung zurück.
    """
    try:
        lhs = parse_to_int(arguments.get("lhs"), "lhs")
        rhs = parse_to_int(arguments.get("rhs"), "rhs")
        op = arguments["op"]

        if isinstance(op, str):
            op = op.strip()

        if op is None:
            raise ValueError ("Missing operator")
        elif op not in ["+", "-", "*", "/"]:
            raise ValueError (f"Invalid operator {op}")

        result = 0
        if op == "+":
            result = lhs + rhs
        elif op == "-":
            result = lhs - rhs
        elif op == "*":
            result = lhs * rhs
        elif op == "/":
            result = divide_trunc_toward_zero(lhs, rhs)

        # Falls die Zahl außerhalb von 32 Bit ist
        if result not in range(-(2 ** 31), 2 ** 31):
            return {"answer": hex(result)}
        return {"answer": result}
    except Exception as e:
        return {"error": str(e)}