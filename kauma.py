#!/usr/bin/env python3

import json
import sys

from actions import calc
from actions.padding_oracle import padding_oracle
from actions import gf128
from actions import aes_gcm
from actions import gfpoly
from actions import gcm_crack
from actions import rsa_factor

def dispatch_action(action, arguments, action_lut):
    """
    Mapped die action auf die korrespondierende Funktion.
    """
    mapped_action = action_lut.get(action)
    if mapped_action is None:
        return {"error": "Unknown action"}
    try:
        return mapped_action(arguments)
    except Exception as e:
        return {"error": f"Action failed: {e}"}


def main():
    """
    Liest eine JSON-Datei ein, interpretiert die action und die arguments
    und gibt als Ergebnis eine JSON im Einzeilenformat aus.
    """
    action_lut = {
        "calc": calc.calc,
        "padding_oracle": padding_oracle.start_attack,
        "gf_mul": gf128.gf_mul,
        "gf_divmod": gf128.gf_divmod,
        "gf_inv": gf128.gf_inv,
        "gf_div": gf128.gf_div,
        "gf_pow": gf128.gf_pow,
        "gf_sqrt": gf128.gf_sqrt,
        "gcm_encrypt": aes_gcm.gcm_encrypt,
        "gfpoly_sort": gfpoly.gfpoly_sort,
        "gfpoly_monic": gfpoly.gfpoly_monic,
        "gfpoly_add": gfpoly.gfpoly_add,
        "gfpoly_mul": gfpoly.gfpoly_mul,
        "gfpoly_divmod": gfpoly.gfpoly_divmod,
        "gfpoly_gcd": gfpoly.gfpoly_gcd,
        "gfpoly_pow": gfpoly.gfpoly_pow,
        "gfpoly_powmod": gfpoly.gfpoly_powmod,
        "gfpoly_diff": gfpoly.gfpoly_diff,
        "gfpoly_sqrt": gfpoly.gfpoly_sqrt,
        "gfpoly_factor_sff": gfpoly.gfpoly_factor_sff,
        "gfpoly_factor_ddf": gfpoly.gfpoly_factor_ddf,
        "gfpoly_factor_edf": gfpoly.gfpoly_factor_edf,
        "gcm_crack": gcm_crack.gcm_crack,
        "rsa_factor": rsa_factor.rsa_factor,
    }

    if len(sys.argv) != 2:
        print(f"Syntax: python3 {sys.argv[0]} <json_filename>", file=sys.stderr)
        sys.exit(1)
    json_testcase = sys.argv[1]

    try:
        with open(json_testcase, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"File {json_testcase} not found", file=sys.stderr)
        sys.exit(1)
    except json.decoder.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Überprüfe, ob mehrere testcases vorhanden sind
    if "testcases" in data:
        testcases = data["testcases"]
        for uuid, content in testcases.items():
            action = content["action"]
            arguments = content["arguments"]
            response = dispatch_action(action, arguments, action_lut)
            print(json.dumps({"id": uuid, "reply": response}))
    else:
        for uuid, content in data.items():
            action = content["action"]
            arguments = content["arguments"]
            response = dispatch_action(action, arguments, action_lut)
            print(json.dumps({"id": uuid, "reply": response}))

if __name__ == '__main__':
    main()