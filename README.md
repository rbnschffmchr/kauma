# kauma

kauma is a command-line tool that reads cryptanalysis assignments from JSON and produces a JSON reply per test case. It was developed for the course "Cryptanalysis and Methods Audit" and is intended strictly for educational and research use.

## Contents and Capabilities

The tool implements tasks aligned with the course material:

- Finite field arithmetic over GF(2^128)
- Polynomial arithmetic with coefficients in GF(2^128)
- AES-GCM implementation and attack scenarios (nonce reuse)
- Batch-GCD based RSA factorization

## Project Structure

- kauma.py - CLI entrypoint
- actions/
  - calc.py - integer arithmetic to validate JSON datatype conventions
  - padding_oracle/
    - server_connection.py - binary client/server protocol for the padding oracle assignment
    - padding_oracle.py - PKCS#7 CBC padding oracle attack
    - aes_gcm.py - GCM utilities (e.g., GHASH)
  - gf128.py - GF(2^128) arithmetic (mul, divmod, inverse, division, power, sqrt)
  - gfpoly.py - polynomials over GF(2^128) (sort, monic, add/mul/divmod, gcd, pow/powmod, diff/sqrt, SFF/DDF/EDF factorization)
  - gcm_crack.py - key recovery under nonce reuse; producing valid tags for a forgery
  - rsa_factor.py - Batch-GCD factoring of weak RSA moduli
- tests/ - local tests
- runtestwithfeedback.py - helper for local test runs with feedback

## Installation and Execution

- Requirements: Python 3.x, cryptography package
- Run convention:
  - Invocation: ./kauma <file.json>
  - Output: One JSON line per testcase on stdout, no diagnostic output on stdout.

## Supported Actions

- calc - basic integer arithmetic to validate JSON datatype conventions.
- padding_oracle - implements the specified binary protocol and CBC padding oracle attack.
- GF(2^128): gf_mul, gf_divmod, gf_inv, gf_div, gf_pow, gf_sqrt.
- AES-GCM: gcm_encrypt - self-implemented AES128-GCM (no direct library GCM), returns ciphertext, tag, GHASH key H, and length field L.
- Polynomials over GF(2^128):
  - gfpoly_sort, gfpoly_monic, gfpoly_add, gfpoly_mul, gfpoly_divmod, gfpoly_gcd, gfpoly_pow, gfpoly_powmod, gfpoly_diff, gfpoly_sqrt.
  - Factorization:
    - gfpoly_factor_sff - square-free factorization
    - gfpoly_factor_ddf - distinct degree factorization
    - gfpoly_factor_edf - Cantor-Zassenhaus equal degree factorization
- GCM Key Recovery: gcm_crack - reconstruct H and EK(Y0) under nonce reuse, verify against a third message and produce a valid tag for the forgery.
- rsa_factor - efficient Batch-GCD factoring of 2-prime RSA moduli with shared factors.

## Input/Output

- Input: JSON file with testcases, each testcase contains action and arguments.
- Output: One line of JSON per testcase on stdout: { "id": "<id>", "reply": { ... } }.

## Security and Disclaimer

- This project is intended strictly for educational and research purposes within the course context.
- Do not use these implementations against systems or data without explicit permission.
- Attacks such as padding oracle, GCM key recovery, and RSA factorization must only be performed in controlled and legally permitted environments.
- The author and institution accept no liability for misuse.
