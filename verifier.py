import argparse
import json
import sys
import time
from schnorr_core import (
    schnorr_verify,
    point_from_hex,
    proof_from_dict,
    validate_point,
    InvalidPointError,
    N,
)

class ProofLoadError(Exception):
    pass


def load_proof(path: str) -> dict:
    
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ProofLoadError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise ProofLoadError(f"Invalid JSON in {path}: {e}")

    for key in ("public_key", "message", "proof"):
        if key not in data:
            raise ProofLoadError(f"Missing field '{key}' in {path}")

    for key in ("R", "s"):
        if key not in data["proof"]:
            raise ProofLoadError(f"Missing proof field '{key}' in {path}")

    
    try:
        pk = point_from_hex(data["public_key"])
        validate_point(pk)
    except (ValueError, InvalidPointError) as e:
        raise ProofLoadError(f"Invalid public_key: {e}")

    try:
        message = bytes.fromhex(data["message"])
    except ValueError as e:
        raise ProofLoadError(f"Invalid message hex: {e}")

    # Decode R and s
    try:
        R, s = proof_from_dict(data["proof"])
        validate_point(R)
    except (ValueError, InvalidPointError) as e:
        raise ProofLoadError(f"Invalid proof.R: {e}")

    if not (1 <= s <= N - 1):
        raise ProofLoadError(f"scalar s is out of range [1, N-1]")

    return {"public_key": pk, "message": message, "R": R, "s": s,
            "raw": data}



def verify_proof_file(path: str, verbose: bool = False) -> bool:
    try:
        proof = load_proof(path)
    except ProofLoadError as e:
        print(f"[verifier] {path}  —  LOAD ERROR: {e}")
        return False

    if verbose:
        pk = proof["public_key"]
        pk_hex = proof["raw"]["public_key"]
        print(f"  Public key : {pk_hex[:20]}…{pk_hex[-8:]}")
        msg_display = proof["message"][:60]
        try:
            msg_display = proof["message"].decode()[:60]
        except Exception:
            msg_display = proof["raw"]["message"][:60]
        print(f"  Message    : {msg_display!r}")
        Rx, Ry = proof["R"]
        print(f"  R.x        : {Rx:064x}"[:74] + "…")
        print(f"  s          : {proof['s']:064x}"[:74] + "…")

    t0    = time.perf_counter()
    valid = schnorr_verify(
        public_key = proof["public_key"],
        message    = proof["message"],
        R          = proof["R"],
        s          = proof["s"],
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000

    status = "proof VALID" if valid else "you INVALID"
    print(f"[verifier] {status:<12}  {path}  ({elapsed_ms:.1f} ms)")
    return valid



def parse_args():
    p = argparse.ArgumentParser(
        description="Schnorr Verifier — checks proof.json from the Prover machine"
    )
    p.add_argument("--proof", nargs="+", default=["proof.json"],
                   metavar="FILE",
                   help="One or more proof JSON files to verify (default: proof.json)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print proof field details before verifying")
    return p.parse_args()


def main():
    args = parse_args()

    print("Schnorr Verifier — secp256k1 / SHA-256 / Fiat-Shamir")
    print("No secret key required on this machine.")
    print()

    results = []
    for path in args.proof:
        if args.verbose:
            print(f"  ── {path} ──")
        ok = verify_proof_file(path, verbose=args.verbose)
        results.append(ok)
        if args.verbose:
            print()

    
    if len(results) > 1:
        passed = sum(results)
        total  = len(results)
        print()
        print(f"Summary: {passed}/{total} proofs valid")

    
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
