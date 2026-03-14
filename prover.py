"""
prover.py  —  Prover Machine (Machine A)
=========================================
This program:
  1. Generates or loads an elliptic-curve identity (secret + public key)
  2. Creates a Schnorr zero-knowledge proof for a given message
  3. Writes proof.json  —  sent to the Verifier (Machine B)

The SECRET KEY never leaves this machine.
The proof file contains only:  public_key, message, R, s

Usage
-----
    # Generate a fresh identity and prove a message:
    python prover.py --message "medical_record_abc123"

    # Prove with a previously saved identity:
    python prover.py --message "ballot_hash_xyz" --identity my_identity.json

    # Use a raw hex message (e.g. a document hash):
    python prover.py --message-hex a3f1...

    # Choose output file:
    python prover.py --message "test" --out hospital_proof.json

Requires only the standard library + cryptography (for AES — unused here,
but kept so both files share the same single dependency).
"""

import argparse
import json
import os
import secrets
import sys

from schnorr_core import (
    G, N,
    ec_mul,
    compute_challenge,
    point_to_hex, point_from_hex,
    proof_to_dict,
    validate_point,
    schnorr_verify,         
)




def keygen() -> dict:
    x = secrets.randbelow(N - 1) + 1
    P = ec_mul(x, G)
    validate_point(P)
    return {"secret_key": x, "public_key": P}


def save_identity(identity: dict, path: str):
    
    data = {
        "secret_key": hex(identity["secret_key"]),
        "public_key": point_to_hex(identity["public_key"]),
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[prover] Identity сохранён → {path}  (не распространяй его!)")


def load_identity(path: str) -> dict:
    
    with open(path) as f:
        data = json.load(f)
    return {
        "secret_key": int(data["secret_key"], 16),
        "public_key": point_from_hex(data["public_key"]),
    }




def schnorr_prove(secret_key: int,
                  public_key: tuple,
                  message:    bytes):
    r = secrets.randbelow(N - 1) + 1
    R = ec_mul(r, G)
    c = compute_challenge(R, public_key, message)
    s = (r + c * secret_key) % N
    return R, s




def build_proof(identity: dict, message: bytes) -> dict:
    sk = identity["secret_key"]
    pk = identity["public_key"]

    R, s = schnorr_prove(sk, pk, message)

    proof = {
        "public_key": point_to_hex(pk),
        "message":    message.hex(),
        "proof":      proof_to_dict(R, s),
        "_note": " prover.py. нет секретного ключа.",
    }
    return proof


def self_check(proof_data: dict) -> bool:
    from schnorr_core import proof_from_dict, point_from_hex
    pk = point_from_hex(proof_data["public_key"])
    msg = bytes.fromhex(proof_data["message"])
    R, s = proof_from_dict(proof_data["proof"])
    return schnorr_verify(pk, msg, R, s)



def parse_args():
    p = argparse.ArgumentParser(
        description="записывает proof.json"
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--message",
                   help="UTF-8 ")
    g.add_argument("--message-hex",
                   help="hex")
    p.add_argument("--identity",     default="identity.json",
                   help="путь для созранения (default: identity.json)")
    p.add_argument("--out",          default="proof.json",
                   help="название файла proof (default: proof.json)")
    p.add_argument("--new-identity", action="store_true",
                   help="принудительное создание новых ключей")
    return p.parse_args()


def main():
    args = parse_args()

    # Resolve message bytes
    if args.message:
        message = args.message.encode()
    else:
        message = bytes.fromhex(args.message_hex)

    # Load or generate identity
    if args.new_identity or not os.path.exists(args.identity):
        print("[prover] генерация identify")
        identity = keygen()
        save_identity(identity, args.identity)
    else:
        identity = load_identity(args.identity)
        print(f"[prover] загрузка {args.identity}")

    pk_hex = point_to_hex(identity["public_key"])
    print(f"[prover] Public key : {pk_hex[:20]}…{pk_hex[-8:]}")
    print(f"[prover] Message    : {message[:60]!r}")

    # Generate proof
    proof_data = build_proof(identity, message)

    # Self-check
    ok = self_check(proof_data)
    if not ok:
        print("[prover]  Self-check FAILED  proof не сохранён", file=sys.stderr)
        sys.exit(1)
    print("[prover] Self-check OK")

    # Write proof.json
    with open(args.out, "w") as f:
        json.dump(proof_data, f, indent=2)
    print(f"[prover] proof сохранён → {args.out}")
    print()
    print(f"Send  {args.out:<33}")
    print("в Machine B (verifier.py)")
    print("не пересылай identity.json")


if __name__ == "__main__":
    main()
