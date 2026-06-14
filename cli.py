"""CLI entrypoint for JOSE-HPKE (draft-ietf-jose-hpke-encrypt-15)."""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from . import cose
from .jose_hpke import DEFAULT_INFO, HPKE_ALG_SUITES, jwe_decrypt, jwe_encrypt


def _read_input(path: Optional[str]) -> bytes:
    if path:
        with open(path, "rb") as handle:
            return handle.read()
    return sys.stdin.buffer.read()


def _write_output(path: Optional[str], data: bytes) -> None:
    if path:
        with open(path, "wb") as handle:
            handle.write(data)
        return
    sys.stdout.buffer.write(data)


def _read_optional_file(path: Optional[str]) -> Optional[bytes]:
    if not path:
        return None
    with open(path, "rb") as handle:
        return handle.read()


def cmd_gen_keys(args: argparse.Namespace) -> int:
    curve = args.curve
    if curve.startswith("X"):
        keypair = cose.generate_okp_keypair(curve)
    else:
        keypair = cose.generate_ec2_keypair(curve)
    pub_path = args.public_key or f"{args.out_prefix}.pub.cose"
    priv_path = args.private_key or f"{args.out_prefix}.priv.cose"

    cose.write_cose_key(pub_path, keypair.public_cose)
    cose.write_cose_key(priv_path, keypair.private_cose)
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    public_cose = cose.read_cose_key(args.public_key)
    plaintext = _read_input(args.input)
    info = _read_optional_file(args.info_file)
    aad = _read_optional_file(args.aad_file)

    payload = jwe_encrypt(
        plaintext,
        public_cose,
        alg=args.alg,
        content_enc=args.enc,
        aad=aad,
        info=DEFAULT_INFO if info is None else info,
        kid=args.kid,
        serialization=args.serialization,
    )
    _write_output(args.output, payload.encode("utf-8"))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    private_cose = cose.read_cose_key(args.private_key)
    data = _read_input(args.input)
    info = _read_optional_file(args.info_file)
    aad = _read_optional_file(args.aad_file)

    plaintext = jwe_decrypt(
        data.decode("utf-8"),
        private_cose,
        aad=aad,
        info=DEFAULT_INFO if info is None else info,
    )
    _write_output(args.output, plaintext)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jose-hpke", description="JOSE-HPKE CLI tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen_parser = subparsers.add_parser("gen-keys", help="Generate COSE keys")
    gen_parser.add_argument("--out-prefix", default="hpke", help="Output prefix for key files")
    gen_parser.add_argument(
        "--curve",
        default="P-256",
        choices=["P-256", "P-384", "P-521", "X25519", "X448"],
        help="Curve for generated keys",
    )
    gen_parser.add_argument("--public-key", help="Optional public key output path")
    gen_parser.add_argument("--private-key", help="Optional private key output path")
    gen_parser.set_defaults(func=cmd_gen_keys)

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt data")
    enc_parser.add_argument("--pub-key", dest="public_key", required=True, help="Recipient public COSE key")
    enc_parser.add_argument(
        "--alg",
        required=True,
        choices=sorted(HPKE_ALG_SUITES.keys()),
        help="HPKE JWE alg",
    )
    enc_parser.add_argument(
        "--enc",
        choices=["A128GCM", "A192GCM", "A256GCM"],
        help="Content encryption (required for *-KE algs)",
    )
    enc_parser.add_argument(
        "--serialization",
        choices=["compact", "flattened", "general"],
        default="flattened",
        help="JWE serialization",
    )
    enc_parser.add_argument("--kid", help="Key ID to include in header")
    enc_parser.add_argument("--aad-file", help="Additional authenticated data file")
    enc_parser.add_argument("--info-file", help="HPKE info file")
    enc_parser.add_argument("--in", dest="input", help="Input file (default: stdin)")
    enc_parser.add_argument("--out", dest="output", help="Output file (default: stdout)")
    enc_parser.set_defaults(func=cmd_encrypt)

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt data")
    dec_parser.add_argument("--priv-key", dest="private_key", required=True, help="Recipient private COSE key")
    dec_parser.add_argument("--aad-file", help="Additional authenticated data file")
    dec_parser.add_argument("--info-file", help="HPKE info file")
    dec_parser.add_argument("--in", dest="input", help="Input file (default: stdin)")
    dec_parser.add_argument("--out", dest="output", help="Output file (default: stdout)")
    dec_parser.set_defaults(func=cmd_decrypt)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
