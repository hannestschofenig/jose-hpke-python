"""COSE Key helpers for EC2 keys."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

# COSE key parameter labels (RFC 8152)
KTY_LABEL = 1
CRV_LABEL = -1
X_LABEL = -2
Y_LABEL = -3
D_LABEL = -4

KTY_OKP = 1
KTY_EC2 = 2
CRV_P256 = 1
CRV_P384 = 2
CRV_P521 = 3
CRV_X25519 = 4
CRV_X448 = 5

SUPPORTED_EC2_CURVES = {
    "P-256": (CRV_P256, ec.SECP256R1),
    "P-384": (CRV_P384, ec.SECP384R1),
    "P-521": (CRV_P521, ec.SECP521R1),
}

COSE_CRV_TO_CURVE = {
    CRV_P256: ec.SECP256R1,
    CRV_P384: ec.SECP384R1,
    CRV_P521: ec.SECP521R1,
}

SUPPORTED_OKP_CURVES = {
    "X25519": (CRV_X25519, x25519.X25519PrivateKey),
    "X448": (CRV_X448, x448.X448PrivateKey),
}

COSE_OKP_CRV_TO_NAME = {
    CRV_X25519: "X25519",
    CRV_X448: "X448",
}


@dataclass
class CoseKeyPair:
    public_cose: Dict[int, bytes]
    private_cose: Dict[int, bytes]


def _int_to_fixed_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder="big")


def _fixed_bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, byteorder="big")


def generate_ec2_keypair(curve_name: str = "P-256") -> CoseKeyPair:
    if curve_name not in SUPPORTED_EC2_CURVES:
        raise ValueError(f"Unsupported curve: {curve_name}")
    cose_crv, curve_cls = SUPPORTED_EC2_CURVES[curve_name]
    private_key = ec.generate_private_key(curve_cls())
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    length = _curve_length_bytes(private_key.curve)
    x = _int_to_fixed_bytes(public_numbers.x, length)
    y = _int_to_fixed_bytes(public_numbers.y, length)
    d = _int_to_fixed_bytes(private_numbers.private_value, length)

    public_cose = {
        KTY_LABEL: KTY_EC2,
        CRV_LABEL: cose_crv,
        X_LABEL: x,
        Y_LABEL: y,
    }
    private_cose = {
        **public_cose,
        D_LABEL: d,
    }

    return CoseKeyPair(public_cose=public_cose, private_cose=private_cose)


def generate_p256_keypair() -> CoseKeyPair:
    return generate_ec2_keypair("P-256")


def generate_okp_keypair(curve_name: str = "X25519") -> CoseKeyPair:
    if curve_name not in SUPPORTED_OKP_CURVES:
        raise ValueError(f"Unsupported curve: {curve_name}")
    cose_crv, key_cls = SUPPORTED_OKP_CURVES[curve_name]
    private_key = key_cls.generate()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    public_cose = {
        KTY_LABEL: KTY_OKP,
        CRV_LABEL: cose_crv,
        X_LABEL: public_bytes,
    }
    private_cose = {
        **public_cose,
        D_LABEL: private_bytes,
    }

    return CoseKeyPair(public_cose=public_cose, private_cose=private_cose)


def write_cose_key(path: str, cose_key: Dict[int, bytes]) -> None:
    with open(path, "wb") as handle:
        handle.write(cbor2.dumps(cose_key))


def read_cose_key(path: str) -> Dict[int, bytes]:
    with open(path, "rb") as handle:
        return cbor2.loads(handle.read())


def cose_to_ec_public_key(cose_key: Dict[int, bytes]) -> ec.EllipticCurvePublicKey:
    curve = _validate_ec2(cose_key)
    x = _fixed_bytes_to_int(cose_key[X_LABEL])
    y = _fixed_bytes_to_int(cose_key[Y_LABEL])
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
    return public_numbers.public_key()


def cose_to_ec_private_key(cose_key: Dict[int, bytes]) -> ec.EllipticCurvePrivateKey:
    curve = _validate_ec2(cose_key)
    if D_LABEL not in cose_key:
        raise ValueError("COSE key does not include private key material")
    d = _fixed_bytes_to_int(cose_key[D_LABEL])
    x = _fixed_bytes_to_int(cose_key[X_LABEL])
    y = _fixed_bytes_to_int(cose_key[Y_LABEL])
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
    private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
    return private_numbers.private_key()


def cose_public_key_to_bytes(cose_key: Dict[int, bytes]) -> bytes:
    if cose_key.get(KTY_LABEL) == KTY_EC2:
        curve = _validate_ec2(cose_key)
        length = _curve_length_bytes(curve)
        x = _int_to_fixed_bytes(_fixed_bytes_to_int(cose_key[X_LABEL]), length)
        y = _int_to_fixed_bytes(_fixed_bytes_to_int(cose_key[Y_LABEL]), length)
        return b"\x04" + x + y
    if cose_key.get(KTY_LABEL) == KTY_OKP:
        _validate_okp(cose_key)
        return cose_key[X_LABEL]
    raise ValueError("Unsupported COSE kty")


def cose_private_key_to_bytes(cose_key: Dict[int, bytes]) -> bytes:
    if cose_key.get(KTY_LABEL) == KTY_EC2:
        curve = _validate_ec2(cose_key)
        length = _curve_length_bytes(curve)
        if D_LABEL not in cose_key:
            raise ValueError("COSE key does not include private key material")
        return _int_to_fixed_bytes(_fixed_bytes_to_int(cose_key[D_LABEL]), length)
    if cose_key.get(KTY_LABEL) == KTY_OKP:
        _validate_okp(cose_key)
        if D_LABEL not in cose_key:
            raise ValueError("COSE key does not include private key material")
        return cose_key[D_LABEL]
    raise ValueError("Unsupported COSE kty")


def ec_public_key_to_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    public_numbers = public_key.public_numbers()
    length = _curve_length_bytes(public_key.curve)
    x = _int_to_fixed_bytes(public_numbers.x, length)
    y = _int_to_fixed_bytes(public_numbers.y, length)
    return b"\x04" + x + y


def ec_private_key_to_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    length = _curve_length_bytes(private_key.curve)
    return _int_to_fixed_bytes(private_key.private_numbers().private_value, length)


def _validate_ec2(cose_key: Dict[int, bytes]) -> ec.EllipticCurve:
    if cose_key.get(KTY_LABEL) != KTY_EC2:
        raise ValueError("Unsupported COSE kty; expected EC2")
    cose_crv = cose_key.get(CRV_LABEL)
    curve_cls = COSE_CRV_TO_CURVE.get(cose_crv)
    if curve_cls is None:
        raise ValueError("Unsupported COSE curve")
    if X_LABEL not in cose_key or Y_LABEL not in cose_key:
        raise ValueError("COSE key missing x/y coordinates")
    return curve_cls()


def _curve_length_bytes(curve: ec.EllipticCurve) -> int:
    return (curve.key_size + 7) // 8


def _validate_okp(cose_key: Dict[int, bytes]) -> str:
    if cose_key.get(KTY_LABEL) != KTY_OKP:
        raise ValueError("Unsupported COSE kty; expected OKP")
    cose_crv = cose_key.get(CRV_LABEL)
    curve_name = COSE_OKP_CRV_TO_NAME.get(cose_crv)
    if curve_name is None:
        raise ValueError("Unsupported COSE OKP curve")
    if X_LABEL not in cose_key:
        raise ValueError("COSE key missing x coordinate")
    return curve_name
