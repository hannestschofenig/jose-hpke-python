"""Compatibility shim for pyhpke API differences."""

from __future__ import annotations

import importlib
from typing import Any


def load_hpke_module() -> Any:
    try:
        return importlib.import_module("hpke")
    except ModuleNotFoundError:
        return importlib.import_module("pyhpke")


def resolve_ids(hpke: Any) -> tuple[Any, Any, Any]:
    kem = _resolve_enum_value(
        hpke,
        ["KEM", "KEM_ID", "KEMId"],
        "DHKEM_P256_HKDF_SHA256",
    )
    kdf = _resolve_enum_value(
        hpke,
        ["KDF", "KDF_ID", "KDFId"],
        "HKDF_SHA256",
    )
    aead = _try_resolve_enum_value(
        hpke,
        ["AEAD", "AEAD_ID", "AEADId"],
        "AES_256_GCM",
    )
    if aead is None:
        aead = _resolve_enum_value(
            hpke,
            ["AEAD", "AEAD_ID", "AEADId"],
            "AES256_GCM",
        )
    return kem, kdf, aead


def make_suite(hpke: Any, kem_id: Any, kdf_id: Any, aead_id: Any) -> Any:
    if hasattr(hpke, "HPKE"):
        return hpke.HPKE(kem_id, kdf_id, aead_id)
    if hasattr(hpke, "HpkeSuite"):
        suite_cls = hpke.HpkeSuite
        if hasattr(suite_cls, "new"):
            return suite_cls.new(kem_id, kdf_id, aead_id)
        return suite_cls(kem_id, kdf_id, aead_id)
    if hasattr(hpke, "CipherSuite"):
        suite_cls = hpke.CipherSuite
        if hasattr(suite_cls, "new"):
            return suite_cls.new(kem_id, kdf_id, aead_id)
        return suite_cls(kem_id, kdf_id, aead_id)
    raise RuntimeError("Unsupported pyhpke API: no suite class found")


def prepare_public_key(suite: Any, public_key_bytes: bytes) -> Any:
    kem = getattr(suite, "kem", None)
    if kem is not None and hasattr(kem, "deserialize_public_key"):
        return kem.deserialize_public_key(public_key_bytes)
    return public_key_bytes


def prepare_private_key(suite: Any, private_key_bytes: bytes) -> Any:
    kem = getattr(suite, "kem", None)
    if kem is not None and hasattr(kem, "deserialize_private_key"):
        return kem.deserialize_private_key(private_key_bytes)
    return private_key_bytes


def suite_seal(suite: Any, recipient_public: Any, info: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    if hasattr(suite, "seal"):
        try:
            return suite.seal(recipient_public, plaintext, info, aad)
        except NotImplementedError:
            pass
    if hasattr(suite, "create_sender_context"):
        enc, ctx = suite.create_sender_context(recipient_public, info)
        return enc, ctx.seal(plaintext, aad)
    raise RuntimeError("Unsupported HPKE suite: cannot seal")


def suite_open(
    suite: Any,
    enc: bytes,
    recipient_private: Any,
    info: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    if hasattr(suite, "open"):
        try:
            return suite.open(enc, recipient_private, ciphertext, info, aad)
        except NotImplementedError:
            pass
    if hasattr(suite, "create_recipient_context"):
        ctx = suite.create_recipient_context(enc, recipient_private, info)
        return ctx.open(ciphertext, aad)
    raise RuntimeError("Unsupported HPKE suite: cannot open")


def _resolve_enum_value(hpke: Any, enum_names: list[str], value_name: str) -> Any:
    resolved = _try_resolve_enum_value(hpke, enum_names, value_name)
    if resolved is None:
        raise RuntimeError(f"Unsupported pyhpke API: missing {value_name}")
    return resolved


def _try_resolve_enum_value(hpke: Any, enum_names: list[str], value_name: str) -> Any | None:
    for enum_name in enum_names:
        enum = getattr(hpke, enum_name, None)
        if enum is None:
            continue
        if hasattr(enum, value_name):
            return getattr(enum, value_name)
    return None
