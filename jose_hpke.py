"""JOSE-HPKE JWE helpers (draft-ietf-jose-hpke-encrypt-15)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from jose import jwe, jwk
from jose.utils import base64url_decode, base64url_encode

from . import cose
from .hpke_compat import (
    load_hpke_module,
    make_suite,
    prepare_private_key,
    prepare_public_key,
    suite_open,
    suite_seal,
)

DEFAULT_INFO = b""
CONTENT_KEY_SIZES = {
    "A128GCM": 16,
    "A192GCM": 24,
    "A256GCM": 32,
}

HPKE_ALG_SUITES = {
    "HPKE-0": ("DHKEM_P256_HKDF_SHA256", "HKDF_SHA256", "AES128_GCM"),
    "HPKE-1": ("DHKEM_P384_HKDF_SHA384", "HKDF_SHA384", "AES256_GCM"),
    "HPKE-2": ("DHKEM_P521_HKDF_SHA512", "HKDF_SHA512", "AES256_GCM"),
    "HPKE-3": ("DHKEM_X25519_HKDF_SHA256", "HKDF_SHA256", "AES128_GCM"),
    "HPKE-4": ("DHKEM_X25519_HKDF_SHA256", "HKDF_SHA256", "CHACHA20_POLY1305"),
    "HPKE-5": ("DHKEM_X448_HKDF_SHA512", "HKDF_SHA512", "AES256_GCM"),
    "HPKE-6": ("DHKEM_X448_HKDF_SHA512", "HKDF_SHA512", "CHACHA20_POLY1305"),
    "HPKE-7": ("DHKEM_P256_HKDF_SHA256", "HKDF_SHA256", "AES256_GCM"),
    "HPKE-0-KE": ("DHKEM_P256_HKDF_SHA256", "HKDF_SHA256", "AES128_GCM"),
    "HPKE-1-KE": ("DHKEM_P384_HKDF_SHA384", "HKDF_SHA384", "AES256_GCM"),
    "HPKE-2-KE": ("DHKEM_P521_HKDF_SHA512", "HKDF_SHA512", "AES256_GCM"),
    "HPKE-3-KE": ("DHKEM_X25519_HKDF_SHA256", "HKDF_SHA256", "AES128_GCM"),
    "HPKE-4-KE": ("DHKEM_X25519_HKDF_SHA256", "HKDF_SHA256", "CHACHA20_POLY1305"),
    "HPKE-5-KE": ("DHKEM_X448_HKDF_SHA512", "HKDF_SHA512", "AES256_GCM"),
    "HPKE-6-KE": ("DHKEM_X448_HKDF_SHA512", "HKDF_SHA512", "CHACHA20_POLY1305"),
    "HPKE-7-KE": ("DHKEM_P256_HKDF_SHA256", "HKDF_SHA256", "AES256_GCM"),
}


@dataclass
class JweParts:
    protected_b64: str
    encrypted_key_b64: str
    iv_b64: str
    ciphertext_b64: str
    tag_b64: str
    aad_b64: Optional[str]
    header: Optional[Dict[str, Any]]
    recipients: Optional[list[Dict[str, Any]]]


def jwe_encrypt(
    plaintext: bytes,
    recipient_public_cose: Dict[int, bytes],
    alg: str,
    content_enc: Optional[str] = None,
    aad: Optional[bytes] = None,
    info: Optional[bytes] = None,
    kid: Optional[str] = None,
    serialization: str = "flattened",
) -> str:
    mode = _alg_mode(alg)
    if serialization not in {"compact", "flattened", "general"}:
        raise ValueError("Unsupported serialization")
    if serialization == "compact" and aad is not None:
        raise ValueError("Compact serialization does not support AAD")
    if mode == "integrated" and content_enc is not None:
        raise ValueError("Integrated Encryption MUST NOT set enc")

    if mode == "integrated":
        jwe = _encrypt_integrated(
            plaintext,
            recipient_public_cose,
            alg,
            aad=aad,
            info=info or DEFAULT_INFO,
            kid=kid,
            serialization=serialization,
        )
    else:
        if content_enc is None:
            raise ValueError("Key Encryption requires content_enc")
        jwe = _encrypt_key_encryption(
            plaintext,
            recipient_public_cose,
            alg,
            content_enc,
            aad=aad,
            info=info,
            kid=kid,
            serialization=serialization,
        )

    if serialization == "compact":
        return _serialize_compact(jwe)
    return json.dumps(jwe, separators=(",", ":"))


def jwe_decrypt(
    serialized: str,
    recipient_private_cose: Dict[int, bytes],
    aad: Optional[bytes] = None,
    info: Optional[bytes] = None,
) -> bytes:
    if _looks_like_compact(serialized):
        parts = _parse_compact(serialized)
        protected = _decode_protected(parts.protected_b64)
    else:
        parts = _parse_json(serialized)
        protected = _decode_protected(parts.protected_b64)

    aad_b64 = parts.aad_b64
    if aad is not None:
        aad_b64 = _b64(aad)
    combined_aad = _combine_aad(parts.protected_b64, aad_b64)

    alg = protected.get("alg")
    header = parts.header or {}
    recipients = parts.recipients or []
    if alg is None and recipients:
        alg = recipients[0].get("header", {}).get("alg")
    if alg is None and header:
        alg = header.get("alg")
    if alg is None:
        raise ValueError("Missing alg")

    mode = _alg_mode(alg)
    if mode == "integrated":
        if "enc" in protected:
            raise ValueError("enc MUST NOT be present for Integrated Encryption")
        return _decrypt_integrated(
            parts,
            recipient_private_cose,
            alg,
            combined_aad,
            info or DEFAULT_INFO,
        )

    enc = protected.get("enc")
    if enc is None:
        raise ValueError("enc is required for Key Encryption")
    return _decrypt_key_encryption(
        parts,
        recipient_private_cose,
        alg,
        enc,
        combined_aad,
        info,
        protected,
    )


def _encrypt_integrated(
    plaintext: bytes,
    recipient_public_cose: Dict[int, bytes],
    alg: str,
    aad: Optional[bytes],
    info: bytes,
    kid: Optional[str],
    serialization: str,
) -> Dict[str, Any]:
    protected = {"alg": alg}
    if kid:
        protected["kid"] = kid
    protected_b64 = _encode_protected(protected)
    aad_b64 = _b64(aad) if aad is not None else None
    combined_aad = _combine_aad(protected_b64, aad_b64)

    suite = _suite_from_alg(alg)
    public_key_bytes = cose.cose_public_key_to_bytes(recipient_public_cose)
    recipient_public = prepare_public_key(suite, public_key_bytes)

    enc, ciphertext = suite_seal(suite, recipient_public, info, combined_aad, plaintext)

    return _build_jwe_json(
        protected_b64,
        enc,
        ciphertext,
        iv=b"",
        tag=b"",
        aad_b64=aad_b64,
        header=None,
        recipients=None,
        serialization=serialization,
    )


def _encrypt_key_encryption(
    plaintext: bytes,
    recipient_public_cose: Dict[int, bytes],
    alg: str,
    content_enc: str,
    aad: Optional[bytes],
    info: Optional[bytes],
    kid: Optional[str],
    serialization: str,
) -> Dict[str, Any]:
    if content_enc not in CONTENT_KEY_SIZES:
        raise ValueError("Unsupported content encryption algorithm")

    suite = _suite_from_alg(alg)
    cek = os.urandom(CONTENT_KEY_SIZES[content_enc])
    recipient_structure = _recipient_structure(content_enc, info or b"")

    public_key_bytes = cose.cose_public_key_to_bytes(recipient_public_cose)
    recipient_public = prepare_public_key(suite, public_key_bytes)

    enc, hpke_ciphertext = suite_seal(suite, recipient_public, recipient_structure, b"", cek)
    encoded_enc = _b64(enc)

    if serialization == "compact":
        # Compact JWE has no per-recipient header, so all required parameters
        # must be integrity-protected in the sole JOSE header.
        protected: Dict[str, Any] = {"alg": alg, "enc": content_enc, "ek": encoded_enc}
        if kid:
            protected["kid"] = kid
        recipient_header = None
    else:
        protected = {"enc": content_enc}
        recipient_header = {"alg": alg, "ek": encoded_enc}
        if kid:
            recipient_header["kid"] = kid

    protected_b64 = _encode_protected(protected)
    aad_b64 = _b64(aad) if aad is not None else None
    combined_aad = _combine_aad(protected_b64, aad_b64)

    cek_key = jwk.construct(cek, jwe.ALGORITHMS.DIR)
    _, iv, ciphertext, tag = jwe._encrypt_and_auth(  # noqa: SLF001
        cek_key,
        jwe.ALGORITHMS.DIR,
        content_enc,
        None,
        plaintext,
        combined_aad,
    )

    return _build_jwe_json(
        protected_b64,
        hpke_ciphertext,
        ciphertext,
        iv=iv,
        tag=tag,
        aad_b64=aad_b64,
        header=recipient_header,
        recipients=(
            [{"encrypted_key": _b64(hpke_ciphertext), "header": recipient_header}]
            if recipient_header is not None
            else None
        ),
        serialization=serialization,
    )


def _decrypt_integrated(
    parts: JweParts,
    recipient_private_cose: Dict[int, bytes],
    alg: str,
    combined_aad: bytes,
    info: bytes,
) -> bytes:
    if parts.iv_b64 or parts.tag_b64:
        raise ValueError("iv and tag must be empty for Integrated Encryption")

    suite = _suite_from_alg(alg)
    private_key_bytes = cose.cose_private_key_to_bytes(recipient_private_cose)
    recipient_private = prepare_private_key(suite, private_key_bytes)

    enc = base64url_decode(parts.encrypted_key_b64.encode("ascii"))
    ciphertext = base64url_decode(parts.ciphertext_b64.encode("ascii"))

    return suite_open(suite, enc, recipient_private, info, combined_aad, ciphertext)


def _decrypt_key_encryption(
    parts: JweParts,
    recipient_private_cose: Dict[int, bytes],
    alg: str,
    content_enc: str,
    combined_aad: bytes,
    info: Optional[bytes],
    protected: Dict[str, Any],
) -> bytes:
    recipient_header = parts.header or {}
    if parts.recipients:
        recipient_header = parts.recipients[0].get("header", {})

    ek_b64 = recipient_header.get("ek")
    if ek_b64 is None:
        ek_b64 = protected.get("ek")
    if ek_b64 is None:
        raise ValueError("Missing ek header for Key Encryption")

    suite = _suite_from_alg(alg)
    private_key_bytes = cose.cose_private_key_to_bytes(recipient_private_cose)
    recipient_private = prepare_private_key(suite, private_key_bytes)

    enc = base64url_decode(ek_b64.encode("ascii"))
    hpke_ciphertext = base64url_decode(parts.encrypted_key_b64.encode("ascii"))
    recipient_structure = _recipient_structure(content_enc, info or b"")

    cek = suite_open(suite, enc, recipient_private, recipient_structure, b"", hpke_ciphertext)

    return jwe._decrypt_and_auth(  # noqa: SLF001
        cek,
        content_enc,
        base64url_decode(parts.ciphertext_b64.encode("ascii")),
        base64url_decode(parts.iv_b64.encode("ascii")),
        combined_aad,
        base64url_decode(parts.tag_b64.encode("ascii")),
    )


def _suite_from_alg(alg: str) -> Any:
    if alg not in HPKE_ALG_SUITES:
        raise ValueError("Unsupported HPKE alg")
    hpke = load_hpke_module()
    kem_name, kdf_name, aead_name = HPKE_ALG_SUITES[alg]
    kem_id = getattr(hpke.KEMId, kem_name)
    kdf_id = getattr(hpke.KDFId, kdf_name)
    aead_id = getattr(hpke.AEADId, aead_name)
    return make_suite(hpke, kem_id, kdf_id, aead_id)


def _alg_mode(alg: str) -> str:
    if alg.endswith("-KE"):
        return "key"
    return "integrated"


def _recipient_structure(content_enc: str, extra_info: bytes) -> bytes:
    return b"JOSE-HPKE rcpt\xff" + content_enc.encode("ascii") + b"\xff" + extra_info


def _encode_protected(header: Dict[str, Any]) -> str:
    encoded = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return _b64(encoded)


def _decode_protected(protected_b64: str) -> Dict[str, Any]:
    return json.loads(base64url_decode(protected_b64.encode("ascii")).decode("utf-8"))


def _build_jwe_json(
    protected_b64: str,
    encrypted_key: bytes,
    ciphertext: bytes,
    iv: bytes,
    tag: bytes,
    aad_b64: Optional[str],
    header: Optional[Dict[str, Any]],
    recipients: Optional[list[Dict[str, Any]]],
    serialization: str,
) -> Dict[str, Any]:
    if serialization == "general":
        payload: Dict[str, Any] = {
            "protected": protected_b64,
            "ciphertext": _b64(ciphertext),
            "recipients": recipients or [{"encrypted_key": _b64(encrypted_key)}],
        }
        if iv:
            payload["iv"] = _b64(iv)
        if tag:
            payload["tag"] = _b64(tag)
        if aad_b64:
            payload["aad"] = aad_b64
        return payload

    payload = {
        "protected": protected_b64,
        "ciphertext": _b64(ciphertext),
        "encrypted_key": _b64(encrypted_key),
    }
    if iv:
        payload["iv"] = _b64(iv)
    if tag:
        payload["tag"] = _b64(tag)
    if aad_b64:
        payload["aad"] = aad_b64
    if header:
        payload["header"] = header
    return payload


def _serialize_compact(jwe_json: Dict[str, Any]) -> str:
    return ".".join(
        [
            jwe_json.get("protected", ""),
            jwe_json.get("encrypted_key", ""),
            jwe_json.get("iv", ""),
            jwe_json.get("ciphertext", ""),
            jwe_json.get("tag", ""),
        ]
    )


def _looks_like_compact(serialized: str) -> bool:
    return serialized.count(".") == 4


def _parse_compact(serialized: str) -> JweParts:
    protected, encrypted_key, iv, ciphertext, tag = serialized.split(".")
    return JweParts(
        protected_b64=protected,
        encrypted_key_b64=encrypted_key,
        iv_b64=iv,
        ciphertext_b64=ciphertext,
        tag_b64=tag,
        aad_b64=None,
        header=None,
        recipients=None,
    )


def _parse_json(serialized: str) -> JweParts:
    payload = json.loads(serialized)
    recipients = payload.get("recipients")
    header = payload.get("header")

    encrypted_key = payload.get("encrypted_key")
    if encrypted_key is None and recipients:
        encrypted_key = recipients[0].get("encrypted_key")

    if encrypted_key is None:
        raise ValueError("Missing encrypted_key")

    return JweParts(
        protected_b64=payload["protected"],
        encrypted_key_b64=encrypted_key,
        iv_b64=payload.get("iv", ""),
        ciphertext_b64=payload["ciphertext"],
        tag_b64=payload.get("tag", ""),
        aad_b64=payload.get("aad"),
        header=header,
        recipients=recipients,
    )


def _b64(data: Optional[bytes]) -> str:
    if data is None:
        return ""
    return base64url_encode(data).decode("ascii")


def _combine_aad(protected_b64: str, aad_b64: Optional[str]) -> bytes:
    if aad_b64:
        return f"{protected_b64}.{aad_b64}".encode("ascii")
    return protected_b64.encode("ascii")
