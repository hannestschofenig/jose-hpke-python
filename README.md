# `jose_hpke` Python Package

`jose_hpke` implements the JOSE-HPKE processing rules defined by
`draft-ietf-jose-hpke-encrypt`. It supports HPKE Integrated Encryption and
HPKE Key Encryption, uses COSE Key structures for recipient keys, and can
produce and consume JWE Compact, Flattened JSON, and General JSON
serializations.

> This package implements an Internet-Draft. The format and algorithm
> identifiers may change before publication as an RFC.

## Components

- `jose_hpke.py` — JOSE-HPKE encryption, decryption, algorithm mapping, JWE
  parsing, and serialization.
- `cose.py` — generation, CBOR encoding, decoding, and conversion of COSE EC2
  and OKP keys.
- `hpke_compat.py` — compatibility layer around the `pyhpke` API.
- `cli.py` — implementation of the `jose-hpke` command-line interface.

## Dependencies

The package uses:

- [`pyhpke`](https://pypi.org/project/pyhpke/) for HPKE
- [`python-jose`](https://pypi.org/project/python-jose/) for JWE content
  encryption
- `cryptography` for key generation and conversion
- `cbor2` for COSE Key serialization

Install the project from the repository root:

```bash
python -m pip install -e .
```

## Supported Algorithms

| JOSE algorithm | KEM | KDF | HPKE AEAD |
|---|---|---|---|
| `HPKE-0`, `HPKE-0-KE` | P-256 | HKDF-SHA256 | AES-128-GCM |
| `HPKE-1`, `HPKE-1-KE` | P-384 | HKDF-SHA384 | AES-256-GCM |
| `HPKE-2`, `HPKE-2-KE` | P-521 | HKDF-SHA512 | AES-256-GCM |
| `HPKE-3`, `HPKE-3-KE` | X25519 | HKDF-SHA256 | AES-128-GCM |
| `HPKE-4`, `HPKE-4-KE` | X25519 | HKDF-SHA256 | ChaCha20Poly1305 |
| `HPKE-5`, `HPKE-5-KE` | X448 | HKDF-SHA512 | AES-256-GCM |
| `HPKE-6`, `HPKE-6-KE` | X448 | HKDF-SHA512 | ChaCha20Poly1305 |
| `HPKE-7`, `HPKE-7-KE` | P-256 | HKDF-SHA256 | AES-256-GCM |

Algorithms without the `-KE` suffix use Integrated Encryption. Algorithms
with the `-KE` suffix use HPKE to encrypt the JWE Content Encryption Key
(CEK).

Key Encryption currently supports the JWE content encryption algorithms
`A128GCM`, `A192GCM`, and `A256GCM` through `python-jose`.

## COSE Keys

Keys are represented as Python dictionaries using integer COSE labels and are
stored as CBOR files.

Supported key types and curves:

- EC2: P-256, P-384, P-521
- OKP: X25519, X448

Generate and store a P-256 key pair:

```python
from jose_hpke import cose

keypair = cose.generate_ec2_keypair("P-256")
cose.write_cose_key("receiver.pub.cose", keypair.public_cose)
cose.write_cose_key("receiver.priv.cose", keypair.private_cose)
```

Generate an X25519 key pair:

```python
keypair = cose.generate_okp_keypair("X25519")
```

Read an existing key:

```python
public_key = cose.read_cose_key("receiver.pub.cose")
private_key = cose.read_cose_key("receiver.priv.cose")
```

## Python API

The primary API consists of `jwe_encrypt()` and `jwe_decrypt()`.

### Integrated Encryption

```python
from jose_hpke import cose
from jose_hpke.jose_hpke import jwe_decrypt, jwe_encrypt

public_key = cose.read_cose_key("receiver.pub.cose")
private_key = cose.read_cose_key("receiver.priv.cose")

serialized = jwe_encrypt(
    b"message",
    public_key,
    alg="HPKE-0",
    kid="receiver-key-1",
    serialization="flattened",
)

plaintext = jwe_decrypt(serialized, private_key)
assert plaintext == b"message"
```

Integrated Encryption directly encrypts the plaintext with HPKE. The protected
header contains `alg` and optionally `kid`; it must not contain `enc` or `ek`.
The JWE Initialization Vector and Authentication Tag are empty.

### Key Encryption

```python
serialized = jwe_encrypt(
    b"message",
    public_key,
    alg="HPKE-0-KE",
    content_enc="A128GCM",
    kid="receiver-key-1",
    serialization="compact",
)

plaintext = jwe_decrypt(serialized, private_key)
assert plaintext == b"message"
```

Key Encryption generates a random CEK, encrypts the CEK with HPKE, and uses the
CEK for normal JWE content encryption. The HPKE `info` value is the draft's
`Recipient_structure`:

```text
"JOSE-HPKE rcpt" || 0xff || ASCII(enc) || 0xff || recipient_extra_info
```

For Compact JWE, `alg`, `kid`, `enc`, and `ek` are placed in the protected
header. JSON serializations may carry recipient-specific HPKE parameters in the
per-recipient header.

### External AAD

External Additional Authenticated Data is supported for JWE JSON
serializations:

```python
serialized = jwe_encrypt(
    b"message",
    public_key,
    alg="HPKE-0",
    aad=b"application context",
    serialization="flattened",
)

plaintext = jwe_decrypt(
    serialized,
    private_key,
    aad=b"application context",
)
```

Compact JWE does not support external JWE AAD.

### HPKE `info`

For Integrated Encryption, `info` defaults to the empty byte string and may be
provided explicitly:

```python
serialized = jwe_encrypt(
    b"message",
    public_key,
    alg="HPKE-0",
    info=b"private application context",
)
```

The same value must be supplied for decryption.

For Key Encryption, the supplied value is used as `recipient_extra_info` in
`Recipient_structure`.

## Serialization Modes

Pass one of the following values to `serialization`:

- `compact` — five-part JWE Compact Serialization
- `flattened` — Flattened JWE JSON Serialization
- `general` — General JWE JSON Serialization

The decryption function detects Compact versus JSON serialization
automatically.

The current General JSON decryption implementation processes the first
recipient only. Recipient selection by `kid` and multi-recipient trial
decryption are not implemented.

## Command-Line Interface

The installed `jose-hpke` command uses this package. Examples:

```bash
jose-hpke gen-keys --curve P-256 --out-prefix receiver

jose-hpke encrypt \
  --alg HPKE-0 \
  --serialization compact \
  --pub-key receiver.pub.cose \
  --in message.txt \
  --out message.jwe

jose-hpke decrypt \
  --priv-key receiver.priv.cose \
  --in message.jwe \
  --out message.dec.txt
```

Key Encryption example:

```bash
jose-hpke encrypt \
  --alg HPKE-0-KE \
  --enc A128GCM \
  --serialization compact \
  --pub-key receiver.pub.cose \
  --in message.txt \
  --out message.jwe
```

Use `--aad-file` and `--info-file` to read external AAD and HPKE context data
from binary files.

## Testing

Run the algorithm and serialization round-trip suite from the repository root:

```bash
PYTHONPATH=src python scripts/test_algorithms.py
```

The suite covers:

- all eight Integrated Encryption algorithms
- all eight Key Encryption algorithms
- General JSON Key Encryption
- Compact Key Encryption
- A128GCM and A256GCM content encryption
- required Compact Key Encryption protected-header parameters

The implementation has also been verified by decrypting the complete test
vector set from PR #101 of `draft-ietf-jose-hpke-encrypt`.
