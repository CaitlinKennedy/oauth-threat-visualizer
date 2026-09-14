"""EC JWK coordinate padding (RFC 7518 §6.2.1.2/.3) for DPoP + private_key_jwt.

The JWK spec requires EC ``x``/``y`` to be encoded at the curve's full field
width (32 bytes for P-256), left-zero-padded when the coordinate's own
big-endian encoding is shorter. PyJWT's own ``ECAlgorithm.to_jwk`` instead
emits the *minimal*-length encoding (the same helper it uses for RSA's
variable-length ``n``/``e``), so roughly 1 in 256 times per coordinate — every
run where the top byte of ``x`` or ``y`` happens to be zero — it emits a JWK
one byte short. PyJWT's own ``ECAlgorithm.from_jwk``/``PyJWK.from_dict`` then
refuse to parse that JWK back (``InvalidKeyError: Coords should be 32 bytes
for curve P-256``), and any RFC 7638 thumbprint computed from the unpadded
coordinate silently disagrees with the correct one — which would break DPoP's
``cnf.jkt`` binding.

Rather than rely on 1-in-256-odds to hit the bug in CI, these tests force the
short-coordinate case by scanning freshly generated P-256 keys for one whose
public numbers actually have a leading zero byte, then exercise it through
every EC JWK code path: ``SigningKey`` (private_key_jwt / assertion sign+
verify) and ``DpopKey`` (DPoP proof sign+verify + cnf.jkt binding). A separate
statistical test also runs many keys through the ordinary API to back-stop
the forced case.
"""

from __future__ import annotations

import base64

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from otv import crypto

ISSUER = "https://as.example/"
AUDIENCE = "https://as.example/token"


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _pem_pair(key: ec.EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _find_ec_key_with_short_coordinate(
    max_tries: int = 4000,
) -> ec.EllipticCurvePrivateKey:
    """Generate real P-256 keys until one has a coordinate < 32 bytes.

    A coordinate's natural big-endian encoding is short whenever its top byte
    is zero: probability 1/256 for each of x and y independently, so the
    chance a single key misses on *both* is (255/256)**2 ≈ 0.992. Missing on
    every one of ``max_tries`` keys has probability ≈ 0.992**4000, on the
    order of 1e-14 — this is a forced case, not a flake.
    """
    for _ in range(max_tries):
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        x_len = (numbers.x.bit_length() + 7) // 8
        y_len = (numbers.y.bit_length() + 7) // 8
        if x_len < 32 or y_len < 32:
            return key
    raise AssertionError(f"no short-coordinate P-256 key found in {max_tries} tries")


# --- forced short-coordinate case: SigningKey / private_key_jwt path -------


def test_signing_key_jwk_pads_a_short_coordinate_and_round_trips():
    key = _find_ec_key_with_short_coordinate()
    numbers = key.public_key().public_numbers()
    x_len = (numbers.x.bit_length() + 7) // 8
    y_len = (numbers.y.bit_length() + 7) // 8
    assert x_len < 32 or y_len < 32, "test setup must actually force a short coordinate"

    private_pem, public_pem = _pem_pair(key)
    signing_key = crypto.SigningKey(
        kid="short-coord-key",
        _private_pem=private_pem,
        _public_pem=public_pem,
        alg="ES256",
    )

    jwk = signing_key.public_jwk()
    x = _b64url_decode(jwk["x"])
    y = _b64url_decode(jwk["y"])
    assert len(x) == 32
    assert len(y) == 32
    assert int.from_bytes(x, "big") == numbers.x
    assert int.from_bytes(y, "big") == numbers.y

    # This is exactly what verify_assertion does under the hood for
    # private_key_jwt client auth — it used to raise InvalidKeyError here
    # whenever the coordinate was short.
    reconstructed = jwt.PyJWK.from_dict(jwk).key.public_numbers()
    assert reconstructed.x == numbers.x
    assert reconstructed.y == numbers.y

    # Full sign + verify round trip through the real assertion helpers.
    assertion = crypto.sign_assertion(
        signing_key, issuer="demo-service-client", subject="demo-service-client", audience=AUDIENCE
    )
    claims = crypto.verify_assertion(
        assertion, jwks=signing_key.jwks(), issuer="demo-service-client", audience=AUDIENCE
    )
    assert claims["sub"] == "demo-service-client"


# --- forced short-coordinate case: DpopKey / DPoP path ----------------------


def test_dpop_key_jwk_pads_a_short_coordinate_and_binds_correctly():
    key = _find_ec_key_with_short_coordinate()
    numbers = key.public_key().public_numbers()
    private_pem, _ = _pem_pair(key)
    dpop_key = crypto.DpopKey(_private_pem=private_pem)

    jwk = dpop_key.public_jwk()
    x = _b64url_decode(jwk["x"])
    y = _b64url_decode(jwk["y"])
    assert len(x) == 32
    assert len(y) == 32
    assert int.from_bytes(x, "big") == numbers.x
    assert int.from_bytes(y, "big") == numbers.y

    # Sign + verify a real DPoP proof; verify_dpop_proof runs the embedded jwk
    # through jwt.algorithms.ECAlgorithm.from_jwk, the exact call that used to
    # raise "Coords should be 32 bytes for curve P-256" on a short coordinate.
    proof = crypto.create_dpop_proof(dpop_key, htm="GET", htu="https://api/x")
    bound = crypto.verify_dpop_proof(proof, htm="GET", htu="https://api/x")

    # cnf.jkt binding: the thumbprint recomputed from the proof's own embedded
    # (padded) jwk must equal the thumbprint of the key that signed it.
    assert bound["jkt"] == dpop_key.thumbprint()
    assert crypto.jwk_thumbprint(bound["jwk"]) == dpop_key.thumbprint()
    assert crypto.jwk_thumbprint(dpop_key.public_jwk()) == dpop_key.thumbprint()


# --- RFC 7638 canonical shape ------------------------------------------------


def test_thumbprint_canonical_members_are_sorted_unpadded_base64url():
    key = crypto.DpopKey.generate()
    jwk = key.public_jwk()
    assert set(jwk) == {"kty", "crv", "x", "y"}
    assert "=" not in jwk["x"]
    assert "=" not in jwk["y"]

    thumbprint = crypto.jwk_thumbprint(jwk)
    assert len(thumbprint) == 43  # base64url(SHA-256) with no '=' padding
    assert "=" not in thumbprint

    # The thumbprint recomputed straight from the exported (padded) JWK must
    # equal the key's own — JWK export and thumbprint must never drift apart.
    assert crypto.jwk_thumbprint(key.public_jwk()) == key.thumbprint()


# --- statistical backstop: every generated key round-trips correctly -------


def test_many_generated_ec_keys_always_export_32_byte_coordinates():
    """A loop over many freshly generated keys — a backstop for the forced
    case above, guarding against any future change that reintroduces
    unpadded coordinates in a way the forced-case tests don't happen to hit.
    """
    for _ in range(300):
        key = crypto.DpopKey.generate()
        jwk = key.public_jwk()
        x = _b64url_decode(jwk["x"])
        y = _b64url_decode(jwk["y"])
        assert len(x) == 32
        assert len(y) == 32

        proof = crypto.create_dpop_proof(key, htm="POST", htu="https://api/y")
        bound = crypto.verify_dpop_proof(proof, htm="POST", htu="https://api/y")
        assert bound["jkt"] == key.thumbprint()
        assert crypto.jwk_thumbprint(key.public_jwk()) == key.thumbprint()
