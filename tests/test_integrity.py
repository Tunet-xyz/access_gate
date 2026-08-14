from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from access_gate import (
    AttributePolicy,
    ContextAttribute,
    PolicyIntegrityError,
    canonical_policy_bytes,
    dumps_signed_policy,
    loads_policy,
    loads_signed_policy,
    policy_fingerprint,
    policy_set_fingerprint,
)
from access_gate import integrity as integrity_module


@dataclass
class HmacSigner:
    secret: bytes
    key_id: str = "test-key-1"
    algorithm: str = "test-hmac-sha256"

    def sign(self, payload: bytes) -> bytes:
        return hmac.digest(self.secret, payload, "sha256")


@dataclass
class HmacVerifier:
    secret: bytes

    def verify(
        self,
        payload: bytes,
        signature: bytes,
        *,
        key_id: str,
        algorithm: str,
    ) -> bool:
        return (
            key_id == "test-key-1"
            and algorithm == "test-hmac-sha256"
            and hmac.compare_digest(signature, hmac.digest(self.secret, payload, "sha256"))
        )


def policy(name: str = "trusted_device") -> AttributePolicy:
    return AttributePolicy(
        ContextAttribute("device.trusted").equals(True),
        actions={"document.read"},
        name=name,
    )


def test_canonical_policy_identity_is_stable_and_algorithm_labelled() -> None:
    first = policy()
    restored = loads_signed_policy(
        dumps_signed_policy(first, HmacSigner(b"secret")),
        HmacVerifier(b"secret"),
    )

    assert canonical_policy_bytes(restored) == canonical_policy_bytes(first)
    assert policy_fingerprint(restored) == policy_fingerprint(first)
    assert policy_fingerprint(first) == (
        "sha256:" + hashlib.sha256(canonical_policy_bytes(first)).hexdigest()
    )


def test_policy_set_fingerprint_preserves_order_and_rejects_duplicate_names() -> None:
    first = policy("first")
    second = policy("second")

    assert policy_set_fingerprint([first, second]) != policy_set_fingerprint([second, first])
    with pytest.raises(PolicyIntegrityError, match="unique"):
        policy_set_fingerprint([first, first])


def test_v1_golden_policy_fingerprint_is_stable() -> None:
    fixture = Path(__file__).parent / "fixtures" / "policies" / "v1" / "trusted-device.json"
    golden = loads_policy(fixture.read_text(encoding="utf-8"))

    assert policy_fingerprint(golden) == (
        "sha256:38e6408b17ee1e83c6b14f44593678e46264f4133ccaac116b5ced51ce3d87a7"
    )


def test_signed_policy_verifies_before_it_is_constructed() -> None:
    document = dumps_signed_policy(policy(), HmacSigner(b"secret"))

    restored = loads_signed_policy(document, HmacVerifier(b"secret"))

    assert restored.to_dict() == policy().to_dict()


def test_signed_policy_rejects_duplicate_json_keys() -> None:
    document = dumps_signed_policy(policy(), HmacSigner(b"secret"))
    duplicated = document.replace(
        '"algorithm":"test-hmac-sha256",',
        '"algorithm":"test-hmac-sha256","algorithm":"test-hmac-sha256",',
    )

    with pytest.raises(PolicyIntegrityError, match="valid JSON"):
        loads_signed_policy(duplicated, HmacVerifier(b"secret"))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("envelope_version", "access_gate.signed_policy.v0"),
        ("canonicalization", "other"),
        ("key_id", "other-key"),
        ("algorithm", "other-algorithm"),
        ("signature", "AAAA"),
    ],
)
def test_signed_policy_rejects_tampered_protected_fields(
    field: str,
    replacement: object,
) -> None:
    envelope = json.loads(dumps_signed_policy(policy(), HmacSigner(b"secret")))
    envelope[field] = replacement

    with pytest.raises(PolicyIntegrityError):
        loads_signed_policy(json.dumps(envelope), HmacVerifier(b"secret"))


def test_signed_policy_rejects_policy_tampering_unknown_fields_and_wrong_key() -> None:
    envelope = json.loads(dumps_signed_policy(policy(), HmacSigner(b"secret")))
    envelope["policy"]["name"] = "tampered"
    with pytest.raises(PolicyIntegrityError, match="invalid"):
        loads_signed_policy(json.dumps(envelope), HmacVerifier(b"secret"))

    envelope = json.loads(dumps_signed_policy(policy(), HmacSigner(b"secret")))
    envelope["unknown"] = True
    with pytest.raises(PolicyIntegrityError, match="missing or unknown"):
        loads_signed_policy(json.dumps(envelope), HmacVerifier(b"secret"))

    with pytest.raises(PolicyIntegrityError, match="invalid"):
        loads_signed_policy(
            dumps_signed_policy(policy(), HmacSigner(b"secret")),
            HmacVerifier(b"wrong"),
        )


class InvalidSigner:
    key_id = "test-key-1"
    algorithm = "test-hmac-sha256"

    def sign(self, payload: bytes) -> bytes:
        del payload
        return "not-bytes"  # type: ignore[return-value]


class InvalidVerifier:
    def verify(
        self,
        payload: bytes,
        signature: bytes,
        *,
        key_id: str,
        algorithm: str,
    ) -> bool:
        del payload, signature, key_id, algorithm
        return 1  # type: ignore[return-value]


class FailingSigner(InvalidSigner):
    def sign(self, payload: bytes) -> bytes:
        del payload
        raise RuntimeError("signer unavailable")


class FailingVerifier:
    def verify(
        self,
        payload: bytes,
        signature: bytes,
        *,
        key_id: str,
        algorithm: str,
    ) -> bool:
        del payload, signature, key_id, algorithm
        raise RuntimeError("trust store unavailable")


class AsyncSigner(InvalidSigner):
    async def sign(self, payload: bytes) -> bytes:
        del payload
        return b"signature"


class AsyncVerifier:
    async def verify(
        self,
        payload: bytes,
        signature: bytes,
        *,
        key_id: str,
        algorithm: str,
    ) -> bool:
        del payload, signature, key_id, algorithm
        return True


def test_signer_and_verifier_contracts_are_fail_closed() -> None:
    with pytest.raises(PolicyIntegrityError, match="return bytes"):
        dumps_signed_policy(policy(), InvalidSigner())

    document = dumps_signed_policy(policy(), HmacSigner(b"secret"))
    with pytest.raises(PolicyIntegrityError, match="return a boolean"):
        loads_signed_policy(document, InvalidVerifier())

    with pytest.raises(PolicyIntegrityError, match="signer failed"):
        dumps_signed_policy(policy(), FailingSigner())
    with pytest.raises(PolicyIntegrityError, match="verifier failed"):
        loads_signed_policy(document, FailingVerifier())
    with pytest.raises(PolicyIntegrityError, match="synchronous"):
        dumps_signed_policy(policy(), AsyncSigner())
    with pytest.raises(PolicyIntegrityError, match="synchronous"):
        loads_signed_policy(document, AsyncVerifier())


@pytest.mark.parametrize("signature", [b"", b"x" * 16_385])
def test_signed_policy_rejects_invalid_signer_output_sizes(signature: bytes) -> None:
    signer = InvalidSigner()
    signer.sign = lambda payload: signature  # type: ignore[method-assign]

    with pytest.raises(PolicyIntegrityError, match="invalid size"):
        dumps_signed_policy(policy(), signer)


def test_integrity_api_rejects_wrong_types_and_non_json_literals() -> None:
    with pytest.raises(TypeError, match="AttributePolicy"):
        canonical_policy_bytes("policy")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="AttributePolicy"):
        dumps_signed_policy("policy", HmacSigner(b"secret"))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="only AttributePolicy"):
        policy_set_fingerprint([object()])  # type: ignore[list-item]
    with pytest.raises(PolicyIntegrityError, match="canonically serializable"):
        canonical_policy_bytes(AttributePolicy(ContextAttribute("scope").equals({"read"})))
    with pytest.raises(TypeError, match="must be a string"):
        loads_signed_policy(b"{}", HmacVerifier(b"secret"))  # type: ignore[arg-type]


def test_signed_policy_parser_rejects_malformed_and_oversized_documents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(PolicyIntegrityError, match="valid JSON"):
        loads_signed_policy("NaN", HmacVerifier(b"secret"))
    with pytest.raises(PolicyIntegrityError, match="must be an object"):
        loads_signed_policy("[]", HmacVerifier(b"secret"))

    document = dumps_signed_policy(policy(), HmacSigner(b"secret"))
    monkeypatch.setattr(integrity_module, "MAX_SIGNED_POLICY_DOCUMENT_CHARS", 1)
    with pytest.raises(PolicyIntegrityError, match="exceeds"):
        loads_signed_policy(document, HmacVerifier(b"secret"))
    with pytest.raises(PolicyIntegrityError, match="exceeds"):
        dumps_signed_policy(policy(), HmacSigner(b"secret"))


@pytest.mark.parametrize("signature", ["=", "A", "AA=="])
def test_signed_policy_rejects_noncanonical_base64url(signature: str) -> None:
    envelope = json.loads(dumps_signed_policy(policy(), HmacSigner(b"secret")))
    envelope["signature"] = signature

    with pytest.raises(PolicyIntegrityError, match="base64url"):
        loads_signed_policy(json.dumps(envelope), HmacVerifier(b"secret"))


def test_signed_policy_rejects_non_object_policy_before_verification() -> None:
    envelope = json.loads(dumps_signed_policy(policy(), HmacSigner(b"secret")))
    envelope["policy"] = []

    with pytest.raises(PolicyIntegrityError, match="policy must be an object"):
        loads_signed_policy(json.dumps(envelope), HmacVerifier(b"secret"))


@pytest.mark.parametrize("bad_value", ["", "bad key", "x" * 513])
def test_signed_policy_rejects_unsafe_key_identifiers(bad_value: str) -> None:
    signer = HmacSigner(b"secret", key_id=bad_value)

    with pytest.raises(PolicyIntegrityError, match="key_id"):
        dumps_signed_policy(policy(), signer)
