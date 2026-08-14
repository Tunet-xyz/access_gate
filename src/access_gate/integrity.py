"""Deterministic policy identity and externally supplied signature verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from inspect import isawaitable
from typing import Protocol, cast

from .abac import (
    MAX_POLICY_DOCUMENT_CHARS,
    AttributePolicy,
    OperatorRegistry,
    PolicySchemaError,
    attribute_policy_from_dict,
)

CANONICAL_POLICY_FORMAT = "access_gate.canonical-json.v1"
POLICY_SET_SCHEMA_VERSION = "access_gate.policy_set.v1"
SIGNED_POLICY_ENVELOPE_VERSION = "access_gate.signed_policy.v1"
MAX_SIGNED_POLICY_DOCUMENT_CHARS = MAX_POLICY_DOCUMENT_CHARS + 32_768
MAX_SIGNATURE_BYTES = 16_384

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]*$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class PolicyIntegrityError(PolicySchemaError):
    """Raised when policy identity or signature verification fails."""


class PolicySigner(Protocol):
    """Sign canonical bytes using keys managed outside AccessGate."""

    key_id: str
    algorithm: str

    def sign(self, payload: bytes) -> bytes: ...


class PolicySignatureVerifier(Protocol):
    """Verify canonical bytes using an application-controlled trust store."""

    def verify(
        self,
        payload: bytes,
        signature: bytes,
        *,
        key_id: str,
        algorithm: str,
    ) -> bool: ...


def _canonical_json_bytes(value: object) -> bytes:
    try:
        document = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise PolicyIntegrityError("The policy is not canonically serializable.") from error
    return document.encode("utf-8")


def canonical_policy_bytes(policy: AttributePolicy) -> bytes:
    """Return deterministic UTF-8 bytes for one validated ABAC policy."""

    if not isinstance(policy, AttributePolicy):
        raise TypeError("policy must be an AttributePolicy.")
    return _canonical_json_bytes(policy.to_dict())


def policy_fingerprint(policy: AttributePolicy) -> str:
    """Return a stable, algorithm-labelled digest for a policy."""

    return f"sha256:{hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()}"


def policy_set_fingerprint(policies: Iterable[AttributePolicy]) -> str:
    """Fingerprint an ordered ABAC policy set, including evaluation order."""

    normalized = tuple(policies)
    if not all(isinstance(policy, AttributePolicy) for policy in normalized):
        raise TypeError("policies must contain only AttributePolicy instances.")
    names = [policy.name for policy in normalized]
    if len(set(names)) != len(names):
        raise PolicyIntegrityError("Policy names must be unique within a policy set.")
    payload = {
        "schema_version": POLICY_SET_SCHEMA_VERSION,
        "policies": [policy.to_dict() for policy in normalized],
    }
    return f"sha256:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"


def _validated_identifier(value: object, *, field_name: str, max_length: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or _SAFE_IDENTIFIER.fullmatch(value) is None
    ):
        raise PolicyIntegrityError(
            f"{field_name} must be a bounded identifier containing only safe characters."
        )
    return value


def _protected_document(
    policy: AttributePolicy,
    *,
    key_id: str,
    algorithm: str,
) -> dict[str, object]:
    return {
        "envelope_version": SIGNED_POLICY_ENVELOPE_VERSION,
        "canonicalization": CANONICAL_POLICY_FORMAT,
        "key_id": key_id,
        "algorithm": algorithm,
        "policy": policy.to_dict(),
    }


def dumps_signed_policy(policy: AttributePolicy, signer: PolicySigner) -> str:
    """Create a signed policy envelope without owning signing keys or algorithms."""

    if not isinstance(policy, AttributePolicy):
        raise TypeError("policy must be an AttributePolicy.")
    key_id = _validated_identifier(signer.key_id, field_name="key_id", max_length=512)
    algorithm = _validated_identifier(signer.algorithm, field_name="algorithm", max_length=128)
    protected = _protected_document(policy, key_id=key_id, algorithm=algorithm)
    try:
        signature = signer.sign(_canonical_json_bytes(protected))
    except Exception as error:
        raise PolicyIntegrityError("The policy signer failed.") from error
    if isawaitable(signature):
        _close_awaitable(signature)
        raise PolicyIntegrityError("Policy signers must be synchronous.")
    if not isinstance(signature, bytes):
        raise PolicyIntegrityError("Policy signers must return bytes.")
    if not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise PolicyIntegrityError("The policy signature has an invalid size.")
    envelope = {
        **protected,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }
    document = _canonical_json_bytes(envelope).decode("utf-8")
    if len(document) > MAX_SIGNED_POLICY_DOCUMENT_CHARS:
        raise PolicyIntegrityError("The signed policy document exceeds the size limit.")
    return document


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str) or not value or _BASE64URL.fullmatch(value) is None:
        raise PolicyIntegrityError("signature must be canonical unpadded base64url.")
    try:
        signature = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise PolicyIntegrityError("signature must be canonical unpadded base64url.") from error
    canonical = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    if canonical != value or not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise PolicyIntegrityError("The policy signature is not canonical or has an invalid size.")
    return signature


def loads_signed_policy(
    document: str,
    verifier: PolicySignatureVerifier,
    *,
    operators: OperatorRegistry | None = None,
) -> AttributePolicy:
    """Verify a signed envelope before constructing its policy."""

    if not isinstance(document, str):
        raise TypeError("signed policy document must be a string.")
    if len(document) > MAX_SIGNED_POLICY_DOCUMENT_CHARS:
        raise PolicyIntegrityError("The signed policy document exceeds the size limit.")
    try:
        value = json.loads(
            document,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_json_object,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise PolicyIntegrityError("The signed policy document is not valid JSON.") from error
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise PolicyIntegrityError("The signed policy envelope must be an object.")
    envelope = cast(Mapping[str, object], value)
    expected_fields = {
        "envelope_version",
        "canonicalization",
        "key_id",
        "algorithm",
        "policy",
        "signature",
    }
    if set(envelope) != expected_fields:
        raise PolicyIntegrityError("The signed policy envelope has missing or unknown fields.")
    if envelope["envelope_version"] != SIGNED_POLICY_ENVELOPE_VERSION:
        raise PolicyIntegrityError("The signed policy envelope version is unsupported.")
    if envelope["canonicalization"] != CANONICAL_POLICY_FORMAT:
        raise PolicyIntegrityError("The signed policy canonicalization is unsupported.")
    key_id = _validated_identifier(envelope["key_id"], field_name="key_id", max_length=512)
    algorithm = _validated_identifier(envelope["algorithm"], field_name="algorithm", max_length=128)
    raw_policy = envelope["policy"]
    if not isinstance(raw_policy, Mapping) or not all(isinstance(key, str) for key in raw_policy):
        raise PolicyIntegrityError("policy must be an object.")
    policy_document = cast(Mapping[str, object], raw_policy)
    signature = _decode_signature(envelope["signature"])
    protected = {
        "envelope_version": envelope["envelope_version"],
        "canonicalization": envelope["canonicalization"],
        "key_id": key_id,
        "algorithm": algorithm,
        "policy": policy_document,
    }
    try:
        verified = verifier.verify(
            _canonical_json_bytes(protected),
            signature,
            key_id=key_id,
            algorithm=algorithm,
        )
    except Exception as error:
        raise PolicyIntegrityError("The policy signature verifier failed.") from error
    if isawaitable(verified):
        _close_awaitable(verified)
        raise PolicyIntegrityError("Policy signature verifiers must be synchronous.")
    if not isinstance(verified, bool):
        raise PolicyIntegrityError("Policy signature verifiers must return a boolean.")
    if not verified:
        raise PolicyIntegrityError("The policy signature is invalid.")
    return attribute_policy_from_dict(policy_document, operators=operators)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON constant: {value}")


def _reject_duplicate_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON object key: {key}")
        value[key] = item
    return value


def _close_awaitable(value: object) -> None:
    close = getattr(value, "close", None)
    if callable(close):
        close()
