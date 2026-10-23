from __future__ import annotations

import json
from array import array
from collections import UserList, deque

import pytest

from access_gate import AuthorizationRequest, Decision, Effect, Resource, Subject


def test_authorization_inputs_are_recursive_immutable_snapshots() -> None:
    attributes = {"tenant": {"id": "a"}, "groups": ["reader"]}
    subject = Subject("user-1", roles={"reader"}, attributes=attributes)

    attributes["tenant"]["id"] = "b"  # type: ignore[index]
    attributes["groups"].append("admin")  # type: ignore[union-attr]

    assert subject.attributes["tenant"] == {"id": "a"}
    assert subject.attributes["groups"] == ("reader",)
    with pytest.raises(TypeError):
        subject.attributes["tenant"] = {"id": "b"}
    with pytest.raises(TypeError):
        subject.attributes["tenant"]["id"] = "b"  # type: ignore[index]


def test_request_resource_and_decision_mappings_are_immutable() -> None:
    request = AuthorizationRequest(
        Subject("user-1"),
        "record.read",
        Resource("record", attributes={"tenant": "a"}),
        context={"device": {"trusted": True}},
        action_attributes={"risk": 1},
    )
    decision = Decision.allow("Allowed.", metadata={"trace": {"policy": "reader"}})

    with pytest.raises(TypeError):
        request.context["device"] = {}
    with pytest.raises(TypeError):
        request.resource.attributes["tenant"] = "b"  # type: ignore[union-attr]
    with pytest.raises(TypeError):
        decision.metadata["trace"]["policy"] = "admin"  # type: ignore[index]


def test_authorization_values_reject_cycles_and_invalid_runtime_types() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    with pytest.raises(ValueError, match="cycles"):
        Subject("user-1", attributes=cyclic)
    with pytest.raises(TypeError, match="collection"):
        Subject("user-1", roles="admin")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="non-empty"):
        AuthorizationRequest(Subject("user-1"), "")
    with pytest.raises(TypeError, match="non-empty"):
        Resource("")


def test_authorization_values_validate_all_security_critical_fields() -> None:
    with pytest.raises(TypeError, match="identifier"):
        Subject(1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="role"):
        Subject("user-1", roles={1})  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="boolean"):
        Subject("user-1", authenticated="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-empty identifier"):
        Subject("")
    with pytest.raises(TypeError, match="identifier"):
        Resource("record", identifier=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="mapping"):
        Subject("user-1", attributes=[])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="keys"):
        Subject("user-1", attributes={1: "value"})  # type: ignore[dict-item]
    with pytest.raises(TypeError, match="Effect"):
        Decision("allow", "Allowed.")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="reason"):
        Decision(Effect.ALLOW, "")
    with pytest.raises(TypeError, match="policy"):
        Decision(Effect.ALLOW, "Allowed.", policy=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="subject"):
        AuthorizationRequest("user-1", "read")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="resource"):
        AuthorizationRequest(Subject("user-1"), "read", resource="record")  # type: ignore[arg-type]


def test_snapshot_bounds_nested_values_and_handles_set_values() -> None:
    subject = Subject("user-1", attributes={"scopes": {"read", "write"}})
    assert subject.attributes["scopes"] == frozenset({"read", "write"})

    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    with pytest.raises(ValueError, match="cycles"):
        Subject("user-1", attributes={"cycle": cyclic_list})

    nested: object = "leaf"
    for _ in range(66):
        nested = [nested]
    with pytest.raises(ValueError, match="nesting depth"):
        Subject("user-1", attributes={"nested": nested})


def test_other_mutable_containers_are_snapshotted() -> None:
    groups = deque(["staff"])
    teams = UserList(["safety"])
    ids = array("i", [1])
    raw = bytearray(b"a")
    scopes = {"read": True}
    trail = deque(["policy-a"])
    request = AuthorizationRequest(
        Subject("user-1", attributes={"groups": groups, "teams": teams}),
        "read",
        context={"ids": ids, "raw": raw, "scopes": scopes.keys(), "flags": scopes.values()},
    )
    decision = Decision.deny("Denied.", metadata={"trail": trail})

    groups.append("admins")
    teams.append("finance")
    ids.append(2)
    raw += b"b"
    scopes["write"] = False
    trail.append("tampered")

    assert request.subject.attributes["groups"] == ("staff",)
    assert request.subject.attributes["teams"] == ("safety",)
    assert request.context["ids"] == (1,)
    assert request.context["raw"] == b"a"
    assert request.context["scopes"] == frozenset({"read"})
    assert request.context["flags"] == (True,)
    assert decision.metadata["trail"] == ("policy-a",)

    cyclic = deque[object]()
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="cycles"):
        Subject("user-1", attributes={"cycle": cyclic})


def test_immutable_values_have_json_serializable_public_snapshots() -> None:
    request = AuthorizationRequest(
        Subject("user-1", roles={"reader"}, attributes={"teams": ["safety"]}),
        "record.read",
        Resource("record", "record-1", {"owner_id": "user-1"}),
        context={"trusted": True},
    )
    decision = Decision.allow(
        "Allowed.",
        policy="reader",
        metadata={"trace": {"policies": ["reader"]}},
    )

    assert json.loads(json.dumps(request.to_dict()))["subject"]["roles"] == ["reader"]
    assert json.loads(json.dumps(decision.to_dict()))["effect"] == "allow"


def test_subject_role_count_is_bounded() -> None:
    with pytest.raises(ValueError, match="maximum item count"):
        Subject("user-1", roles={f"role-{index}" for index in range(10_001)})
