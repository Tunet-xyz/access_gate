from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any

import pytest

django = pytest.importorskip("django")
from django.utils.asyncio import async_unsafe  # noqa: E402
from django.utils.functional import SimpleLazyObject  # noqa: E402

from access_gate import (  # noqa: E402
    AuthenticatedPolicy,
    AuthorizationEngine,
    AuthorizationRequest,
    Decision,
    FunctionPolicy,
    Subject,
)
from access_gate.adapters.django import DjangoAuthorizer  # noqa: E402


@async_unsafe("database access")
def _query(value: object = None) -> object:
    """Stands in for the ORM, which refuses to run on the event loop thread."""

    return value


def _asgi_request() -> Any:
    # AuthenticationMiddleware attaches a lazy user loaded from session storage.
    user = SimpleLazyObject(
        lambda: _query(SimpleNamespace(pk=7, is_authenticated=True))  # type: ignore[arg-type]
    )
    return SimpleNamespace(user=user, method="GET", path="/incidents/1")


class _DatabaseSink:
    def __init__(self) -> None:
        self.effects: list[str] = []

    def record(self, request: AuthorizationRequest, decision: Decision) -> None:
        _query()
        self.effects.append(decision.effect.value)


@pytest.fixture(autouse=True)
def _async_safety_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DJANGO_ALLOW_ASYNC_UNSAFE", raising=False)


def test_async_view_runs_the_default_subject_resolver_off_the_event_loop() -> None:
    sink = _DatabaseSink()
    authorizer = DjangoAuthorizer(AuthorizationEngine([AuthenticatedPolicy()], audit_sink=sink))

    @authorizer.require("incident.read")
    async def view(request: Any) -> str:
        return "ok"

    assert asyncio.run(view(_asgi_request())) == "ok"
    assert sink.effects == ["allow"]


def test_async_view_runs_database_backed_policies_and_sinks_off_the_event_loop() -> None:
    sink = _DatabaseSink()

    def owner(request: AuthorizationRequest) -> Decision | None:
        _query()
        return None

    async def subject(request: Any) -> Subject:
        return Subject("7")

    authorizer = DjangoAuthorizer(
        AuthorizationEngine(
            [AuthenticatedPolicy(), FunctionPolicy("owner", owner)],
            audit_sink=sink,
        ),
        subject_resolver=subject,
        denial_handler=lambda request, decision: f"denied by {decision.policy}",
    )

    @authorizer.require("incident.read")
    async def view(request: Any) -> str:
        return "ok"

    assert asyncio.run(view(_asgi_request())) == "ok"
    assert sink.effects == ["allow"]


@pytest.mark.parametrize("in_thread", [True, False])
def test_async_engine_thread_can_be_disabled_for_non_blocking_policies(in_thread: bool) -> None:
    threads: list[int] = []

    def record_thread(request: AuthorizationRequest) -> Decision | None:
        threads.append(threading.get_ident())
        return None

    async def subject(request: Any) -> Subject:
        return Subject("7")

    authorizer = DjangoAuthorizer(
        AuthorizationEngine([AuthenticatedPolicy(), FunctionPolicy("thread", record_thread)]),
        subject_resolver=subject,
        async_engine_in_thread=in_thread,
    )

    @authorizer.require("incident.read")
    async def view(request: Any) -> int:
        return threading.get_ident()

    loop_thread = asyncio.run(view(_asgi_request()))
    assert len(threads) == 1
    assert (threads[0] != loop_thread) is in_thread


def test_async_engine_in_thread_is_validated() -> None:
    with pytest.raises(TypeError, match="bool"):
        DjangoAuthorizer(AuthorizationEngine([]), async_engine_in_thread=1)  # type: ignore[arg-type]
