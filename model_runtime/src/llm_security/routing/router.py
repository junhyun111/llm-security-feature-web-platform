from __future__ import annotations

from typing import Protocol

from ..models import Candidate, RouteDecision


class Router(Protocol):
    """The only routing interface used by production inference."""

    def route(self, candidate: Candidate) -> RouteDecision: ...
