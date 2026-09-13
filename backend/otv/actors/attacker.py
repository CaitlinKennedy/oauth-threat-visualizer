"""The Attacker actor.

A first-class actor in the design (DESIGN.md §3), modeled with its own service
and, where relevant, its own origin. Exposed here as a service-API interface so
later phases add real attack methods (auth-code injection, replay, phishing
chains) behind the same seam every other actor uses.

In Phase 0 the attacker is **idle**: the node is present in the diagram and the
knowledge ledger, but it takes no actions against the real endpoints.
"""

from __future__ import annotations

import abc

from ..recorder import Recorder
from .environment import Environment


class Attacker(abc.ABC):
    """Service-API interface for the adversary."""

    @abc.abstractmethod
    def is_active(self) -> bool:
        """Whether any attack is configured to run in this scenario."""


class AttackerImpl(Attacker):
    def __init__(self, recorder: Recorder, env: Environment):
        self.recorder = recorder
        self.env = env
        self.origin = "https://attacker.evil.internal"

    def is_active(self) -> bool:
        """No attacks are implemented in Phase 0."""
        return False

    # Intentionally no attack methods yet. Adding auth-code injection, replay,
    # and phishing here in later phases will emit StepEvents through the same
    # recorder and contract as every other actor, and satisfy this interface.
