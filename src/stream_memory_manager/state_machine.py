"""Explicit formal Operation State Machine with strict transition enforcement.

Enforces Invariants 4 (Journaling), 5 (Ambiguity), 6 (Duplicate prevention), and 7 (Verification).
"""

from __future__ import annotations

from stream_memory_manager.models import (
    IllegalStateTransitionError,
    OperationState,
)

# Exhaustive directed graph of legal state transitions.
# CRITICAL SAFETY PROPERTIES:
# 1. `UNCERTAIN_REMOTE_OUTCOME` can NEVER transition directly to `READY`, `RETRY_WAIT`,
#    `REQUEST_PREPARED`, or `REQUEST_IN_FLIGHT` (blocks blind retry of ambiguous writes!).
#    It may ONLY transition to `AWAITING_VERIFICATION` (evidence lookup), `VERIFIED`
#    (unambiguous remote adoption), `CONFLICTED`, or `BLOCKED`.
# 2. `REQUEST_IN_FLIGHT` can NEVER transition straight to `VERIFIED` without going through
#    `ACKNOWLEDGED` or `AWAITING_VERIFICATION` (distinguishes ack from verification!).
# 3. Terminal states (`VERIFIED`, `FAILED_CONFIRMED`, `CANCELLED_BEFORE_WRITE`) have zero outgoing edges.
ALLOWED_TRANSITIONS: dict[OperationState, frozenset[OperationState]] = {
    OperationState.PLANNED: frozenset(
        {
            OperationState.APPROVED,
            OperationState.BLOCKED,
            OperationState.CONFLICTED,
            OperationState.CANCELLED_BEFORE_WRITE,
        }
    ),
    OperationState.APPROVED: frozenset(
        {
            OperationState.READY,
            OperationState.BLOCKED,
            OperationState.CONFLICTED,
            OperationState.PAUSED_AUTHORIZATION,
            OperationState.CANCELLED_BEFORE_WRITE,
        }
    ),
    OperationState.READY: frozenset(
        {
            OperationState.REQUEST_PREPARED,
            OperationState.PAUSED_AUTHORIZATION,
            OperationState.PAUSED_RATE_LIMIT,
            OperationState.BLOCKED,
            OperationState.CONFLICTED,
            OperationState.FAILED_CONFIRMED,
            OperationState.CANCELLED_BEFORE_WRITE,
        }
    ),
    OperationState.REQUEST_PREPARED: frozenset(
        {
            OperationState.REQUEST_IN_FLIGHT,
            OperationState.READY,  # Allowed ONLY if crash/abort happened strictly before socket dispatch
            OperationState.RETRY_WAIT,
            OperationState.PAUSED_AUTHORIZATION,
            OperationState.PAUSED_RATE_LIMIT,
            OperationState.FAILED_CONFIRMED,
            OperationState.BLOCKED,
            OperationState.CANCELLED_BEFORE_WRITE,
        }
    ),
    OperationState.REQUEST_IN_FLIGHT: frozenset(
        {
            OperationState.ACKNOWLEDGED,
            OperationState.UNCERTAIN_REMOTE_OUTCOME,
            OperationState.RETRY_WAIT,  # ONLY for confirmed pre-commit rejection (e.g. HTTP 429)
            OperationState.PAUSED_AUTHORIZATION,  # ONLY for confirmed HTTP 401 before commit
            OperationState.PAUSED_RATE_LIMIT,  # ONLY for confirmed HTTP 429 / tool rate-limit before commit
            OperationState.CONFLICTED,
            OperationState.FAILED_CONFIRMED,  # ONLY for confirmed server-side validation rejection
        }
    ),
    OperationState.ACKNOWLEDGED: frozenset(
        {
            OperationState.AWAITING_VERIFICATION,
            OperationState.VERIFIED,  # Allowed ONLY after explicit postcondition verification helper succeeds
            OperationState.CONFLICTED,
            OperationState.BLOCKED,
        }
    ),
    OperationState.AWAITING_VERIFICATION: frozenset(
        {
            OperationState.VERIFIED,
            OperationState.AWAITING_VERIFICATION,  # Bounded re-check during indexing lag
            OperationState.PAUSED_VERIFICATION_AUTH,
            OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
            OperationState.UNCERTAIN_REMOTE_OUTCOME,
            OperationState.CONFLICTED,
            OperationState.BLOCKED,
        }
    ),
    OperationState.RETRY_WAIT: frozenset(
        {
            OperationState.READY,
            OperationState.PAUSED_AUTHORIZATION,
            OperationState.PAUSED_RATE_LIMIT,
            OperationState.BLOCKED,
            OperationState.FAILED_CONFIRMED,
            OperationState.CANCELLED_BEFORE_WRITE,
        }
    ),
    OperationState.PAUSED_AUTHORIZATION: frozenset(
        {
            OperationState.READY,
            OperationState.BLOCKED,
            OperationState.CANCELLED_BEFORE_WRITE,
        }
    ),
    OperationState.PAUSED_RATE_LIMIT: frozenset(
        {
            OperationState.READY,
            OperationState.BLOCKED,
            OperationState.CANCELLED_BEFORE_WRITE,
        }
    ),
    # Dedicated post-write verification pause states: can NEVER return to READY or CANCELLED_BEFORE_WRITE!
    OperationState.PAUSED_VERIFICATION_AUTH: frozenset(
        {
            OperationState.AWAITING_VERIFICATION,
            OperationState.BLOCKED,
        }
    ),
    OperationState.PAUSED_VERIFICATION_RATE_LIMIT: frozenset(
        {
            OperationState.AWAITING_VERIFICATION,
            OperationState.BLOCKED,
        }
    ),
    OperationState.UNCERTAIN_REMOTE_OUTCOME: frozenset(
        {
            OperationState.AWAITING_VERIFICATION,
            OperationState.CONFLICTED,
            OperationState.BLOCKED,
        }
    ),
    OperationState.CONFLICTED: frozenset(
        {
            OperationState.BLOCKED,
        }
    ),
    OperationState.BLOCKED: frozenset(
        {
            OperationState.AWAITING_VERIFICATION,
            OperationState.CONFLICTED,
        }
    ),
    OperationState.VERIFIED: frozenset(),
    OperationState.FAILED_CONFIRMED: frozenset(),
    OperationState.CANCELLED_BEFORE_WRITE: frozenset(),
}

TERMINAL_STATES: frozenset[OperationState] = frozenset(
    {
        OperationState.VERIFIED,
        OperationState.FAILED_CONFIRMED,
        OperationState.CANCELLED_BEFORE_WRITE,
    }
)

BLOCKING_STATES: frozenset[OperationState] = frozenset(
    {
        OperationState.UNCERTAIN_REMOTE_OUTCOME,
        OperationState.CONFLICTED,
        OperationState.BLOCKED,
        OperationState.PAUSED_AUTHORIZATION,
        OperationState.PAUSED_RATE_LIMIT,
        OperationState.PAUSED_VERIFICATION_AUTH,
        OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
    }
)

PRE_WRITE_CANCELLABLE_STATES: frozenset[OperationState] = frozenset(
    {
        OperationState.PLANNED,
        OperationState.APPROVED,
        OperationState.READY,
        OperationState.REQUEST_PREPARED,
        OperationState.RETRY_WAIT,
        OperationState.PAUSED_AUTHORIZATION,
        OperationState.PAUSED_RATE_LIMIT,
    }
)


def can_transition(current: OperationState, target: OperationState) -> bool:
    return target in ALLOWED_TRANSITIONS[current]


def validate_transition(
    current: OperationState, target: OperationState, *, op_id: str = ""
) -> None:
    """Assert that transitioning `current -> target` obeys the formal state machine."""
    if not can_transition(current, target):
        raise IllegalStateTransitionError(
            f"Illegal operation state transition for {op_id or '<op>'}: "
            f"{current.value} -> {target.value}",
            details={"op_id": op_id, "from_state": current.value, "to_state": target.value},
        )


def is_terminal(state: OperationState) -> bool:
    return state in TERMINAL_STATES


def is_blocking(state: OperationState) -> bool:
    return state in BLOCKING_STATES
