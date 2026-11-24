"""Exhaustive formal Operation State Machine tests + Hypothesis RuleBasedStateMachine model verification."""

from __future__ import annotations

import pytest
from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from stream_memory_manager.models import IllegalStateTransitionError, OperationState
from stream_memory_manager.state_machine import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    can_transition,
    is_terminal,
    validate_transition,
)


def test_all_324_transition_pairs_enforced_deterministically() -> None:
    """Verify every (from, to) state pair across all 18 states (324 pairs) matches the formal spec."""
    all_states = list(OperationState)
    assert len(all_states) == 18
    pairs_checked = 0
    for src in all_states:
        for dst in all_states:
            pairs_checked += 1
            if dst in ALLOWED_TRANSITIONS[src]:
                assert can_transition(src, dst) is True
                validate_transition(src, dst, op_id="op_test")
            else:
                assert can_transition(src, dst) is False
                with pytest.raises(IllegalStateTransitionError):
                    validate_transition(src, dst, op_id="op_test")
    assert pairs_checked == 324


def test_critical_safety_invariants_in_state_graph() -> None:
    # Invariant 5 & 6: UNCERTAIN_REMOTE_OUTCOME can NEVER jump directly back to dispatch/retry/cancel states!
    forbidden_from_uncertain = {
        OperationState.PLANNED,
        OperationState.APPROVED,
        OperationState.READY,
        OperationState.REQUEST_PREPARED,
        OperationState.REQUEST_IN_FLIGHT,
        OperationState.RETRY_WAIT,
        OperationState.PAUSED_AUTHORIZATION,
        OperationState.PAUSED_RATE_LIMIT,
        OperationState.CANCELLED_BEFORE_WRITE,
    }
    for bad_dst in forbidden_from_uncertain:
        assert not can_transition(OperationState.UNCERTAIN_REMOTE_OUTCOME, bad_dst)

    # Audit R1: Post-write verification pauses can NEVER transition back to READY, REQUEST_IN_FLIGHT, or CANCELLED_BEFORE_WRITE!
    for ver_pause in (
        OperationState.PAUSED_VERIFICATION_AUTH,
        OperationState.PAUSED_VERIFICATION_RATE_LIMIT,
    ):
        assert ALLOWED_TRANSITIONS[ver_pause] == frozenset(
            {
                OperationState.AWAITING_VERIFICATION,
                OperationState.BLOCKED,
            }
        )
        assert not can_transition(ver_pause, OperationState.READY)
        assert not can_transition(ver_pause, OperationState.REQUEST_IN_FLIGHT)
        assert not can_transition(ver_pause, OperationState.CANCELLED_BEFORE_WRITE)

    # Invariant 7: REQUEST_IN_FLIGHT can NEVER jump straight to VERIFIED without ack/verification!
    assert not can_transition(OperationState.REQUEST_IN_FLIGHT, OperationState.VERIFIED)

    # Terminal states have zero outgoing edges
    for term in TERMINAL_STATES:
        assert len(ALLOWED_TRANSITIONS[term]) == 0
        assert is_terminal(term)


class OperationLifecycleModel(RuleBasedStateMachine):
    """Model-based test verifying safety invariants across arbitrary event orderings (including all pause states)."""

    def __init__(self) -> None:
        super().__init__()
        self.state = OperationState.PLANNED
        self.ever_post_write = False
        self.dispatches = 0
        self.dispatches_after_post_write = 0
        self.acked_or_verified_read = False

    @initialize()
    def init_op(self) -> None:
        self.state = OperationState.PLANNED
        self.ever_post_write = False
        self.dispatches = 0
        self.dispatches_after_post_write = 0
        self.acked_or_verified_read = False

    @precondition(lambda self: can_transition(self.state, OperationState.APPROVED))
    @rule()
    def approve(self) -> None:
        validate_transition(self.state, OperationState.APPROVED)
        self.state = OperationState.APPROVED

    @precondition(lambda self: can_transition(self.state, OperationState.READY))
    @rule()
    def mark_ready(self) -> None:
        validate_transition(self.state, OperationState.READY)
        self.state = OperationState.READY

    @precondition(lambda self: can_transition(self.state, OperationState.REQUEST_PREPARED))
    @rule()
    def prepare(self) -> None:
        validate_transition(self.state, OperationState.REQUEST_PREPARED)
        self.state = OperationState.REQUEST_PREPARED

    @precondition(lambda self: can_transition(self.state, OperationState.REQUEST_IN_FLIGHT))
    @rule()
    def dispatch(self) -> None:
        validate_transition(self.state, OperationState.REQUEST_IN_FLIGHT)
        self.dispatches += 1
        if self.ever_post_write:
            self.dispatches_after_post_write += 1
        self.state = OperationState.REQUEST_IN_FLIGHT

    @precondition(lambda self: can_transition(self.state, OperationState.UNCERTAIN_REMOTE_OUTCOME))
    @rule()
    def network_drop_or_crash(self) -> None:
        validate_transition(self.state, OperationState.UNCERTAIN_REMOTE_OUTCOME)
        self.ever_post_write = True
        self.state = OperationState.UNCERTAIN_REMOTE_OUTCOME

    @precondition(lambda self: can_transition(self.state, OperationState.ACKNOWLEDGED))
    @rule()
    def receive_ack(self) -> None:
        validate_transition(self.state, OperationState.ACKNOWLEDGED)
        self.ever_post_write = True
        self.acked_or_verified_read = True
        self.state = OperationState.ACKNOWLEDGED

    @precondition(lambda self: can_transition(self.state, OperationState.AWAITING_VERIFICATION))
    @rule()
    def await_verify(self) -> None:
        validate_transition(self.state, OperationState.AWAITING_VERIFICATION)
        self.ever_post_write = True
        self.acked_or_verified_read = True
        self.state = OperationState.AWAITING_VERIFICATION

    @precondition(lambda self: can_transition(self.state, OperationState.RETRY_WAIT))
    @rule()
    def confirmed_rate_limit_retry_wait(self) -> None:
        validate_transition(self.state, OperationState.RETRY_WAIT)
        self.state = OperationState.RETRY_WAIT

    @precondition(lambda self: can_transition(self.state, OperationState.PAUSED_AUTHORIZATION))
    @rule()
    def pause_auth_pre_write(self) -> None:
        validate_transition(self.state, OperationState.PAUSED_AUTHORIZATION)
        self.state = OperationState.PAUSED_AUTHORIZATION

    @precondition(lambda self: can_transition(self.state, OperationState.PAUSED_RATE_LIMIT))
    @rule()
    def pause_rate_limit_pre_write(self) -> None:
        validate_transition(self.state, OperationState.PAUSED_RATE_LIMIT)
        self.state = OperationState.PAUSED_RATE_LIMIT

    @precondition(lambda self: can_transition(self.state, OperationState.PAUSED_VERIFICATION_AUTH))
    @rule()
    def pause_auth_post_write(self) -> None:
        validate_transition(self.state, OperationState.PAUSED_VERIFICATION_AUTH)
        self.ever_post_write = True
        self.state = OperationState.PAUSED_VERIFICATION_AUTH

    @precondition(
        lambda self: can_transition(self.state, OperationState.PAUSED_VERIFICATION_RATE_LIMIT)
    )
    @rule()
    def pause_rate_limit_post_write(self) -> None:
        validate_transition(self.state, OperationState.PAUSED_VERIFICATION_RATE_LIMIT)
        self.ever_post_write = True
        self.state = OperationState.PAUSED_VERIFICATION_RATE_LIMIT

    @precondition(lambda self: can_transition(self.state, OperationState.VERIFIED))
    @rule()
    def verify_remote(self) -> None:
        validate_transition(self.state, OperationState.VERIFIED)
        self.state = OperationState.VERIFIED

    @precondition(lambda self: can_transition(self.state, OperationState.BLOCKED))
    @rule()
    def block(self) -> None:
        validate_transition(self.state, OperationState.BLOCKED)
        self.state = OperationState.BLOCKED

    @precondition(lambda self: can_transition(self.state, OperationState.CONFLICTED))
    @rule()
    def conflict(self) -> None:
        validate_transition(self.state, OperationState.CONFLICTED)
        self.state = OperationState.CONFLICTED

    @precondition(lambda self: can_transition(self.state, OperationState.FAILED_CONFIRMED))
    @rule()
    def fail_confirmed(self) -> None:
        validate_transition(self.state, OperationState.FAILED_CONFIRMED)
        self.state = OperationState.FAILED_CONFIRMED

    @precondition(lambda self: can_transition(self.state, OperationState.CANCELLED_BEFORE_WRITE))
    @rule()
    def cancel(self) -> None:
        validate_transition(self.state, OperationState.CANCELLED_BEFORE_WRITE)
        self.state = OperationState.CANCELLED_BEFORE_WRITE

    @precondition(lambda self: is_terminal(self.state))
    @rule()
    def assert_terminal_stays_terminal(self) -> None:
        for dst in OperationState:
            assert not can_transition(self.state, dst)

    @invariant()
    def no_blind_redispatch_after_post_write_or_uncertainty(self) -> None:
        # Once acknowledged, awaiting verification, paused in verification, or uncertain,
        # the state machine NEVER allows another write dispatch — not even in 2+ hops!
        assert self.dispatches_after_post_write == 0

    @invariant()
    def no_cancel_before_write_after_post_write(self) -> None:
        if self.ever_post_write:
            assert self.state != OperationState.CANCELLED_BEFORE_WRITE

    @invariant()
    def verified_requires_ack_or_verification_step(self) -> None:
        if self.state == OperationState.VERIFIED:
            assert self.acked_or_verified_read


TestOperationStateMachine = OperationLifecycleModel.TestCase
TestOperationStateMachine.settings = settings(
    max_examples=200, stateful_step_count=35, derandomize=True
)
