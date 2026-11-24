"""OAuth 2.1 token storage, automatic silent refresh, fail-closed interactive re-auth, and revocation tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl

from stream_memory_manager.auth import (
    SecureTokenStorage,
    revoke_and_disconnect,
)
from stream_memory_manager.clock import FakeClock
from stream_memory_manager.db import Database
from stream_memory_manager.mcp_adapter import SandbarMCPAdapter
from stream_memory_manager.mock_server import MockSandbarState, MockServerConfig, RunningMockServer
from stream_memory_manager.models import AuthorizationRequiredError
from stream_memory_manager.rate_limit import AccountRateScheduler


@pytest.mark.asyncio
async def test_oauth_silent_refresh_fail_closed_reauth_and_revocation(
    tmp_db: Database, tmp_path: Path, fake_clock: FakeClock
) -> None:
    state = MockSandbarState(MockServerConfig())
    with RunningMockServer(state) as srv:
        cred_dir = tmp_path / "creds"
        storage = SecureTokenStorage(
            profile="oauth_test",
            server_url=srv.mcp_url,
            fallback_dir=cred_dir,
            use_keyring=False,
        )
        # Seed registered client + valid token pair from mock server
        tok_data = srv.state.issue_token("acct_primary")
        await storage.set_client_info(
            OAuthClientInformationFull(
                client_id="client_mock_01",
                redirect_uris=[AnyUrl("http://127.0.0.1:0/callback")],
                token_endpoint_auth_method="none",
                issuer=srv.state.base_url,
            )
        )
        await storage.set_tokens(OAuthToken.model_validate(tok_data))

        # Verify restricted file permissions (0600) on fallback credential files
        for f in cred_dir.iterdir():
            assert (os.stat(f).st_mode & 0o777) == 0o600

        sched = AccountRateScheduler(
            tmp_db, "acct_primary", min_interval_seconds=0.1, clock=fake_clock
        )
        adapter = SandbarMCPAdapter(
            server_url=srv.mcp_url,
            scheduler=sched,
            storage=storage,
            allow_localhost_http=True,
        )

        # 1. Initial discovery works
        caps = await adapter.discover_capabilities()
        assert caps.supports_create_log

        # 2. Expire ONLY access token -> OAuthClientProvider silently refreshes via /token and succeeds!
        srv.state.expire_all_access_tokens()
        folders = await adapter.list_folders()
        assert isinstance(folders, list)
        refreshed_tokens = await storage.get_tokens()
        assert refreshed_tokens is not None
        assert refreshed_tokens.access_token != tok_data["access_token"]

        # 3. Expire BOTH access + refresh tokens -> non-interactive execution FAILS CLOSED!
        srv.state.expire_all_access_tokens()
        srv.state.expire_all_refresh_tokens()
        with pytest.raises(AuthorizationRequiredError):
            await adapter.list_folders()

        # 4. Revoke & disconnect calls /revoke and removes local credential files
        res = await revoke_and_disconnect(
            storage=storage,
            revocation_url=f"{srv.state.base_url}/revoke",
            allow_localhost_http=True,
        )
        assert res["disconnected"] is True
        assert res["revoked_remotely"] is True
        assert await storage.get_tokens() is None
        assert await storage.get_client_info() is None
