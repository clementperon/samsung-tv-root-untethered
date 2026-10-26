"""Offline coverage of actions inside an authenticated archive-root session."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from samsung_tv_root import archive_root
from samsung_tv_root.root_agent import RootAgentResult
from samsung_tv_root.sdb import CaptureResult


@pytest.fixture
def session(monkeypatch, tmp_path):
    events = []
    identity = SimpleNamespace(
        uid=0,
        euid=0,
        gid=0,
        egid=0,
        effective_capabilities="0000003fffffffff",
        smack_label="User",
    )

    async def execute(command, timeout):
        events.append("command")
        return RootAgentResult(1, 0, False, "result\n", "")

    async def shutdown():
        events.append("shutdown")

    connection = SimpleNamespace(
        ping=AsyncMock(return_value=identity),
        execute=AsyncMock(side_effect=execute),
        shutdown=AsyncMock(side_effect=shutdown),
    )
    server = SimpleNamespace(
        secret=b"x" * 32,
        listening_port=12345,
        start=AsyncMock(),
        accept=AsyncMock(return_value=connection),
        close=AsyncMock(),
    )
    client = Mock()
    client.capture.return_value = CaptureResult("\n[exit:0]\n", 0)
    client_factory = Mock(return_value=client)
    cleanup = Mock(return_value=True)
    monkeypatch.setattr(archive_root, "SdbClient", client_factory)
    monkeypatch.setattr(archive_root, "find_sdb", lambda: Path("unused-sdb"))
    monkeypatch.setattr(archive_root, "RootAgentServer", Mock(return_value=server))
    monkeypatch.setattr(
        archive_root,
        "_check_target",
        Mock(
            return_value=archive_root.TargetAssessment("capabilities", "hashes", "6.0")
        ),
    )
    monkeypatch.setattr(archive_root, "_prepare_artifacts", Mock())
    monkeypatch.setattr(archive_root, "_stage", Mock())
    monkeypatch.setattr(archive_root, "_cleanup", cleanup)
    monkeypatch.setattr(archive_root, "_capture", Mock(return_value="hashes"))
    for name in archive_root.PAYLOAD_FILES:
        (tmp_path / name).touch()

    async def run(**kwargs):
        return await archive_root.probe(
            "192.0.2.50", callback_host="192.0.2.10", payloads=tmp_path, **kwargs
        )

    return SimpleNamespace(
        run=run,
        connection=connection,
        server=server,
        client=client,
        client_factory=client_factory,
        cleanup=cleanup,
        events=events,
    )


def assert_cleaned(session):
    session.connection.shutdown.assert_awaited_once()
    session.server.close.assert_awaited_once()
    session.cleanup.assert_called_once()
    session.client.disconnect.assert_called_once()


def test_action_uses_connection_before_commands_and_extends_transport(session):
    async def action(connection):
        assert connection is session.connection
        session.events.append("action")
        await connection.ping()

    evidence = asyncio.run(
        session.run(
            session_action=action,
            session_timeout=90,
            commands=("read-result",),
        )
    )

    assert session.events == ["action", "command", "shutdown"]
    assert session.client.capture.call_args.kwargs["timeout"] == 140
    assert evidence["authenticated"] is True
    assert evidence["commands"][0]["stdout"] == "result\n"
    assert evidence["system_files_unchanged"] is True
    assert evidence["staging_cleaned"] is True
    assert_cleaned(session)


def test_without_action_preserves_transport_timeout(session):
    asyncio.run(session.run(commands=("read-result",)))
    assert session.events == ["command", "shutdown"]
    assert session.client.capture.call_args.kwargs["timeout"] == 50
    assert_cleaned(session)


def test_action_failure_propagates_after_cleanup(session):
    async def action(connection):
        raise RuntimeError("action failed")

    with pytest.raises(RuntimeError, match="action failed"):
        asyncio.run(session.run(session_action=action, commands=("must-not-run",)))

    session.connection.execute.assert_not_awaited()
    assert_cleaned(session)


def test_action_timeout_cancels_action_and_cleans_up(session):
    cancelled = []

    async def action(connection):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    with pytest.raises(TimeoutError):
        asyncio.run(session.run(session_action=action, session_timeout=0.01))

    assert cancelled == [True]
    assert_cleaned(session)


@pytest.mark.parametrize("timeout", [0, -1, 7201, float("inf"), float("nan")])
def test_invalid_timeout_fails_before_connecting(session, timeout):
    with pytest.raises(ValueError, match="session_timeout"):
        asyncio.run(session.run(session_timeout=timeout))
    session.client_factory.assert_not_called()


def test_action_success_does_not_hide_cleanup_failure(session):
    session.cleanup.return_value = False
    action = AsyncMock()
    with pytest.raises(archive_root.ArchiveRootError, match="cleanup checks failed"):
        asyncio.run(session.run(session_action=action))
    action.assert_awaited_once_with(session.connection)
    assert_cleaned(session)
