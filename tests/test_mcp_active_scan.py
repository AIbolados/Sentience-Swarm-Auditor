import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import mcp_server  # noqa: E402


def test_mcp_server_registers_active_security_scan_tool():
    tool_names = {t.name for t in mcp_server.mcp._tool_manager._tools.values()}
    assert "active_security_scan" in tool_names


@pytest.mark.asyncio
async def test_active_security_scan_tool_rejects_without_confirmation():
    result = await mcp_server.active_security_scan(
        target="http://localhost:9999",
        environment="local_staging",
    )
    assert "error" in result
    assert "confirm_own_target" in result["error"]


@pytest.mark.asyncio
async def test_active_security_scan_tool_rejects_production_without_second_confirmation():
    result = await mcp_server.active_security_scan(
        target="https://miapp.com",
        environment="production",
        confirm_own_target=True,
    )
    assert "error" in result
    assert "confirm_production_risk" in result["error"]


@pytest.mark.asyncio
async def test_active_security_scan_tool_rejects_invalid_environment():
    result = await mcp_server.active_security_scan(
        target="http://localhost:9999",
        environment="not-a-real-environment",
        confirm_own_target=True,
    )
    assert "error" in result
