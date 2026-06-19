from agentshield.guard import guard


@guard(analysis_type="tool_metadata")
def sample_tool(path: str) -> str:
    return f"ok:{path}"


def test_guard_allows_safe_tool():
    assert sample_tool("/tmp/safe.txt") == "ok:/tmp/safe.txt"