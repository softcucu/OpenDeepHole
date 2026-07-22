from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from deephole_client import git_history


def test_git_history_commands_use_utf8_replace(tmp_path: Path) -> None:
    calls: list[tuple[list[str], dict]] = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["encoding"] == "utf-8"
        assert kwargs["errors"] == "replace"
        if cmd[3] == "rev-parse":
            return CompletedProcess(cmd, 0, stdout="true\n", stderr="")
        if cmd[3] == "log":
            return CompletedProcess(cmd, 0, stdout="abc123\x1ffix out-of-bounds read\n", stderr="")
        if cmd[3] == "show" and "--stat" in cmd:
            return CompletedProcess(cmd, 0, stdout="fix out-of-bounds read\n file.c | 2 +-\n", stderr="")
        if cmd[3] == "show":
            return CompletedProcess(cmd, 0, stdout="diff --git a/file.c b/file.c\n", stderr="")
        raise AssertionError(f"unexpected git command: {cmd}")

    with patch("deephole_client.git_history.subprocess.run", side_effect=fake_run):
        assert git_history.is_git_repo(tmp_path) is True
        commits = git_history.collect_commits(tmp_path, max_commits=1)
        diff = git_history._commit_diff(tmp_path, "abc123")

    assert commits == [git_history._Commit(hash="abc123", subject="fix out-of-bounds read")]
    assert "fix out-of-bounds read" in diff
    assert "----- diff -----" in diff
    assert [cmd[3] for cmd, _kwargs in calls] == ["rev-parse", "log", "show", "show"]
