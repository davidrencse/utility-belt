import subprocess

from stegkit import gitsteg


def test_git_whitespace_round_trip(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Steg Test"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "steg@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "--allow-empty", "-m", "initial"],
        check=True,
        capture_output=True,
    )
    gitsteg.encode_whitespace(tmp_path, b"git secret", "key")
    assert gitsteg.decode_whitespace(tmp_path, "key") == b"git secret"
