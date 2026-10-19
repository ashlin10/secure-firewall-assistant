"""Push reviewed main (and an optional existing version tag) to both private destinations."""
import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REMOTES = {
    "origin": "git@wwwin-github.cisco.com:aleroyds/secure-firewall-assistant.git",
    "github": "git@github.com:ashlin10/secure-firewall-assistant.git",
}


def git(*args, capture=False):
    result = subprocess.run(["git", *args], cwd=ROOT, check=True, text=True,
                            capture_output=capture)
    return result.stdout.strip() if capture else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-tag", help="Push this existing vX.Y.Z tag along with main")
    args = parser.parse_args()
    if git("branch", "--show-current", capture=True) != "main":
        raise SystemExit("Switch to the reviewed main branch before synchronizing repositories.")
    if git("status", "--porcelain", capture=True):
        raise SystemExit("Commit or set aside local changes before synchronizing repositories.")
    if args.release_tag:
        if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", args.release_tag):
            raise SystemExit("Supply an existing version tag such as v0.1.0.")
        git("rev-parse", "--verify", "refs/tags/" + args.release_tag)
    for remote, expected in REMOTES.items():
        if git("remote", "get-url", "--push", remote, capture=True) != expected:
            raise SystemExit(f"Remote {remote} differs from the documented destination; no pushes attempted.")
    for remote in REMOTES:
        git("push", remote, "main")
        if args.release_tag:
            git("push", remote, "refs/tags/" + args.release_tag)
        print(f"Updated {remote}.")


if __name__ == "__main__":
    main()
