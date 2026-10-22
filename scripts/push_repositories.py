"""Push reviewed main (and an optional existing version tag) to both private destinations."""
import argparse
import re
import shlex
import subprocess
import sys
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
    identity = git("config", "--default", "", "--get",
                   "secureFirewall.githubIdentityFile", capture=True)
    github_options = []
    if identity:
        identity_path = Path(identity).expanduser().resolve()
        if not identity_path.is_file():
            raise SystemExit("Configured GitHub SSH identity file does not exist; no pushes attempted.")
        ssh = ["ssh", "-F", "/dev/null" if sys.platform != "win32" else "NUL",
               "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
               "-o", "StrictHostKeyChecking=yes", "-i", str(identity_path)]
        if sys.platform == "darwin":
            ssh += ["-o", "UseKeychain=yes"]
        github_options = ["-c", "core.sshCommand=" + shlex.join(ssh)]
    for remote in REMOTES:
        options = github_options if remote == "github" else []
        git(*options, "push", remote, "main")
        local = git("rev-parse", "HEAD", capture=True)
        observed = git(*options, "ls-remote", remote, "refs/heads/main", capture=True).split()[0]
        if observed != local:
            raise SystemExit(f"Remote {remote} tip does not match the local commit.")
        if args.release_tag:
            git(*options, "push", remote, "refs/tags/" + args.release_tag)
        print(f"Updated {remote}.")
    # The deployed schema source and every published revision have their own
    # Cisco repository. A failed backup makes the release workflow fail visibly.
    subprocess.run([sys.executable, str(ROOT / "scripts/sync_schema_repository.py")], check=True)


if __name__ == "__main__":
    main()
