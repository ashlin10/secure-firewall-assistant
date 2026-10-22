"""Snapshot deployed schema service source/catalogs and push its separate Cisco repository.

Uses existing SSH authentication only. Never copies virtual environments, credentials,
device inventory, evidence, logs, or machine-specific Codex configuration.
"""
import argparse
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REMOTE = "git@wwwin-github.cisco.com:aleroyds/secure-firewall-schema-service.git"
HOST = "admin@10.196.150.41"

# Fixed selection on the schema host; no shell interpolation of remote paths.
SNAPSHOT = r'''
import io, pathlib, sys, tarfile
root = pathlib.Path('/opt/secure-firewall-schema-service')
registry = pathlib.Path('/var/lib/secure-firewall-schemas')
top = {'plugin.json', 'mcp.json', '.mcp.json', 'pyproject.toml', 'uv.lock', '.python-version',
       'README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'NOTICE.md',
       'Install.command', 'Manage.command', 'Install.ps1', 'Manage.ps1', 'devices.example.yaml'}
directories = {'src', 'scripts', 'deployment', 'docs', 'skills', '.codex-plugin'}
excluded = {'__pycache__', '.venv', '.git', '.pytest_cache', '.ruff_cache', 'private', 'evidence'}
if not (root / 'pyproject.toml').is_file() or not (registry / 'index.json').is_file():
    raise RuntimeError('Schema runtime or published registry is missing')
def selected():
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if any(part in excluded for part in rel.parts):
            continue
        if rel.parts[0] not in directories and rel.as_posix() not in top:
            continue
        if path.is_symlink():
            raise RuntimeError('Unexpected symlink in schema runtime')
        if not path.is_file():
            continue
        if path.name in {'devices.yaml', 'inventory.json', '.env', 'installation.json'} or path.suffix in {'.pyc', '.log', '.key', '.pem'} or path.name.startswith('.sfa-'):
            raise RuntimeError('Private/generated file in schema runtime selection')
        yield path, 'runtime/' + rel.as_posix()
    for path in sorted(registry.iterdir()):
        if path.name in {'index.json', 'revisions.json'} or path.name.endswith('.json.gz'):
            if path.is_symlink() or not path.is_file():
                raise RuntimeError('Unexpected schema registry entry')
            yield path, 'registry/' + path.name
    unit = pathlib.Path('/etc/systemd/system/secure-firewall-schemas.service')
    yield unit, 'deployment/secure-firewall-schemas.service'
    drops = unit.with_name(unit.name + '.d')
    if drops.exists() and any(drops.iterdir()):
        raise RuntimeError('Review systemd drop-ins before extending the snapshot selection')
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as archive:
    for path, name in selected():
        data = path.read_bytes()
        item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o644
        archive.addfile(item, io.BytesIO(data))
'''


def git(repository, *args, capture=False):
    result = subprocess.run(["git", "-C", str(repository), *args], check=True,
                            text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def unpack_snapshot(raw, destination):
    """Validate archive names/types before writing any snapshot files."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            path = Path(member.name)
            if (not member.isfile() or path.is_absolute() or ".." in path.parts or
                    not path.parts or path.parts[0] not in {"runtime", "registry", "deployment"} or
                    member.name in files or member.size > 64 * 1024 * 1024):
                raise RuntimeError("Unexpected entry in remote schema snapshot")
            files[member.name] = archive.extractfile(member).read()
    if not {"runtime/pyproject.toml", "registry/index.json", "deployment/secure-firewall-schemas.service"} <= files.keys():
        raise RuntimeError("Incomplete remote schema snapshot")
    index = json.loads(files["registry/index.json"])
    history = json.loads(files.get("registry/revisions.json", b"{}"))
    checksums = {entry["sha256"] for entry in index["schemas"]} | set(history.values())
    for checksum in checksums:
        data = files.get(f"registry/{checksum}.json.gz")
        if data is None or hashlib.sha256(data).hexdigest() != checksum:
            raise RuntimeError("Remote schema history is incomplete or corrupt")
    for folder in ("runtime", "registry", "deployment"):
        if (destination / folder).is_symlink():
            raise RuntimeError("Snapshot destination contains a symlink")
    for folder in ("runtime", "registry", "deployment"):
        shutil.rmtree(destination / folder, ignore_errors=True)
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    manifest = {"format_version": 1, "files": {name: hashlib.sha256(data).hexdigest()
                                               for name, data in sorted(files.items())}}
    (destination / "snapshot.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def sync(repository, host=HOST, control_path=None):
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes"]
    if control_path:
        ssh += ["-S", str(control_path)]
    # Fetch the complete deployed snapshot before creating/changing the local checkout.
    result = subprocess.run([*ssh, host, "python3 -c " + shlex.quote(SNAPSHOT)],
                            capture_output=True, check=True)
    if not (repository / ".git").exists():
        if repository.exists() and any(repository.iterdir()):
            raise RuntimeError("Schema repository directory must be empty or an existing checkout")
        subprocess.run(["git", "clone", REMOTE, str(repository)], check=True)
    if git(repository, "remote", "get-url", "--push", "origin", capture=True) != REMOTE:
        raise RuntimeError("Schema repository origin differs from the required Cisco destination")
    if git(repository, "status", "--porcelain", capture=True):
        raise RuntimeError("Commit or preserve existing schema repository work before synchronizing")
    git(repository, "fetch", "origin")
    if git(repository, "ls-remote", "origin", "refs/heads/main", capture=True):
        git(repository, "checkout", "main")
        git(repository, "merge", "--ff-only", "origin/main")
    else:
        git(repository, "checkout", "-B", "main")
    manifest = unpack_snapshot(result.stdout, repository)
    (repository / "README.md").write_text(
        "# Secure Firewall schema MCP service\n\n"
        "Deployed source, actual systemd unit, and all published schema packages and revision history.\n"
        "`snapshot.json` records SHA-256 checksums of every captured file.\n\n"
        "Maintained by `scripts/sync_schema_repository.py` in the Secure Firewall Assistant repository.\n"
        "Run that script after every server code, unit, or schema publication change. The plugin release\n"
        "push workflow invokes it automatically. Restore runtime/ and registry/ to their documented\n"
        "service directories, prepare dependencies with uv, and install the captured systemd unit.\n"
        "Virtual environments, credentials, private inventory, caches, and logs are excluded.\n")
    (repository / "AGENTS.md").write_text(
        "# Working instructions\n\n"
        "This repository is a verified snapshot of the deployed schema MCP service.\n"
        "Implement changes in the Secure Firewall Assistant source repository, test and deploy them,\n"
        "then run scripts/sync_schema_repository.py there before reporting completion.\n"
        "Every code, service configuration, or registry publication change requires a new snapshot\n"
        "commit and a push here. Never commit credentials, device inventory, evidence, or caches.\n"
        "Preserve remote history; never force-push.\n")
    git(repository, "add", "runtime", "registry", "deployment", "snapshot.json", "README.md", "AGENTS.md")
    if git(repository, "diff", "--cached", "--name-only", capture=True):
        git(repository, "commit", "-m", "Synchronize deployed schema MCP source and published registry")
    git(repository, "push", "origin", "main")
    local = git(repository, "rev-parse", "HEAD", capture=True)
    remote = git(repository, "ls-remote", "origin", "refs/heads/main", capture=True).split()[0]
    if local != remote:
        raise RuntimeError("Schema repository remote tip does not match the local snapshot")
    print(json.dumps({"repository": REMOTE, "commit": local, "captured_files": len(manifest["files"])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT.parent / "secure-firewall-schema-service")
    parser.add_argument("--host", default=HOST)
    configured = git(ROOT, "config", "--default", "", "--get", "secureFirewall.schemaSshControlPath", capture=True)
    parser.add_argument("--control-path", default=os.environ.get("SFA_SCHEMA_SSH_CONTROL_PATH") or configured or None)
    args = parser.parse_args()
    sync(args.repository.resolve(), args.host, args.control_path)


if __name__ == "__main__":
    main()
