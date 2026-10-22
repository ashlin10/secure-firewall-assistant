"""Versioned schema packages shared by the remote MCP and the local validator.

Only FMC software versions cross this boundary. Device inventory, API bodies,
credentials and evidence never leave the local execution helper.
"""
import base64
import gzip
import hashlib
import io
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

import httpx
from filelock import FileLock

from .catalog import Catalog
from .errors import AssistantError
from .state import atomic_json

DEFAULT_SCHEMA_MCP_URL = "http://10.196.150.41:8765/mcp"
MAX_PACKAGE = 8 * 1024 * 1024
MAX_DOCUMENT = 32 * 1024 * 1024


def version_key(version):
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:\s|$)", version)
    if not match:
        raise AssistantError("schema_version_invalid", "Use a numeric FMC version with up to four components.")
    return tuple(int(part or 0) for part in match.groups())


def decode_package(package):
    try:
        if len(package["gzip_base64"]) > MAX_PACKAGE * 2:
            raise ValueError
        packed = base64.b64decode(package["gzip_base64"], validate=True)
        if len(packed) > MAX_PACKAGE or hashlib.sha256(packed).hexdigest() != package["sha256"]:
            raise ValueError
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
            raw = stream.read(MAX_DOCUMENT + 1)
        if len(raw) > MAX_DOCUMENT:
            raise ValueError
        document = json.loads(raw)
        if not isinstance(document.get("paths"), dict) or not isinstance(document.get("components"), dict):
            raise ValueError
        version_key(package["schema_version"])
        if not isinstance(package["revision"], str) or not package["revision"]:
            raise ValueError
        return document
    except (KeyError, TypeError, ValueError, OSError, EOFError):
        raise AssistantError("schema_package_invalid", "The schema package is invalid or failed its checksum.") from None


class SchemaRegistry:
    """Read-only file-backed registry. Publishing is an administrative operation."""

    def __init__(self, directory):
        self.directory = Path(directory)

    def versions(self):
        try:
            entries = json.loads((self.directory / "index.json").read_text())["schemas"]
            if not entries or len({version_key(e["version"]) for e in entries}) != len(entries):
                raise ValueError
            for entry in entries:
                version_key(entry["version"])
                if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                    raise ValueError
                if not isinstance(entry["revision"], str) or not entry["revision"]:
                    raise ValueError
            return sorted(entries, key=lambda e: version_key(e["version"]))
        except (OSError, ValueError, KeyError, TypeError):
            raise AssistantError("schema_registry_invalid", "No valid published schema index is available.") from None

    def resolve(self, fmc_version=""):
        entries = self.versions()
        requested = version_key(fmc_version) if fmc_version else None
        exact = next((e for e in entries if version_key(e["version"]) == requested), None)
        selected = exact or entries[-1]
        return {"requested_fmc_version": fmc_version, "schema_version": selected["version"],
                "revision": selected["revision"], "sha256": selected["sha256"],
                "selection": "exact" if exact else "latest_fallback" if fmc_version else "latest",
                "compatibility_verified": False}

    def package(self, fmc_version=""):
        metadata = self.resolve(fmc_version)
        try:
            packed = (self.directory / (metadata["sha256"] + ".json.gz")).read_bytes()
        except OSError:
            raise AssistantError("schema_package_missing", "The selected published schema package is missing.") from None
        package = {**metadata, "gzip_base64": base64.b64encode(packed).decode()}
        decode_package(package)
        return package

    def catalog(self, fmc_version=""):
        package = self.package(fmc_version)
        catalog = Catalog(decode_package(package))
        catalog.provenance = {k: v for k, v in package.items() if k != "gzip_base64"}
        return catalog


def publish_json(path, value):
    """Atomic public metadata without changing a shared registry's permissions."""
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".schema-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def publish(directory, schema_path, version, revision):
    version = ".".join(map(str, version_key(version)))
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", revision):
        raise AssistantError("schema_revision_invalid", "Use a simple immutable schema revision identifier.")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    raw = Path(schema_path).read_bytes()
    if not str(schema_path).endswith(".gz"):
        raw = gzip.compress(raw, mtime=0)
    sha = hashlib.sha256(raw).hexdigest()
    decode_package({"gzip_base64": base64.b64encode(raw).decode(), "sha256": sha,
                    "schema_version": version, "revision": revision})
    with FileLock(str(directory / "publish.lock"), timeout=20):
        index_path = directory / "index.json"
        entries = json.loads(index_path.read_text())["schemas"] if index_path.exists() else []
        history_path = directory / "revisions.json"
        history = json.loads(history_path.read_text()) if history_path.exists() else {}
        key = f"{version}/{revision}"
        if key in history and history[key] != sha:
            raise AssistantError("schema_revision_conflict", "Publish corrected content under a new revision.")
        artifact = directory / (sha + ".json.gz")
        if not artifact.exists():
            artifact.write_bytes(raw)
            artifact.chmod(0o644)
        history[key] = sha
        publish_json(history_path, history)
        entries = [e for e in entries if version_key(e["version"]) != version_key(version)]
        entries.append({"version": version, "revision": revision, "sha256": sha})
        publish_json(index_path, {"schemas": sorted(entries, key=lambda e: version_key(e["version"]))})
    return {"version": version, "revision": revision, "sha256": sha}


class RemoteCatalogProvider:
    """Read-only HTTP MCP client, bounded refresh, atomic cache, pinned Catalogs."""

    def __init__(self, cache, url=None, transport=None, refresh_seconds=60):
        self.cache = Path(cache)
        self.url = url or os.environ.get("SFA_SCHEMA_MCP_URL", DEFAULT_SCHEMA_MCP_URL)
        from urllib.parse import urlsplit
        origin = urlsplit(self.url)
        if origin.scheme not in ("http", "https") or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment:
            raise AssistantError("schema_url_invalid", "Configure an HTTP(S) schema MCP URL without credentials.")
        self.http = httpx.Client(timeout=30, trust_env=False, follow_redirects=False, transport=transport)
        self.refresh_seconds = refresh_seconds
        self.loaded = {}
        self.lock = threading.RLock()

    def close(self):
        self.http.close()

    def _rpc(self, method, params, identifier):
        with self.http.stream("POST", self.url, headers={"Accept": "application/json, text/event-stream",
                              "MCP-Protocol-Version": "2025-11-25"},
                              json={"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}) as response:
            response.raise_for_status()
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > MAX_PACKAGE * 3:
                    raise AssistantError("schema_package_invalid", "The schema response exceeds its size limit.")
        message = json.loads(raw)
        if message.get("id") != identifier or "error" in message:
            raise AssistantError("schema_service_error", "The schema MCP rejected the read request.")
        return message["result"]

    def get(self, fmc_version=""):
        key = ".".join(map(str, version_key(fmc_version))) if fmc_version else "latest"
        with self.lock:
            previous = self.loaded.get(key)
            if previous and time.monotonic() - previous[0] < self.refresh_seconds:
                return previous[1]
            package = None
            cache_path = self.cache / (key + ".json")
            source = "remote_mcp"
            try:
                self._rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                          "clientInfo": {"name": "secure-firewall-local", "version": "0.4.1"}}, 1)
                result = self._rpc("tools/call", {"name": "get_schema_package", "arguments": {"fmc_version": fmc_version}}, 2)
                if result.get("isError"):
                    raise AssistantError("schema_service_error", "The schema MCP could not select a schema.")
                package = result.get("structuredContent")
                if package is None:
                    package = json.loads(next(c["text"] for c in result["content"] if c["type"] == "text"))
                document = decode_package(package)
                if package["requested_fmc_version"] != fmc_version:
                    raise AssistantError("schema_package_invalid", "Schema selection does not match the requested version.")
                atomic_json(cache_path, package)
            except (httpx.HTTPError, OSError):
                if not cache_path.exists():
                    raise AssistantError("schema_service_unavailable", "Schema service is unavailable and no cached schema exists.") from None
                try:
                    package = json.loads(cache_path.read_text())
                    document = decode_package(package)
                    cached_version = package["requested_fmc_version"]
                    if ((version_key(cached_version) if cached_version else None) !=
                            (version_key(fmc_version) if fmc_version else None)):
                        raise ValueError
                    package["requested_fmc_version"] = fmc_version
                except (OSError, ValueError, KeyError):
                    raise AssistantError("schema_cache_invalid", "The cached schema cannot be used.") from None
                source = "local_cache_service_unavailable"
            except (ValueError, KeyError, TypeError, StopIteration):
                raise AssistantError("schema_service_invalid", "The schema MCP returned an invalid response.") from None
            catalog = Catalog(document)
            catalog.provenance = {k: v for k, v in package.items() if k != "gzip_base64"}
            catalog.provenance.update(source=source, schema_mcp_url=self.url)
            self.loaded[key] = (time.monotonic(), catalog)
            return catalog


class BundledCatalogProvider:
    """Explicit offline test/development provider; production uses remote MCP."""

    def get(self, fmc_version=""):
        catalog = Catalog()
        catalog.provenance.update(schema_version="10.5.0.0", revision="r1", requested_fmc_version=fmc_version,
                                  selection="exact" if fmc_version and version_key(fmc_version) == (10, 5, 0, 0) else "latest_fallback",
                                  source="explicit_bundled_provider")
        return catalog

    def close(self):
        pass
