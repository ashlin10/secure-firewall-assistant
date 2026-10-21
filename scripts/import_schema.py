"""Read the supplied OpenAPI document as data; never execute its examples."""
import argparse
import gzip
import hashlib
import json
import re
from pathlib import Path

from schema_corrections import CORRECTION_NOTE, apply_corrections

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src/secure_firewall_assistant/data"


def sanitize(value, redactions=()):
    if isinstance(value, dict):
        return {k: sanitize(v, redactions) for k, v in value.items()
                if k not in {"example", "examples", "x-codeSamples", "x-code-samples"}}
    if isinstance(value, list):
        return [sanitize(v, redactions) for v in value]
    if isinstance(value, str):
        for secret in redactions:
            value = value.replace(secret, "[EXAMPLE CREDENTIAL REMOVED]")
        # Preserve public documentation links; remove sample environment destinations.
        value = re.sub(r"https?://[^\s<>\"')]+",
                       lambda m: m[0] if re.match(r"https?://(?:www\.)?cisco\.com/", m[0])
                       else "https://fmc.example.invalid", value)
    return value


def example_credentials(doc):
    candidates, identifiers = set(), set()

    def walk(value, example=False):
        if isinstance(value, dict):
            identifiers.update(value)
            for key, item in value.items():
                inside = example or key in {"example", "examples"}
                if (inside and re.search(r"password|passwd|secret|token", key, re.I) and
                        isinstance(item, str) and len(item) >= 6):
                    candidates.add(item)
                walk(item, inside)
        elif isinstance(value, list):
            for item in value:
                walk(item, example)

    walk(doc)
    # A literal schema identifier such as "password" is structural, not a password.
    return sorted((v for v in candidates if v not in identifiers and set(v) - set("*xX-")), key=len, reverse=True)


def unresolved_refs(doc):
    missing = set()

    def walk(obj):
        if isinstance(obj, dict):
            if "$ref" in obj:
                ref = obj["$ref"]
                if not ref.startswith("#/"):
                    raise ValueError("External references must not be resolved over the network")
                try:
                    cursor = doc
                    for part in ref[2:].split("/"):
                        cursor = cursor[part.replace("~1", "/").replace("~0", "~")]
                except (KeyError, TypeError):
                    missing.add(ref)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(doc)
    return sorted(missing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    raw = args.source.read_bytes()
    doc = json.loads(raw)
    cleaned = sanitize(doc, example_credentials(doc))
    apply_corrections(cleaned)
    encoded = json.dumps(cleaned, separators=(",", ":"), sort_keys=True).encode()
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "fmc.openapi.json.gz").write_bytes(gzip.compress(encoded, mtime=0))
    operations = [o for v in doc["paths"].values() for m, o in v.items()
                  if m in {"get", "post", "put", "patch", "delete", "head", "options"}]
    provenance = {
        "source_filename": args.source.name,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "sanitized_sha256": hashlib.sha256(encoded).hexdigest(),
        "openapi": doc["openapi"], "info_version": doc["info"]["version"],
        "declared_device_version": None,
        "paths": len(doc["paths"]), "operations": len(operations),
        "schemas": len(doc["components"]["schemas"]),
        "unresolved_references": unresolved_refs(cleaned),
        "transformations": [CORRECTION_NOTE, "Removed all example/examples and code sample fields",
                            "Removed non-structural sample credential values repeated elsewhere in the document",
                            "Replaced non-public-documentation example URLs",
                            "No missing definitions fabricated; affected response validation reports a warning"],
    }
    (DATA / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps(provenance, indent=2))


if __name__ == "__main__":
    main()
