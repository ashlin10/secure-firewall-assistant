import argparse
import getpass
import json
import sys
from pathlib import Path

from .errors import AssistantError
from .inventory import DEVICE_TYPES
from .security import Redactor, SecretStore
from .state import Device, State


def hidden_password(label="Password: "):
    if not sys.stdin.isatty():
        raise AssistantError("interactive_enrollment_required", "Run enrollment in your own terminal. Passwords cannot be passed in arguments, environment variables, or redirected input.")
    first = getpass.getpass(label)
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise AssistantError("password_mismatch", "Passwords did not match; nothing was saved.")
    return first


def parser():
    p = argparse.ArgumentParser(description="Secure Firewall Assistant local setup and diagnostics")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Run the local MCP server")
    remote = sub.add_parser("schema-serve", help="Run the shared read-only HTTP MCP schema service")
    remote.add_argument("--directory", type=Path, required=True)
    remote.add_argument("--host", default="0.0.0.0")
    remote.add_argument("--port", type=int, default=8765)
    remote.add_argument("--allowed-host", action="append")
    publish = sub.add_parser("schema-publish", help="Publish a reviewed schema revision to a registry directory")
    publish.add_argument("--directory", type=Path, required=True)
    publish.add_argument("--schema", type=Path, required=True)
    publish.add_argument("--fmc-version", required=True)
    publish.add_argument("--revision", required=True)
    sub.add_parser("health", help="Inspect package and paths without device or credential access")
    sub.add_parser("list", help="List enrolled aliases")
    enroll = sub.add_parser("enroll", help="Save a private device and password through local hidden entry")
    enroll.add_argument("kind", choices=DEVICE_TYPES)
    enroll.add_argument("alias")
    enroll.add_argument("address", help="FMC HTTPS origin or FTD hostname/IP")
    enroll.add_argument("--username", required=True)
    enroll.add_argument("--domain", help="Exact FMC domain name or UUID; required if several domains are available")
    enroll.add_argument("--ca-bundle", type=Path, help="PEM trust bundle; enables certificate and hostname verification")
    enroll.add_argument("--verify-ssl", action="store_true", help="Verify certificate and hostname (disabled by default for labs)")
    enroll.add_argument("--expected-version-prefix", help="Block writes when the observed version does not start with this prefix")
    enroll.add_argument("--port", type=int, default=22)
    enroll.add_argument("--fmc-alias")
    enroll.add_argument("--device-uuid")
    enroll.add_argument("--replace", action="store_true", help="Replace this alias's enrollment without an additional prompt")
    secret = sub.add_parser("set-secret", help="Enroll a secret used by a sensitive API configuration field")
    secret.add_argument("reference")
    trust = sub.add_parser("trust-host", help="Inspect and automatically record an FTD SSH host key")
    trust.add_argument("alias")
    check = sub.add_parser("check", help="Check an enrolled FMC login/version without changing configuration")
    check.add_argument("alias")
    return p


def main():
    args = parser().parse_args()
    if args.command == "serve":
        from .server import serve
        serve()
        return
    if args.command == "schema-serve":
        from .schema_server import serve_schema
        serve_schema(args.directory, args.host, args.port, args.allowed_host)
        return
    if args.command == "schema-publish":
        from .schema_registry import publish
        print(json.dumps(publish(args.directory, args.schema, args.fmc_version, args.revision)))
        return
    redactor = Redactor()
    try:
        state = State()
        secrets = SecretStore(redactor)
        if args.command == "enroll":
            if args.alias in state.inventory()["devices"] and not args.replace:
                raise AssistantError("alias_exists", "Alias already exists. Use --replace to deliberately update its enrollment.")
            ca = str(args.ca_bundle.expanduser().resolve()) if args.ca_bundle else None
            if ca and not Path(ca).is_file():
                raise AssistantError("ca_bundle_missing", "Certificate trust bundle was not found.")
            device = Device(alias=args.alias, kind=args.kind, address=args.address.rstrip("/"),
                            username=args.username, credential_ref=args.alias + "-auth", domain=args.domain,
                            ca_bundle=ca, verify_ssl=args.verify_ssl, expected_version_prefix=args.expected_version_prefix, port=args.port,
                            fmc_alias=args.fmc_alias, device_uuid=args.device_uuid)
            # Serialize enrollment against active operations and other setup processes.
            with state.target_lock(args.alias):
                value = hidden_password()
                secrets.set(device.credential_ref, value, device=device)
                state.save_device(device)
            result = {"ok": True, "alias": device.alias, "kind": device.kind,
                      "next_step": "Run check for an FMC, or diagnostics for an optional FTD."}
        elif args.command == "set-secret":
            secrets.set(args.reference, hidden_password("Secret value: "))
            result = {"ok": True, "reference": args.reference}
        elif args.command == "trust-host":
            from .ssh import fingerprint, host_key, save_host_key
            device = state.device(args.alias, "ftd")
            key = host_key(device)
            value = fingerprint(key)
            print(f"Host: {device.address}:{device.port}\nFingerprint: {value}")
            save_host_key(state, device, key)
            result = {"ok": True, "alias": device.alias, "fingerprint": value}
        elif args.command == "list":
            result = {"devices": state.aliases()}
        else:
            from .service import Assistant
            assistant = Assistant(state=state)
            try:
                result = assistant.connect(args.alias) if args.command == "check" else assistant.health()
            finally:
                assistant.close()
        print(json.dumps(redactor.clean(result), indent=2))
    except AssistantError as error:
        print(json.dumps(redactor.clean(error.result()), indent=2), file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print("Local setup failed. Check devices.yaml file permissions and format; no exception details were logged.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
