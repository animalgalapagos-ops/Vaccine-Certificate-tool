#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sys

SCHEMA = "vaxcert.v1"


def now_utc_iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_date(value: str, field: str) -> str:
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be YYYY-MM-DD") from exc
    return parsed.isoformat()


def normalize_datetime(value: str, field: str) -> str:
    raw = value
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be ISO-8601 datetime") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    parsed = parsed.astimezone(dt.timezone.utc).replace(microsecond=0)
    return parsed.isoformat().replace("+00:00", "Z")


def prune_none(obj):
    if isinstance(obj, dict):
        cleaned = {k: prune_none(v) for k, v in obj.items() if v is not None}
        return {k: v for k, v in cleaned.items() if not (isinstance(v, dict) and not v)}
    if isinstance(obj, list):
        return [prune_none(v) for v in obj]
    return obj


def canonical_payload(cert: dict) -> str:
    payload = {k: v for k, v in cert.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_payload(payload_json: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def get_secret(args) -> str:
    if args.secret:
        return args.secret
    env_secret = os.getenv("VAXCERT_SECRET")
    if env_secret:
        return env_secret
    raise SystemExit("secret is required via --secret or VAXCERT_SECRET")


def build_certificate(args) -> dict:
    cert = {
        "schema": SCHEMA,
        "issued_at": now_utc_iso(),
        "expires_at": normalize_datetime(args.expires_at, "expires_at")
        if args.expires_at
        else None,
        "holder": {
            "name": args.name,
            "dob": normalize_date(args.dob, "dob"),
            "id": args.holder_id,
        },
        "vaccination": {
            "vaccine": args.vaccine,
            "doses": args.doses,
            "last_dose": normalize_date(args.last_dose, "last_dose")
            if args.last_dose
            else None,
        },
        "issuer": {"name": args.issuer, "id": args.issuer_id},
    }
    return prune_none(cert)


def issue_certificate(args) -> int:
    secret = get_secret(args)
    cert = build_certificate(args)
    payload_json = canonical_payload(cert)
    cert["signature"] = sign_payload(payload_json, secret)
    output = json.dumps(cert, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
    else:
        sys.stdout.write(output + "\n")
    return 0


def load_certificate(args) -> dict:
    if args.input:
        raw = read_text(args.input)
    elif args.cert:
        raw = args.cert
    else:
        raw = sys.stdin.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON: {exc}") from exc


def verify_certificate(args) -> int:
    secret = get_secret(args)
    cert = load_certificate(args)
    errors = []

    if cert.get("schema") != SCHEMA:
        errors.append("unsupported schema")

    signature = cert.get("signature")
    if not signature:
        errors.append("missing signature")
    else:
        payload_json = canonical_payload(cert)
        expected = sign_payload(payload_json, secret)
        if not hmac.compare_digest(signature, expected):
            errors.append("signature mismatch")

    if not args.skip_expiry and cert.get("expires_at"):
        try:
            expires_at = normalize_datetime(cert["expires_at"], "expires_at")
            expires_dt = dt.datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")
            ).astimezone(dt.timezone.utc)
        except ValueError:
            errors.append("invalid expires_at")
        else:
            if expires_dt < dt.datetime.now(dt.timezone.utc):
                errors.append("certificate expired")

    if errors:
        sys.stdout.write("INVALID\n")
        for error in errors:
            sys.stdout.write(f"- {error}\n")
        return 1

    sys.stdout.write("VALID\n")
    return 0


def inspect_certificate(args) -> int:
    cert = load_certificate(args)
    holder = cert.get("holder", {})
    vaccination = cert.get("vaccination", {})
    issuer = cert.get("issuer", {})
    summary = {
        "schema": cert.get("schema"),
        "issued_at": cert.get("issued_at"),
        "expires_at": cert.get("expires_at"),
        "holder_name": holder.get("name"),
        "holder_dob": holder.get("dob"),
        "vaccine": vaccination.get("vaccine"),
        "doses": vaccination.get("doses"),
        "last_dose": vaccination.get("last_dose"),
        "issuer_name": issuer.get("name"),
    }
    sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Vaccine Certificate Tool (demo)"
    )
    parser.add_argument(
        "--secret",
        help="Signing secret (or set VAXCERT_SECRET)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue = subparsers.add_parser("issue", help="Issue a certificate")
    issue.add_argument("--name", required=True, help="Holder full name")
    issue.add_argument("--dob", required=True, help="Holder DOB (YYYY-MM-DD)")
    issue.add_argument("--holder-id", help="Holder identifier")
    issue.add_argument("--vaccine", required=True, help="Vaccine brand or code")
    issue.add_argument(
        "--doses",
        required=True,
        type=int,
        help="Number of doses",
    )
    issue.add_argument("--last-dose", help="Last dose date (YYYY-MM-DD)")
    issue.add_argument("--issuer", required=True, help="Issuer name")
    issue.add_argument("--issuer-id", help="Issuer identifier")
    issue.add_argument(
        "--expires-at",
        help="Expiry datetime (ISO-8601, e.g. 2026-12-31T00:00:00Z)",
    )
    issue.add_argument("--output", help="Write certificate JSON to file")
    issue.set_defaults(func=issue_certificate)

    verify = subparsers.add_parser("verify", help="Verify a certificate")
    verify.add_argument("--input", help="Certificate JSON file (or '-')")
    verify.add_argument("--cert", help="Certificate JSON string")
    verify.add_argument(
        "--skip-expiry",
        action="store_true",
        help="Skip expiry validation",
    )
    verify.set_defaults(func=verify_certificate)

    inspect = subparsers.add_parser("inspect", help="Show certificate summary")
    inspect.add_argument("--input", help="Certificate JSON file (or '-')")
    inspect.add_argument("--cert", help="Certificate JSON string")
    inspect.set_defaults(func=inspect_certificate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
