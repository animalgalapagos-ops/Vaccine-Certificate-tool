#!/usr/bin/env python3
"""
Vaccine certificate issuing and verification tool.

This is a lightweight, offline-friendly CLI that issues a signed certificate
and verifies it using an HMAC-SHA256 secret.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import uuid

SCHEMA_VERSION = "vaxcert:1"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _get_secret(value: str | None) -> str:
    secret = value or os.environ.get("VAXCERT_SECRET")
    if not secret:
        raise ValueError("Missing secret. Use --secret or VAXCERT_SECRET.")
    return secret


def _parse_date(value: str) -> str:
    try:
        dt.date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Invalid date format. Use YYYY-MM-DD."
        ) from exc
    return value


def _now_iso_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _compute_signature(payload: dict, secret: str) -> str:
    canonical = _canonical_json(payload).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).digest()
    return _b64url_encode(digest)


def _build_token(payload: dict, secret: str) -> str:
    payload_b64 = _b64url_encode(_canonical_json(payload).encode("utf-8"))
    signature = _compute_signature(payload, secret)
    return f"{payload_b64}.{signature}"


def _load_certificate(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise ValueError(f"Certificate not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON certificate file.") from exc

    if not isinstance(data, dict):
        raise ValueError("Certificate file must contain a JSON object.")
    if "payload" not in data or "signature" not in data:
        raise ValueError("Certificate must include payload and signature.")
    if not isinstance(data["payload"], dict):
        raise ValueError("Certificate payload must be an object.")
    if not isinstance(data["signature"], str):
        raise ValueError("Certificate signature must be a string.")
    return data


def _load_token(token: str) -> dict:
    if token.count(".") != 1:
        raise ValueError("Token must contain exactly one '.' separator.")
    payload_b64, signature = token.split(".", 1)
    try:
        payload_raw = _b64url_decode(payload_b64)
        payload = json.loads(payload_raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Token payload is not valid JSON.") from exc

    if not isinstance(payload, dict):
        raise ValueError("Token payload must be a JSON object.")
    return {"payload": payload, "signature": signature}


def _validate_payload(payload: dict) -> None:
    if payload.get("schema") != SCHEMA_VERSION:
        raise ValueError("Unsupported schema version.")


def issue_command(args: argparse.Namespace) -> int:
    secret = _get_secret(args.secret)
    payload = {
        "schema": SCHEMA_VERSION,
        "id": args.id or str(uuid.uuid4()),
        "name": args.name,
        "dob": args.dob,
        "vaccine": args.vaccine,
        "dose": args.dose,
        "date": args.date,
        "issuer": args.issuer,
        "issued_at": _now_iso_utc(),
    }
    signature = _compute_signature(payload, secret)
    certificate = {"payload": payload, "signature": signature}

    output = json.dumps(
        certificate, ensure_ascii=False, indent=2, sort_keys=True
    )
    if args.out == "-":
        print(output)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")

    if args.print_token or args.token_out:
        token = _build_token(payload, secret)
        if args.print_token:
            print(token)
        if args.token_out:
            with open(args.token_out, "w", encoding="utf-8") as handle:
                handle.write(token + "\n")

    return 0


def verify_command(args: argparse.Namespace) -> int:
    secret = _get_secret(args.secret)
    if args.token:
        certificate = _load_token(args.token)
    else:
        certificate = _load_certificate(args.input)

    payload = certificate["payload"]
    signature = certificate["signature"]

    _validate_payload(payload)
    expected = _compute_signature(payload, secret)

    if not hmac.compare_digest(expected, signature):
        print("INVALID")
        return 1

    print("VALID")
    if args.show_payload:
        print(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        )
    return 0


def show_command(args: argparse.Namespace) -> int:
    certificate = _load_certificate(args.input)
    print(
        json.dumps(
            certificate["payload"],
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Issue and verify vaccine certificates."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue = subparsers.add_parser("issue", help="Issue a certificate.")
    issue.add_argument("--name", required=True, help="Full name.")
    issue.add_argument("--dob", required=True, type=_parse_date, help="YYYY-MM-DD")
    issue.add_argument("--vaccine", required=True, help="Vaccine product name.")
    issue.add_argument("--dose", required=True, type=int, help="Dose number.")
    issue.add_argument("--date", required=True, type=_parse_date, help="YYYY-MM-DD")
    issue.add_argument("--issuer", required=True, help="Issuing organization.")
    issue.add_argument("--id", help="Certificate identifier (UUID).")
    issue.add_argument(
        "--secret", help="HMAC secret (or set VAXCERT_SECRET)."
    )
    issue.add_argument("--out", default="certificate.json", help="Output path.")
    issue.add_argument(
        "--print-token",
        action="store_true",
        help="Print token for QR code encoding.",
    )
    issue.add_argument(
        "--token-out",
        help="Write token to a file for QR code encoding.",
    )
    issue.set_defaults(func=issue_command)

    verify = subparsers.add_parser("verify", help="Verify a certificate.")
    verify.add_argument(
        "--input", default="certificate.json", help="Certificate JSON file."
    )
    verify.add_argument("--token", help="Token string instead of a file.")
    verify.add_argument(
        "--secret", help="HMAC secret (or set VAXCERT_SECRET)."
    )
    verify.add_argument(
        "--show-payload",
        action="store_true",
        help="Print payload on successful verification.",
    )
    verify.set_defaults(func=verify_command)

    show = subparsers.add_parser(
        "show", help="Display payload without verification."
    )
    show.add_argument(
        "--input", default="certificate.json", help="Certificate JSON file."
    )
    show.set_defaults(func=show_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "command", None) == "verify" and args.token and args.input:
        # Prevent ambiguous input sources.
        parser.error("Use --token or --input, not both.")

    if getattr(args, "command", None) == "issue" and args.dose < 1:
        parser.error("--dose must be 1 or greater.")

    try:
        return args.func(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
