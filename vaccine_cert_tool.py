#!/usr/bin/env python3
"""
Vaccine Certificate Tool

Issue and verify signed vaccine certificates using HMAC-SHA256.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

TOKEN_PREFIX = "VC1"
ENV_SECRET = "VAXCERT_SECRET"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def iso_now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def validate_date(value: str, field_name: str) -> str:
    try:
        dt.date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be YYYY-MM-DD") from exc
    return value


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_payload(payload_bytes: bytes, secret: bytes) -> str:
    digest = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    return b64url_encode(digest)


def make_token(payload: Dict[str, Any], secret: bytes) -> str:
    payload_bytes = canonical_json(payload)
    payload_b64 = b64url_encode(payload_bytes)
    signature = sign_payload(payload_bytes, secret)
    return f"{TOKEN_PREFIX}.{payload_b64}.{signature}"


def parse_token(token: str) -> Tuple[str, bytes, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token must have 3 dot-separated parts")
    prefix, payload_b64, signature = parts
    if prefix != TOKEN_PREFIX:
        raise ValueError(f"Token prefix must be {TOKEN_PREFIX}")
    payload_bytes = b64url_decode(payload_b64)
    return payload_b64, payload_bytes, signature


def verify_token(token: str, secret: bytes) -> Dict[str, Any]:
    _, payload_bytes, signature = parse_token(token)
    expected = sign_payload(payload_bytes, secret)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Signature mismatch")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Payload is not valid JSON") from exc
    enforce_valid_until(payload)
    return payload


def enforce_valid_until(payload: Dict[str, Any]) -> None:
    valid_until = payload.get("valid_until")
    if not valid_until:
        return
    valid_until = validate_date(valid_until, "valid_until")
    expiry = dt.date.fromisoformat(valid_until)
    today = dt.datetime.now(dt.timezone.utc).date()
    if expiry < today:
        raise ValueError("Certificate has expired")


def load_secret(args: argparse.Namespace) -> bytes:
    if args.secret and args.secret_file:
        raise ValueError("Use only one of --secret or --secret-file")
    if args.secret_file:
        secret = Path(args.secret_file).read_text(encoding="utf-8").strip()
    elif args.secret:
        secret = args.secret
    else:
        secret = os.environ.get(ENV_SECRET, "").strip()
        if not secret:
            raise ValueError(
                "Missing secret. Use --secret, --secret-file, or VAXCERT_SECRET."
            )
    return secret.encode("utf-8")


def read_token(token: Optional[str], token_file: Optional[str]) -> str:
    if token and token_file:
        raise ValueError("Use only one of --token or --token-file")
    if token:
        return token.strip()
    if not token_file:
        raise ValueError("Missing token. Use --token or --token-file.")
    raw = Path(token_file).read_text(encoding="utf-8").strip()
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and "token" in parsed:
                return str(parsed["token"]).strip()
        except json.JSONDecodeError:
            pass
    return raw


def write_output(text: str, output_path: Optional[str]) -> None:
    if output_path:
        Path(output_path).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    dob = validate_date(args.dob, "dob")
    dose_date = validate_date(args.dose_date, "dose-date")
    if args.valid_until:
        validate_date(args.valid_until, "valid-until")

    dose_number = args.dose_number
    total_doses = args.total_doses
    if dose_number < 1:
        raise ValueError("dose-number must be >= 1")
    if total_doses < 1:
        raise ValueError("total-doses must be >= 1")
    if dose_number > total_doses:
        raise ValueError("dose-number cannot exceed total-doses")

    subject: Dict[str, Any] = {"name": args.name, "dob": dob}
    if args.patient_id:
        subject["id"] = args.patient_id

    vaccination: Dict[str, Any] = {
        "vaccine": args.vaccine,
        "dose_number": dose_number,
        "total_doses": total_doses,
        "date": dose_date,
    }
    if args.lot:
        vaccination["lot"] = args.lot

    payload: Dict[str, Any] = {
        "schema": "vaccine_certificate",
        "schema_version": "1.0",
        "certificate_id": str(uuid.uuid4()),
        "issued_at": iso_now_utc(),
        "issuer": {"name": args.issuer, "country": args.country},
        "subject": subject,
        "vaccinations": [vaccination],
    }
    if args.valid_until:
        payload["valid_until"] = args.valid_until
    return payload


def add_secret_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--secret",
        help="Signing secret (or set VAXCERT_SECRET).",
    )
    parser.add_argument(
        "--secret-file",
        help="Path to file containing the signing secret.",
    )


def cmd_issue(args: argparse.Namespace) -> None:
    secret = load_secret(args)
    payload = build_payload(args)
    token = make_token(payload, secret)
    if args.format == "json":
        output = json.dumps(
            {"token": token, "payload": payload},
            ensure_ascii=False,
            indent=2,
        )
    else:
        output = token
    write_output(output, args.output)


def cmd_verify(args: argparse.Namespace) -> None:
    secret = load_secret(args)
    token = read_token(args.token, args.token_file)
    payload = verify_token(token, secret)
    if args.format == "json":
        output = json.dumps(
            {"valid": True, "payload": payload},
            ensure_ascii=False,
            indent=2,
        )
    else:
        output = "VALID\n" + json.dumps(
            payload, ensure_ascii=False, indent=2, sort_keys=True
        )
    write_output(output, args.output)


def cmd_inspect(args: argparse.Namespace) -> None:
    token = read_token(args.token, args.token_file)
    _, payload_bytes, _ = parse_token(token)
    payload = json.loads(payload_bytes.decode("utf-8"))
    output = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    write_output(output, args.output)


def cmd_gen_secret(args: argparse.Namespace) -> None:
    secret = secrets.token_urlsafe(args.length)
    write_output(secret, args.output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Issue and verify signed vaccine certificates."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue = subparsers.add_parser("issue", help="Issue a certificate")
    issue.add_argument("--name", required=True, help="Full name")
    issue.add_argument("--dob", required=True, help="Date of birth YYYY-MM-DD")
    issue.add_argument("--patient-id", help="Optional patient identifier")
    issue.add_argument("--vaccine", required=True, help="Vaccine name")
    issue.add_argument(
        "--dose-number", type=int, default=1, help="Dose number (default: 1)"
    )
    issue.add_argument(
        "--total-doses", type=int, default=1, help="Total doses (default: 1)"
    )
    issue.add_argument("--dose-date", required=True, help="Dose date YYYY-MM-DD")
    issue.add_argument("--lot", help="Vaccine lot number")
    issue.add_argument(
        "--issuer",
        default="Local Health Authority",
        help="Issuing authority",
    )
    issue.add_argument("--country", default="JP", help="Issuer country code")
    issue.add_argument("--valid-until", help="Optional expiry date YYYY-MM-DD")
    issue.add_argument(
        "--format",
        choices=["token", "json"],
        default="token",
        help="Output format",
    )
    issue.add_argument("--output", help="Write output to a file")
    add_secret_args(issue)
    issue.set_defaults(func=cmd_issue)

    verify = subparsers.add_parser("verify", help="Verify a certificate")
    verify.add_argument("--token", help="Token string")
    verify.add_argument("--token-file", help="Read token from file")
    verify.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    verify.add_argument("--output", help="Write output to a file")
    add_secret_args(verify)
    verify.set_defaults(func=cmd_verify)

    inspect = subparsers.add_parser("inspect", help="Decode token without verifying")
    inspect.add_argument("--token", help="Token string")
    inspect.add_argument("--token-file", help="Read token from file")
    inspect.add_argument("--output", help="Write output to a file")
    inspect.set_defaults(func=cmd_inspect)

    gen_secret = subparsers.add_parser("gen-secret", help="Generate a secret")
    gen_secret.add_argument(
        "--length",
        type=int,
        default=32,
        help="Secret length in bytes (default: 32)",
    )
    gen_secret.add_argument("--output", help="Write output to a file")
    gen_secret.set_defaults(func=cmd_gen_secret)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        args.func(args)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
