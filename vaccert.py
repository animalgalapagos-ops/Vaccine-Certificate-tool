#!/usr/bin/env python3
"""
Vaccine Certificate tool (demo)

This tool creates and verifies a simple vaccine certificate payload.
It uses HMAC-SHA256 for integrity and is intended for demos only.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hmac
import json
import os
import sys
import uuid

VERSION = "0.1.0"


def _parse_date(value: str, field_name: str) -> str:
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{field_name} must be YYYY-MM-DD"
        ) from exc
    return parsed.isoformat()


def _parse_dose(value: str) -> dict:
    parts = value.split(":", 1)
    dose_date = _parse_date(parts[0], "dose date")
    entry = {"date": dose_date}
    if len(parts) == 2 and parts[1]:
        entry["lot"] = parts[1]
    return entry


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _load_secret(arg_secret: str | None) -> bytes:
    secret = arg_secret or os.environ.get("VACCERT_SECRET")
    if not secret:
        raise SystemExit(
            "Secret missing. Use --secret or set VACCERT_SECRET."
        )
    return secret.encode("utf-8")


def _sign_payload(payload: dict, secret: bytes) -> str:
    msg = _canonical_json(payload).encode("utf-8")
    digest = hmac.new(secret, msg, digestmod="sha256").digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def _write_output(data: dict, output_path: str | None) -> None:
    output = json.dumps(
        data, indent=2, sort_keys=True, ensure_ascii=True
    ) + "\n"
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        sys.stdout.write(output)


def build_certificate(args: argparse.Namespace) -> dict:
    certificate_id = args.certificate_id or str(uuid.uuid4())
    issued_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    doses = []
    for index, dose_entry in enumerate(args.dose, start=1):
        entry = {"dose": index, "date": dose_entry["date"]}
        if "lot" in dose_entry:
            entry["lot"] = dose_entry["lot"]
        doses.append(entry)

    payload = {
        "id": certificate_id,
        "name": args.name,
        "dob": _parse_date(args.dob, "date of birth"),
        "vaccine": args.vaccine,
        "doses": doses,
        "issuer": args.issuer,
        "issued_at": issued_at,
    }
    secret = _load_secret(args.secret)
    signature = _sign_payload(payload, secret)
    certificate = dict(payload)
    certificate["signature"] = signature
    return certificate


def cmd_create(args: argparse.Namespace) -> int:
    certificate = build_certificate(args)
    _write_output(certificate, args.output)
    return 0


def _load_certificate(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit("Certificate file must contain a JSON object.")
    if "signature" not in data:
        raise SystemExit("Certificate missing signature field.")
    return data


def _verify_certificate(certificate: dict, secret: bytes) -> bool:
    signature = certificate.get("signature")
    payload = dict(certificate)
    payload.pop("signature", None)
    expected = _sign_payload(payload, secret)
    if not isinstance(signature, str):
        return False
    return hmac.compare_digest(signature, expected)


def cmd_verify(args: argparse.Namespace) -> int:
    certificate = _load_certificate(args.input)
    secret = _load_secret(args.secret)
    if _verify_certificate(certificate, secret):
        print("VALID")
        return 0
    print("INVALID")
    return 1


def cmd_show(args: argparse.Namespace) -> int:
    certificate = _load_certificate(args.input)
    doses = certificate.get("doses", [])
    lines = [
        f"Certificate ID: {certificate.get('id', '')}",
        f"Name: {certificate.get('name', '')}",
        f"Date of Birth: {certificate.get('dob', '')}",
        f"Vaccine: {certificate.get('vaccine', '')}",
        f"Issuer: {certificate.get('issuer', '')}",
        f"Issued At: {certificate.get('issued_at', '')}",
        f"Doses: {len(doses)}",
    ]
    for dose in doses:
        dose_num = dose.get("dose", "")
        dose_date = dose.get("date", "")
        lot = dose.get("lot")
        if lot:
            lines.append(f"  - Dose {dose_num}: {dose_date} (lot {lot})")
        else:
            lines.append(f"  - Dose {dose_num}: {dose_date}")
    print("\n".join(lines))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Vaccine certificate tool (demo)"
    )
    parser.add_argument("--version", action="version", version=VERSION)

    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create a certificate")
    create.add_argument("--name", required=True, help="Full name")
    create.add_argument("--dob", required=True, help="Date of birth YYYY-MM-DD")
    create.add_argument("--vaccine", required=True, help="Vaccine product name")
    create.add_argument(
        "--dose",
        required=True,
        action="append",
        type=_parse_dose,
        help="Dose date YYYY-MM-DD or YYYY-MM-DD:LOT (repeatable)",
    )
    create.add_argument("--issuer", required=True, help="Issuing authority")
    create.add_argument(
        "--certificate-id",
        help="Optional certificate id (UUID if omitted)",
    )
    create.add_argument(
        "--secret",
        help="Signing secret (fallback to VACCERT_SECRET)",
    )
    create.add_argument(
        "--output",
        help="Output path (defaults to stdout)",
    )
    create.set_defaults(func=cmd_create)

    verify = subparsers.add_parser("verify", help="Verify a certificate")
    verify.add_argument("--input", required=True, help="Certificate JSON file")
    verify.add_argument(
        "--secret",
        help="Verification secret (fallback to VACCERT_SECRET)",
    )
    verify.set_defaults(func=cmd_verify)

    show = subparsers.add_parser("show", help="Display a certificate summary")
    show.add_argument("--input", required=True, help="Certificate JSON file")
    show.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
