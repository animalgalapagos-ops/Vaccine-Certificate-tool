# Vaccine Certificate Tool

This is a small, self-contained CLI that issues and verifies signed vaccine
certificate JSON documents. It is intended for demo or internal tooling use
only and is **not** a medical device.

## Requirements

- Python 3.8+

## Quick start

Set a signing secret (recommended via env var):

```bash
export VAXCERT_SECRET="replace-with-a-strong-secret"
```

Issue a certificate:

```bash
python vaxcert.py issue \
  --name "Taro Yamada" \
  --dob 1990-04-12 \
  --vaccine "Pfizer" \
  --doses 2 \
  --last-dose 2025-09-01 \
  --issuer "Tokyo Health Office" \
  --expires-at 2026-12-31T00:00:00Z \
  --output cert.json
```

Verify a certificate:

```bash
python vaxcert.py verify --input cert.json
```

Inspect summary fields:

```bash
python vaxcert.py inspect --input cert.json
```

## Notes

- The certificate is signed using HMAC-SHA256 with a shared secret.
- Keep the secret out of source control.
- Validation checks signature and optional expiry.
