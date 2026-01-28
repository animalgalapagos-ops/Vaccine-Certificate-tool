# Vaccine Certificate tool

A lightweight CLI to issue and verify a signed vaccine certificate. It uses
HMAC-SHA256 with a shared secret and outputs JSON and an optional token for QR
encoding.

## Requirements
- Python 3.8+

## Quick start

Set the shared secret:

```bash
export VAXCERT_SECRET="change-me"
```

Issue a certificate:

```bash
python vaxcert.py issue \
  --name "Taro Yamada" \
  --dob 1990-01-01 \
  --vaccine "Moderna" \
  --dose 2 \
  --date 2025-01-20 \
  --issuer "City Health Office" \
  --out cert.json \
  --print-token
```

Verify a certificate file:

```bash
python vaxcert.py verify --input cert.json
```

Verify a token:

```bash
TOKEN="$(python vaxcert.py issue \
  --name "Taro Yamada" \
  --dob 1990-01-01 \
  --vaccine "Moderna" \
  --dose 2 \
  --date 2025-01-20 \
  --issuer "City Health Office" \
  --print-token)"
python vaxcert.py verify --token "$TOKEN"
```

Display payload without verification:

```bash
python vaxcert.py show --input cert.json
```

## Notes
- This is a demo tool and not an official certificate format.
- Protect the HMAC secret; anyone with it can forge certificates.
- Tokens are formatted as `base64url(payload).signature`.
