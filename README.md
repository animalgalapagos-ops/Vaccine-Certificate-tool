# Vaccine Certificate tool

This repository provides a small offline CLI to issue and verify signed
vaccine certificates. Certificates are signed with HMAC-SHA256 and encoded
as compact tokens that can be shared or stored in files.

## Quick start

Generate a secret:

```
python vaccine_cert_tool.py gen-secret > .secret
```

Issue a certificate token:

```
python vaccine_cert_tool.py issue \
  --name "Taro Yamada" \
  --dob 1990-04-10 \
  --vaccine "ExampleVax" \
  --dose-number 2 \
  --total-doses 2 \
  --dose-date 2025-12-15 \
  --issuer "JP Health Authority" \
  --country JP \
  --secret-file .secret \
  --format json \
  --output certificate.json
```

Verify a token (accepts a raw token or a JSON file containing "token"):

```
python vaccine_cert_tool.py verify --token-file certificate.json --secret-file .secret
```

Inspect a token without verifying:

```
python vaccine_cert_tool.py inspect --token-file certificate.json
```

## Notes

- The signing secret can be supplied via `--secret`, `--secret-file`, or
  the `VAXCERT_SECRET` environment variable.
- The token format is `VC1.<payload>.<signature>` where payload is
  base64url-encoded JSON.
