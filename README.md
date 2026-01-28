# Vaccine Certificate Tool

Demo CLI that creates and verifies simple vaccine certificates as JSON.
It uses HMAC-SHA256 for integrity checks and is intended for demos only.
It is not an official or compliant medical certificate system.

## Requirements

- Python 3.10+ (standard library only)

## Usage

Set a secret for signing:

```bash
export VACCERT_SECRET="your-secret"
```

Create a certificate:

```bash
python vaccert.py create \
  --name "Taro Yamada" \
  --dob 1990-01-01 \
  --vaccine "ExampleVax" \
  --dose 2024-01-01 \
  --dose 2024-02-01:LOT123 \
  --issuer "City Health Office" \
  --output certificate.json
```

Verify a certificate:

```bash
python vaccert.py verify --input certificate.json
```

Show a readable summary:

```bash
python vaccert.py show --input certificate.json
```

You can also pass `--secret` on the command line instead of using
`VACCERT_SECRET`.
