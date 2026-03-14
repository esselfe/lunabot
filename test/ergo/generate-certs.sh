#!/usr/bin/env bash
# Generate self-signed TLS certificates for the Ergo IRC test server.
# Skips generation if the files already exist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT="$SCRIPT_DIR/fullchain.pem"
KEY="$SCRIPT_DIR/privkey.pem"

if [[ -f "$CERT" ]] && [[ -f "$KEY" ]]; then
    echo "TLS certificates already exist, skipping generation."
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
    -days 365 -nodes -subj "/CN=ergo.test" 2>/dev/null

echo "Generated self-signed TLS certificates."
