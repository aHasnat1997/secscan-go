#!/usr/bin/env bash
set -euo pipefail

echo "==> Running tests..."
go test ./...

echo "==> Building static secscan binary in dist/..."
mkdir -p dist
CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/secscan .

echo "==> Installing to /usr/local/bin/secscan..."
sudo install -m755 dist/secscan /usr/local/bin/secscan

echo "==> Done!"
secscan --version
