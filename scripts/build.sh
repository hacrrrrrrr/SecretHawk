#!/usr/bin/env bash
set -euo pipefail

mkdir -p bin
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/secrethawk ./cmd/secrethawk
echo "built bin/secrethawk"
