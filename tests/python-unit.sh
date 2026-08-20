#!/usr/bin/env bash
# Run offline Python tests inside the release image. This deliberately avoids a
# developer virtualenv whose cryptography/OpenSSL versions could differ from the
# image that will actually rotate credentials.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
docker run --rm --network none --entrypoint python3 \
  -v "$PWD":/workspace:ro -w /workspace \
  "$image" /workspace/tests/test_runtime_python.py
