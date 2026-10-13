#!/usr/bin/env bash
# Prove vendor/sasl-xoauth2/src is the unmodified upstream commit recorded in
# vendor/sasl-xoauth2/UPSTREAM (Git tree hash, ChangeLog version, license
# present). Offline; part of tests/static.sh. The online counterpart,
# `vendor/sasl-xoauth2/update.sh --verify`, runs in the CI suite.
set -euo pipefail
cd "$(dirname "$0")/.."
vendor/sasl-xoauth2/update.sh --check
