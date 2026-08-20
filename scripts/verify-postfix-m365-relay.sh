#!/usr/bin/env bash
echo 'verify-postfix-m365-relay.sh retired: verification runs inside the container.' >&2
echo 'Run: docker exec postfix-m365-relay /usr/local/libexec/mail-relay/verify-relay.sh' >&2
exit 1
