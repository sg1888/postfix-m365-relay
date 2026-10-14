#!/usr/bin/env bash
# Fuzz the vendored sasl-xoauth2 plugin with libFuzzer, under AddressSanitizer
# and UndefinedBehaviorSanitizer, in the three places it parses untrusted-shaped
# data: the token file, the server's AUTH challenge, and a token refresh reply
# (tests/fuzz/fuzz_sasl_xoauth2.cc). Any crash, memory error, leak, undefined
# behaviour or hang fails the run and prints the input that triggered it.
#
# FUZZ_SECONDS (default 60) bounds the run. The image is untouched: this
# compiles a throwaway copy inside a disposable Ubuntu container.
set -euo pipefail

cd "$(dirname "$0")/.."
base=${SANITIZER_BASE_IMAGE:-ubuntu:24.04}
seconds=${FUZZ_SECONDS:-60}

# shellcheck disable=SC2016  # expanded inside the container
docker run --rm -e FUZZ_SECONDS="$seconds" \
  -v "$PWD/vendor/sasl-xoauth2:/vendor:ro" -v "$PWD/tests/fuzz:/fuzz:ro" \
  "$base" bash -euo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# llvm-18 provides llvm-symbolizer, so a finding names file and line.
apt-get install -y -qq --no-install-recommends clang libclang-rt-18-dev llvm-18 \
  pkg-config libsasl2-dev libcurl4-openssl-dev libjsoncpp-dev >/dev/null
src=/vendor/src/src
clang++ -std=c++17 -g -O1 -fno-omit-frame-pointer \
  -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
  -I"$src" -DCONFIG_FILE_FULL_PATH="\"/nonexistent/sasl-xoauth2.conf\"" \
  "$src"/client.cc "$src"/config.cc "$src"/http.cc "$src"/log.cc \
  "$src"/module.cc "$src"/token_store.cc /fuzz/fuzz_sasl_xoauth2.cc \
  $(pkg-config --cflags --libs jsoncpp libcurl libsasl2) -o /tmp/fuzz

# Seeds: one valid example per mode (first byte selects the mode).
mkdir -p /tmp/seeds /tmp/corpus /tmp/crash
expiry=$(( $(date +%s) + 3600 ))
printf "\\000{\"access_token\":\"a\",\"refresh_token\":\"r\",\"expiry\":\"%s\"}" "$expiry" > /tmp/seeds/token
printf "\\000{\"refresh_token\":\"r\",\"expiry\":\"0\",\"user\":\"u\",\"refresh_window\":\"60\"}" > /tmp/seeds/token-expired
printf "\\001{\"status\":\"401\",\"schemes\":\"Bearer\",\"scope\":\"x\"}" > /tmp/seeds/challenge-401
printf "\\001{\"status\":\"500\"}" > /tmp/seeds/challenge-500
printf "\\002{\"access_token\":\"n\",\"expires_in\":3599,\"refresh_token\":\"r2\"}" > /tmp/seeds/refresh

export ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-18/bin/llvm-symbolizer
echo "fuzzing for ${FUZZ_SECONDS}s"
if ! /tmp/fuzz -max_total_time="$FUZZ_SECONDS" -timeout=10 -rss_limit_mb=2048 \
     -dict=/fuzz/json.dict -artifact_prefix=/tmp/crash/ -print_final_stats=1 \
     /tmp/corpus /tmp/seeds 2>/tmp/fuzz.log; then
  # The whole sanitizer report (access and allocation stacks), else the tail.
  if grep -q "==ERROR" /tmp/fuzz.log; then
    sed -n "/==ERROR/,/^SUMMARY/p" /tmp/fuzz.log
  else
    tail -n 60 /tmp/fuzz.log
  fi
  for f in /tmp/crash/*; do echo "reproducer $f (base64):"; base64 "$f"; done
  exit 1
fi
grep -E "stat::number_of_executed_units|stat::new_units_added|cov:" /tmp/fuzz.log | tail -n 3
'
echo "ok vendored sasl-xoauth2 survived ${seconds}s of libFuzzer under ASan and UBSan"
