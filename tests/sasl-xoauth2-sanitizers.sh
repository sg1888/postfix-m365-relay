#!/usr/bin/env bash
# Build the vendored sasl-xoauth2 with AddressSanitizer, LeakSanitizer and
# UndefinedBehaviorSanitizer and run upstream's unit tests under them.
#
# The shipped plugin is C++; upstream's tests prove behaviour but not memory
# safety, and 0.28 itself fixed a use-after-free. Under the sanitizers any
# out-of-bounds access, use-after-free, leak or undefined behaviour the tests
# reach aborts the run. Nothing here touches the shipped image: it compiles a
# throwaway copy inside a disposable Ubuntu container.
set -euo pipefail

cd "$(dirname "$0")/.."
base=${SANITIZER_BASE_IMAGE:-ubuntu:24.04}

# shellcheck disable=SC2016  # expanded inside the container
docker run --rm --network bridge -v "$PWD/vendor/sasl-xoauth2:/vendor:ro" "$base" bash -euo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  g++ make cmake pkg-config libsasl2-dev libcurl4-openssl-dev libjsoncpp-dev >/dev/null
cp -a /vendor/src /tmp/src
# Upstream docs need tools the plugin does not; the image build drops them too.
sed -i "/add_subdirectory(docs)/d" /tmp/src/CMakeLists.txt
flags="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -O1"
cmake -S /tmp/src -B /tmp/build -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="$flags" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null
cmake --build /tmp/build -j "$(nproc)" >/dev/null
cd /tmp/build
# One known leak, in upstream test code only: FakeGetPassword (xoauth2_test.cc)
# mallocs a fresh secret per call and never frees it. Under the Cyrus SASL
# callback contract the application owns that buffer (Postfix hands back its
# own), so the plugin rightly never frees it. Any other leak still fails.
echo "leak:FakeGetPassword" > /tmp/lsan.supp
LSAN_OPTIONS=suppressions=/tmp/lsan.supp:print_suppressions=0 \
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:strict_string_checks=1:detect_stack_use_after_return=1 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  ctest --output-on-failure
'
echo "ok vendored sasl-xoauth2 unit tests pass under ASan, LSan and UBSan on $base"
