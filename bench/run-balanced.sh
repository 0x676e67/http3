#!/usr/bin/env bash
# Runs the HTTP/3 Clients against a native nghttp3/ngtcp2 Server on Linux/macOS.
#
# The Rust Clients use a Tokio current-thread runtime. Cargo builds the native
# nghttp3 Client and Server; each uses one event-loop thread. This script sets
# no CPU affinity: the operating system may migrate
# Client threads, so results measure single-threaded Client throughput rather
# than strict single-core performance. The Server is a separate, unpinned process.
# All Clients use the same Server, validation, response content, and transport
# settings. Its single worker may limit throughput; these results do not establish
# a Client-only ceiling. The native build requires CMake, a C compiler,
# LLVM/libclang and pkg-config (NASM is for applicable x86 builds, not ARM Macs).
# On macOS, use the Xcode command-line tools and make CMake available in PATH.
# The published sys crates include the
# required C sources, so repository submodules are not needed. Each batch timer
# includes request-state allocation, connection establishment, all response
# validation and normal task aggregation. Runtime, trust/TLS configuration,
# socket and address preparation precede it; shutdown and result serialization
# follow it.
# Each Client uses one HTTP/3 connection and one UDP socket. Concurrent
# requests use streams on that connection, following RFC 9114 Section 3.3:
# https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3
#
# Default body-size cases:
#   bash bench/run-balanced.sh -- --noplot
# Custom body-size cases:
#   bash bench/run-balanced.sh --body-sizes 0B,64KiB,1MiB \
#     --requests 20000 --concurrency 32 --headers both --qpack all -- --noplot

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run-balanced.sh [options] [-- <criterion arguments>]

Options:
  --body-sizes VALUE   Comma-separated IEC response sizes, up to 100 MiB.
  --requests VALUE     Requests per Criterion iteration, from 1 to 20000.
                       By default the benchmark chooses it from the body size.
  --concurrency VALUE  Maximum concurrent request streams on the one connection.
                       Range: 1-100. By default the benchmark chooses it from
                       the body size; it cannot exceed a case's request count.
                       The Server advertises a fixed 1000-stream credit window.
  --headers MODE      Header templates: none, request, response, both (default).
                       Request: 12 Chrome navigation fields plus 5 custom fields.
                       Response: 12 designed fields. Each field appears once.
                       Counts exclude pseudo-headers, status, and content-length.
                       Both exercises Client QPACK encoding and decoding;
                       request or response isolates the added work's direction.
  --qpack MODE        Dynamic compression: none, request, response, both, all (default).
                       Independent of --headers: request enables Client encoding,
                       response enables Client decoding. Capacity: 4096 bytes;
                       permitted blocked streams: 100. h3 runs only none.
                       The Server verifies actual references; allow enough requests
                       to reuse the table after setup (e.g. 128 at concurrency 4).
  -h, --help           Show this help.

For each body size, --qpack all runs none, request, response, both in that order.
Static cases run Clients http3, h3, nghttp3; dynamic cases run http3, nghttp3.
The pinned h3 Client only supports static QPACK and is explicitly skipped otherwise.
Result names begin with the Client and include server-nghttp3-native-4 and /qpack-MODE.
Each batch uses one timer covering request-state allocation, connection
establishment, all response validation and normal task aggregation. Runtime,
certificate trust/TLS configuration, UDP endpoint/socket and address preparation
happen before timing. Shutdown and result serialization are excluded.
Each batch starts with a fresh QPACK table.
Cargo builds the native nghttp3/ngtcp2 Client and Server automatically. The
native build requires CMake, a C compiler, LLVM/libclang, and pkg-config.
macOS requires Xcode command-line tools; ARM Macs do not require NASM.
Criterion arguments such as --sample-size and --measurement-time override the
harness defaults. The published sys crates include the required C sources, so
repository submodules are not needed for this benchmark.

Default body sizes:
  0B,1KiB,10KiB,64KiB,128KiB,1MiB,2MiB,4MiB,100MiB

Examples:
  bash bench/run-balanced.sh -- --noplot
  bash bench/run-balanced.sh --body-sizes 0B,1KiB --headers response --qpack response -- --noplot
  bash bench/run-balanced.sh --body-sizes 0B,1KiB,100KiB \
    --requests 128 --concurrency 4 --qpack all -- --test
  bash bench/run-balanced.sh --body-sizes 0B,64KiB,1MiB \
    --requests 20000 --concurrency 32 --headers both --qpack all -- \
    --sample-size 20 --measurement-time 60 --noplot
EOF
}

body_sizes=
requests=
concurrency=
headers=both
qpack=all
criterion_args=()

while (($# > 0)); do
  case $1 in
    --body-sizes)
      (($# >= 2)) || { echo '--body-sizes requires a value' >&2; exit 2; }
      body_sizes=$2
      shift 2
      ;;
    --requests)
      (($# >= 2)) || { echo '--requests requires a value' >&2; exit 2; }
      [[ $2 =~ ^[1-9][0-9]*$ ]] || {
        echo '--requests must be a positive integer' >&2
        exit 2
      }
      ((10#$2 <= 20000)) || {
        echo '--requests cannot exceed 20000' >&2
        exit 2
      }
      requests=$2
      shift 2
      ;;
    --concurrency)
      (($# >= 2)) || { echo '--concurrency requires a value' >&2; exit 2; }
      [[ $2 =~ ^[1-9][0-9]*$ ]] || {
        echo '--concurrency must be a positive integer' >&2
        exit 2
      }
      ((10#$2 <= 100)) || {
        echo '--concurrency cannot exceed 100' >&2
        exit 2
      }
      concurrency=$2
      shift 2
      ;;
    --headers)
      (($# >= 2)) || { echo '--headers requires a value' >&2; exit 2; }
      case $2 in
        none|request|response|both) headers=$2 ;;
        *) echo '--headers must be none, request, response, or both' >&2; exit 2 ;;
      esac
      shift 2
      ;;
    --qpack)
      (($# >= 2)) || { echo '--qpack requires a value' >&2; exit 2; }
      case $2 in
        none|request|response|both|all) qpack=$2 ;;
        *) echo '--qpack must be none, request, response, both, or all' >&2; exit 2 ;;
      esac
      shift 2
      ;;
    --)
      shift
      criterion_args=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case $(uname -s) in
  Linux|Darwin) ;;
  *)
    echo "unsupported operating system: $(uname -s)" >&2
    exit 2
    ;;
esac

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/.." && pwd -P)
cd "$repo_root"

if [[ -n $body_sizes ]]; then
  export HTTP3_BENCH_BODY_SIZES=$body_sizes
else
  unset HTTP3_BENCH_BODY_SIZES || true
fi
if [[ -n $requests ]]; then
  export HTTP3_BENCH_REQUESTS=$requests
else
  unset HTTP3_BENCH_REQUESTS || true
fi
if [[ -n $concurrency ]]; then
  export HTTP3_BENCH_CONCURRENCY=$concurrency
else
  unset HTTP3_BENCH_CONCURRENCY || true
fi
export HTTP3_BENCH_HEADERS=$headers
export HTTP3_BENCH_QPACK=$qpack

echo 'Server: nghttp3/ngtcp2, one native event loop; static Clients: http3, h3, nghttp3; dynamic Clients: http3, nghttp3'
# Bash 3.2 on macOS treats an empty array as unset under `set -u`.
cargo bench -p bench --bench clients --locked -- ${criterion_args[@]+"${criterion_args[@]}"}
