#!/usr/bin/env bash
# Runs the http3, h3, and nghttp3 Clients against both http3 and h3 Servers on Linux.
#
# The Rust Clients use a Tokio current-thread runtime. The native nghttp3
# Client is built automatically by Cargo and uses one event-loop thread. This
# script intentionally sets no CPU affinity: the operating system may migrate
# Client threads, so results measure single-threaded Client throughput rather
# than strict single-core performance. The benchmark Server is a separate,
# unpinned 8-worker process, with shared validation and transport settings for
# both Server libraries. The native build requires CMake, a C compiler,
# LLVM/libclang, NASM, and pkg-config. The published sys crates include the
# required C sources, so repository submodules are not needed. Each sample ends
# when the last complete response is validated;
# task aggregation, extra receive draining, final result checks, and shutdown
# are not included in its elapsed time.
# Each Client uses one HTTP/3 connection and one UDP socket. Concurrent
# requests use streams on that connection, following RFC 9114 Section 3.3:
# https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3
#
# Default body-size cases:
#   bash bench/run-balanced.sh -- --noplot
# Custom body-size cases:
#   bash bench/run-balanced.sh --body-sizes 0B,64KiB,1MiB \
#     --requests 20000 --concurrency 32 --headers both -- --noplot

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
  -h, --help           Show this help.

For each selected body size, run the http3 Server and then the h3 Server.
Under each Server, Clients run in this fixed order: http3, h3, nghttp3.
Result names begin with the Client and include server-http3 or server-h3.
Cargo builds the native nghttp3/ngtcp2 Client automatically. The
native build requires CMake, a C compiler, LLVM/libclang, NASM, and pkg-config.
Criterion arguments such as --sample-size and --measurement-time override the
harness defaults. The published sys crates include the required C sources, so
repository submodules are not needed for this benchmark.

Default body sizes:
  0B,1KiB,10KiB,64KiB,128KiB,1MiB,2MiB,4MiB,100MiB

Examples:
  bash bench/run-balanced.sh -- --noplot
  bash bench/run-balanced.sh --body-sizes 0B,1KiB --headers response -- --noplot
  bash bench/run-balanced.sh --body-sizes 1KiB -- server-h3 --noplot
  bash bench/run-balanced.sh --body-sizes 0B,64KiB,1MiB \
    --requests 20000 --concurrency 32 --headers both -- \
    --sample-size 20 --measurement-time 60 --noplot
EOF
}

body_sizes=
requests=
concurrency=
headers=both
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
  Linux) ;;
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

echo 'Each body size: Server http3, then h3; each Server: Clients http3, h3, nghttp3'
cargo bench -p bench --bench clients --locked -- "${criterion_args[@]}"
