#!/usr/bin/env bash
# Runs the http3, h3, and nghttp3 Clients on Linux, including WSL2.
#
# The Rust Clients use a Tokio current-thread runtime. The native nghttp3
# Client is built automatically by Cargo and uses one event-loop thread. This
# script intentionally sets no CPU affinity: the operating system may migrate
# Client threads, so results measure single-threaded Client throughput rather
# than strict single-core performance. The benchmark Server is a separate,
# unpinned 8-worker process. The native build requires CMake, a C compiler,
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
#     --requests 20000 --concurrency 32 -- --noplot

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
  -h, --help           Show this help.

For each selected body size, the Clients run in this fixed order: http3, h3,
nghttp3. Cargo builds the native nghttp3/ngtcp2 Client automatically. The
native build requires CMake, a C compiler, LLVM/libclang, NASM, and pkg-config.
Criterion arguments such as --sample-size and --measurement-time override the
harness defaults. The published sys crates include the required C sources, so
repository submodules are not needed for this benchmark.

Default body sizes:
  0B,1KiB,10KiB,64KiB,128KiB,1MiB,2MiB,4MiB,100MiB

Examples:
  bash bench/run-balanced.sh -- --noplot
  bash bench/run-balanced.sh --body-sizes 0B,64KiB,1MiB \
    --requests 20000 --concurrency 32 -- \
    --sample-size 20 --measurement-time 60 --noplot
EOF
}

body_sizes=
requests=
concurrency=
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

echo 'Running each selected case in fixed Client order: http3, h3, nghttp3'
cargo bench -p bench --bench clients --locked -- "${criterion_args[@]}"
