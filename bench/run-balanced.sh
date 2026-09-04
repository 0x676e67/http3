#!/usr/bin/env bash
# Runs the http3, h3, and nghttp3 Clients on Linux, including WSL2.
#
# The Rust Clients use a Tokio current-thread runtime. The native nghttp3
# Client is built automatically by Cargo and uses one event-loop thread. This
# script intentionally sets no CPU affinity: the operating system may migrate
# Client threads, so results measure single-threaded Client throughput rather
# than strict single-core performance. The benchmark Server is a separate,
# unpinned 8-worker process. The native build requires CMake, a C compiler,
# LLVM/libclang, NASM, and pkg-config. Clone with --recurse-submodules or run
# `git submodule update --init --recursive` from the repository root before the
# first build. Each sample ends when the last complete response is validated;
# task aggregation, extra receive draining, final result checks, and shutdown
# are not included in its elapsed time.
#
# Default body-size cases:
#   bash bench/run-balanced.sh --topologies 4/1 -- --noplot
# Custom body-size cases:
#   bash bench/run-balanced.sh --topologies 4/1 \
#     --body-sizes 0B,64KiB,1MiB -- --noplot

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run-balanced.sh [options] [-- <criterion arguments>]

Options:
  --topologies VALUE   Comma-separated connections/sockets pairs (default: 1/1,4/1).
                       The shared comparison supports 1-4 connections and 1 socket;
                       request and in-flight totals must divide evenly.
  --body-sizes VALUE   Comma-separated IEC response sizes, up to 100 MiB.
  -h, --help           Show this help.

The Clients always run once in this fixed order: http3, h3, nghttp3. Cargo
builds the native nghttp3/ngtcp2 Client automatically. The native build requires
CMake, a C compiler, LLVM/libclang, NASM, and pkg-config. Criterion arguments
such as --sample-size and --measurement-time override the harness defaults.
The ngtcp2 and nghttp3 sources are Git submodules; clone with
--recurse-submodules or run `git submodule update --init --recursive` from the
repository root before the first build.

Default body sizes:
  0B,1KiB,10KiB,64KiB,128KiB,1MiB,2MiB,4MiB,100MiB

Examples:
  bash bench/run-balanced.sh -- --noplot
  bash bench/run-balanced.sh --topologies 4/1 \
    --body-sizes 0B,64KiB,1MiB -- \
    --sample-size 20 --measurement-time 60 --noplot
EOF
}

topologies='1/1,4/1'
body_sizes=
criterion_args=()

while (($# > 0)); do
  case $1 in
    --topologies)
      (($# >= 2)) || { echo '--topologies requires a value' >&2; exit 2; }
      topologies=$2
      shift 2
      ;;
    --body-sizes)
      (($# >= 2)) || { echo '--body-sizes requires a value' >&2; exit 2; }
      body_sizes=$2
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

export HTTP3_BENCH_TOPOLOGIES=$topologies
if [[ -n $body_sizes ]]; then
  export HTTP3_BENCH_BODY_SIZES=$body_sizes
else
  unset HTTP3_BENCH_BODY_SIZES || true
fi

echo 'Running HTTP/3 Clients in fixed order: http3, h3, nghttp3'
cargo bench -p http3-bench --bench clients -- "${criterion_args[@]}"
