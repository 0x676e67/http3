#!/usr/bin/env bash
# One Actions step owns one concurrency level. Reuse the executable built
# by the workflow; compile/setup work must not run alongside Client samples.
# Usage: BENCH_EXE=/path/to/clients bash bench/ci.sh 1 [Criterion options]
# Append --list to inspect coverage or --test for a functional smoke check.
# Default comparison: fixed browser templates in both directions, static and
# bidirectional dynamic QPACK. HTTP3_BENCH_SUITE=diagnostic selects all directions.
# With GITHUB_STEP_SUMMARY set, append a table from measured Criterion JSON.
set -euo pipefail

concurrency=${1:?missing concurrency (1, 10, 50, or 100)}
shift
case "$concurrency" in
  1|10|50|100) ;;
  *) printf 'Concurrency must be 1, 10, 50, or 100: %s\n' "$concurrency" >&2; exit 2 ;;
esac
export HTTP3_BENCH_CONCURRENCY=$concurrency
export HTTP3_BENCH_REQUESTS=1000
suite=${HTTP3_BENCH_SUITE:-comparison}
case "$suite" in
  comparison) header_modes=(both); qpack_modes=(none both) ;;
  diagnostic) header_modes=(none request response both); qpack_modes=(none request response both) ;;
  *) printf 'Unknown benchmark suite: %s\n' "$suite" >&2; exit 1 ;;
esac

if [[ -n ${HTTP3_BENCH_RESULTS:-} ]]; then
  # Keep smoke runs and other suites out of the published measurement tables.
  export CRITERION_HOME="$HTTP3_BENCH_RESULTS/$suite/concurrency-$concurrency"
fi

summarize=true
for argument in "$@"; do
  case "$argument" in --list|--test) summarize=false ;; esac
done

for body in 1KiB 10KiB 100KiB 0B; do
  export HTTP3_BENCH_BODY_SIZES=$body
  body_label=$body
  if [[ $body == 0B ]]; then
    body_label='0 B (headers and scheduling diagnostic)'
  fi
  for headers in "${header_modes[@]}"; do
    export HTTP3_BENCH_HEADERS=$headers
    for qpack in "${qpack_modes[@]}"; do
      export HTTP3_BENCH_QPACK=$qpack
      if [[ $qpack == none ]]; then
        label=static
      else
        label="dynamic $qpack"
      fi
      printf '::group::Body: %s / Headers: %s / QPACK: %s\n' \
        "$body_label" "$headers" "$label"
      # Without --bench, directly invoking Criterion selects its test mode.
      # The runner keeps the http3/h3/nghttp3 order and excludes unsupported h3
      # dynamic modes. All directions use the same batch and timing parameters.
      "${BENCH_EXE:?missing prebuilt benchmark executable}" --bench \
        --sample-size 10 --measurement-time 3 --warm-up-time 1 --noplot "$@"
      printf '::endgroup::\n'
    done
  done
done

if [[ $summarize == true && -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  python3 "$(dirname "${BASH_SOURCE[0]}")/summary.py" \
    "${CRITERION_HOME:?missing Criterion output directory}" \
    "$concurrency" "$suite" >> "$GITHUB_STEP_SUMMARY"
fi
