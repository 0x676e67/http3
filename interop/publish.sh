#!/usr/bin/env sh
set -eu

execute=0
registry="crates-io"
token=""
delay_seconds=30

usage() {
    cat <<'USAGE'
Usage: interop/publish.sh [OPTIONS]

Options:
  --execute              publish for real instead of running cargo publish --dry-run
  --registry NAME        registry name, default: crates-io
  --token TOKEN          cargo registry token
  --delay-seconds N      delay between real publishes, default: 30
  -h, --help             show this help
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --execute)
            execute=1
            shift
            ;;
        --registry)
            if [ "$#" -lt 2 ]; then
                echo "--registry requires a value" >&2
                exit 2
            fi
            registry="$2"
            shift 2
            ;;
        --token)
            if [ "$#" -lt 2 ]; then
                echo "--token requires a value" >&2
                exit 2
            fi
            token="$2"
            shift 2
            ;;
        --delay-seconds)
            if [ "$#" -lt 2 ]; then
                echo "--delay-seconds requires a value" >&2
                exit 2
            fi
            delay_seconds="$2"
            shift 2
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

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
tmp_root="${TMPDIR:-/tmp}/http3-rs-publish-$$"

cd "$repo_root"

if [ -n "$(git status --porcelain)" ]; then
    echo "warning: working tree is not clean. Review changes before publishing." >&2
fi

cleanup() {
    case "$tmp_root" in
        ""|"/"|"/tmp"|"/var/tmp")
            echo "refusing to remove unsafe temporary path: $tmp_root" >&2
            ;;
        *)
            rm -rf "$tmp_root"
            ;;
    esac
}
trap cleanup EXIT INT TERM

if [ -e "$tmp_root" ]; then
    echo "temporary path already exists: $tmp_root" >&2
    exit 1
fi

echo "Preparing temporary publish workspace: $tmp_root"
mkdir "$tmp_root"
tar -cf - \
    --exclude='./.git' \
    --exclude='*/.git' \
    --exclude='./target' \
    --exclude='*/target' \
    . | (cd "$tmp_root" && tar -xf -)

for manifest in \
    interop/crates/nghttp3-sys/Cargo.toml \
    interop/crates/ngtcp2-sys/Cargo.toml \
    interop/crates/ngtcp2/Cargo.toml \
    interop/crates/tokio-ngtcp2/Cargo.toml
do
    tmp_manifest="$manifest.tmp"
    awk -v registry="$registry" '
        /^publish = false$/ {
            print "publish = [\"" registry "\"]"
            changed = 1
            next
        }
        { print }
        END {
            if (!changed) {
                exit 42
            }
        }
    ' "$tmp_root/$manifest" > "$tmp_root/$tmp_manifest" || {
        echo "failed to enable publish in $manifest" >&2
        exit 1
    }
    mv "$tmp_root/$tmp_manifest" "$tmp_root/$manifest"
done

cd "$tmp_root"

manifests="
interop/crates/nghttp3-sys/Cargo.toml
interop/crates/ngtcp2-sys/Cargo.toml
interop/crates/ngtcp2/Cargo.toml
interop/crates/tokio-ngtcp2/Cargo.toml
"

for manifest in $manifests; do
    set -- publish --manifest-path "$manifest" --registry "$registry"
    if [ "$execute" -eq 0 ]; then
        set -- "$@" --dry-run
    fi
    if [ -n "$token" ]; then
        set -- "$@" --token "$token"
    fi

    printf 'cargo'
    for arg do
        printf ' %s' "$arg"
    done
    printf '\n'

    cargo "$@"

    if [ "$execute" -eq 1 ] && [ "$manifest" != "interop/crates/tokio-ngtcp2/Cargo.toml" ] && [ "$delay_seconds" -gt 0 ]; then
        echo "Waiting $delay_seconds seconds for registry index propagation..."
        sleep "$delay_seconds"
    fi
done
