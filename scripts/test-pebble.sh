#!/bin/sh
set -eu
umask 077

cd "$(dirname "$0")/.."
command -v docker >/dev/null
command -v curl >/dev/null
docker info >/dev/null

test_dir=$(mktemp -d)
container="acme-client2-pebble-$$"
cleanup() {
    exit_code=$?
    trap - EXIT
    if [ "$exit_code" -ne 0 ]; then
        docker logs "$container" >&2 || true
    fi
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf "$test_dir"
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set --
if [ "$(uname -s)" = Linux ]; then
    set -- --add-host host.docker.internal:host-gateway
fi
docker run --detach --name "$container" \
    --publish 127.0.0.1::14000 --publish 127.0.0.1::15000 \
    --env PEBBLE_VA_ALWAYS_VALID=0 --env PEBBLE_VA_NOSLEEP=1 \
    --env PEBBLE_WFE_NONCEREJECT=0 --env PEBBLE_AUTHZREUSE=0 \
    --env PEBBLE_ALTERNATE_ROOTS=0 --env PEBBLE_CHAIN_LENGTH=1 \
    --mount "type=bind,src=$PWD/tests/pebble-config.json,dst=/test/pebble-config.json,readonly" \
    "$@" ghcr.io/letsencrypt/pebble:2.8.0@sha256:d9080f68f6cb6af8d82134ab26de0aaaf312ac9cba42aecc6d3aede6cb63007b \
    -config /test/pebble-config.json -strict=false

acme_address=$(docker port "$container" 14000/tcp)
management_address=$(docker port "$container" 15000/tcp)
curl --silent --show-error --fail --insecure \
    --retry 10 --retry-delay 1 --retry-connrefused --retry-all-errors \
    --connect-timeout 2 --max-time 3 \
    "https://$acme_address/dir" >/dev/null
curl --silent --show-error --fail --insecure --connect-timeout 2 --max-time 5 \
    "https://$management_address/roots/0" --output "$test_dir/root.pem"

PEBBLE_DIRECTORY_URL="https://$acme_address/dir" PEBBLE_TEST_DIR="$test_dir" \
    cargo test --locked --test pebble pebble_http01_issuance -- --ignored --exact --nocapture