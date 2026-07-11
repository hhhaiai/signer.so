#!/bin/sh
set -eu

script=$1
module=$2

set +e
output=$($script --abi x86_64 --module "$module" --pid 999999 2>&1)
status=$?
set -e

test "$status" -ne 0
printf '%s\n' "$output" | grep -F "QBDI headers/library" >/dev/null
printf '%s\n' "$output" | grep -F "target process" >/dev/null
printf '%s\n' "$output" | grep -F "target module" >/dev/null

