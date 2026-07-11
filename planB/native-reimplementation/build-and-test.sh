#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$ROOT/build"

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
  "$ROOT/recovered_primitives.cpp" \
  -o "$ROOT/build/recovered-primitives"

exec "$ROOT/build/recovered-primitives"
