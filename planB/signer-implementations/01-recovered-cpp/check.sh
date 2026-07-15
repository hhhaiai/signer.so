#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$HERE/src/recovered_primitives.cpp"
CXX_BIN="${CXX:-c++}"

[[ -f "$SOURCE" ]] || { echo "missing local source: $SOURCE" >&2; exit 1; }
command -v "$CXX_BIN" >/dev/null 2>&1 || { echo "C++ compiler not found: $CXX_BIN" >&2; exit 1; }

echo "+ $CXX_BIN -std=c++17 -Wall -Wextra -Werror -fsyntax-only $SOURCE"
"$CXX_BIN" -std=c++17 -Wall -Wextra -Werror -fsyntax-only "$SOURCE"
echo "recovered C++ compile-only check: PASS"
