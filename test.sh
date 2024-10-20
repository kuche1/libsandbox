#! /usr/bin/env bash

set -euo pipefail

HERE=$(dirname "$BASH_SOURCE")

COMPILER='gcc'

FLAGS_STANDARD='-std=c99'
# `std99` doesn't allow for `kill`

FLAGS_STRICT='-Werror -Wextra -Wall -pedantic -Wfatal-errors -Wshadow'

FLAGS_LIBRARIES='-lseccomp'
# note that we can't have both `-static` and `-lseccomp`

FLAGS_OPTIMISATION='-Ofast'

FLAGS="$FLAGS_STANDARD $FLAGS_STRICT $FLAGS_LIBRARIES $FLAGS_OPTIMISATION"

clear

"$HERE/compile.sh"

$COMPILER $FLAGS -o "$HERE/test1" "$HERE/test/test1.c" "$HERE/libsandbox.a"

"$HERE/test1"
