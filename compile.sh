#! /usr/bin/env bash

set -euo pipefail

HERE=$(dirname "$BASH_SOURCE")

COMPILER='gcc'

FLAGS_STANDARD='-std=gnu99'
# `std99` doesn't allow for `kill`

FLAGS_STRICT='-Werror -Wextra -Wall -pedantic -Wfatal-errors -Wshadow'

FLAGS_LIBRARIES=''

FLAGS_OPTIMISATION='-Ofast'

FLAGS="$FLAGS_STANDARD $FLAGS_STRICT $FLAGS_LIBRARIES $FLAGS_OPTIMISATION"

clear

# create dynamic library
$COMPILER $FLAGS -o "$HERE/libsandbox.o" -c "$HERE/src/libsandbox.c"

# create static library
ar rcs "$HERE/libsandbox.a" "$HERE/libsandbox.o"
