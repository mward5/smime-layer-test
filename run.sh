#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Build smime-layers against an Evolution build tree and run it on test
# messages. HOME is pointed at a throwaway directory, because camel_init()
# opens ~/.pki/nssdb; the real NSS database is never touched.
#
# Usage: EVO_BUILD=/path/to/evolution/build [PREFIX=/usr] run.sh [--html] [message...]
#   EVO_BUILD  a configured and built Evolution CMake build directory
#   PREFIX     where the matching evolution-data-server is installed (default /usr)
#   NSSDB      NSS database to verify and decrypt with (default ./nssdb, from make-certs.sh)
#   message    default: messages/*.eml, from make-messages.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${EVO_BUILD:?set EVO_BUILD to an Evolution build directory}"
PREFIX=${PREFIX:-/usr}
NSSDB=$(realpath "${NSSDB:-nssdb}")
FLAGS=$EVO_BUILD/src/em-format/CMakeFiles/evolution-mail-formatter.dir/flags.make

[ -f "$FLAGS" ] || { echo "error: $FLAGS not found; is EVO_BUILD a built Evolution tree?" >&2; exit 1; }
[ -d certs ] || ./make-certs.sh >/dev/null
[ -d messages ] || ./make-messages.sh >/dev/null

INCLUDES=$(sed -n 's/^C_INCLUDES = //p' "$FLAGS")
LIBDIRS="$EVO_BUILD/src/em-format:$EVO_BUILD/src/e-util:$EVO_BUILD/src/shell:$EVO_BUILD/src/smime/lib:$EVO_BUILD/src/smime/gui:$PREFIX/lib"

# shellcheck disable=SC2086
cc -o smime-layers smime-layers.c $INCLUDES \
	-L"$EVO_BUILD/src/em-format" -levolution-mail-formatter \
	-L"$PREFIX/lib" -lcamel-1.2 -ledataserver-1.2 \
	$(PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig pkg-config --libs gtk+-3.0) \
	-Wl,-rpath,"$LIBDIRS"

rm -rf home && mkdir -p home/.pki && ln -s "$NSSDB" home/.pki/nssdb

args=() html=()
for a in "$@"; do
	if [ "$a" = --html ]; then html=(--html); else args+=("$a"); fi
done
[ ${#args[@]} -gt 0 ] || args=(messages/*.eml)

HOME=$PWD/home XDG_DATA_HOME=$PWD/home/data XDG_CONFIG_HOME=$PWD/home/config XDG_CACHE_HOME=$PWD/home/cache \
	GSETTINGS_SCHEMA_DIR=$EVO_BUILD/data \
	./smime-layers "${html[@]}" "${args[@]}"
