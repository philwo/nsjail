#!/bin/bash
# Checks the mounts that both mount backends build for a jail: which are
# read-only or writable, and that building them leaves the sources unchanged.
#
# The test prepares bind sources with nested mounts in a user and mount namespace
# of its own, so it needs neither root nor changes to the host. It needs
# unshare(1) with --map-auto, which maps ids through newuidmap(1): nsjail calls
# setgroups(), which an `unshare -r` namespace denies. Without it, the test
# skips itself.
set -u

NSJAIL_BIN=$(realpath "${NSJAIL_BIN:-./nsjail}")

# Re-run this script in a fresh user and mount namespace.
if [ -z "${NSJAIL_MNT_TEST_DIR:-}" ]; then
	if ! unshare --map-auto --map-root-user -m true 2>/dev/null; then
		echo "SKIP: unshare --map-auto --map-root-user is unavailable"
		exit 0
	fi
	dir=$(mktemp -d "${TMPDIR:-/tmp}/nsjail-mnt-test.XXXXXX")
	trap 'rm -rf "$dir"' EXIT
	NSJAIL_MNT_TEST_DIR=$dir unshare --map-auto --map-root-user -m --propagation private \
		"$0" "$@"
	exit
fi

# Build a minimal jail root from the host's system directories. A bind follows
# a symlink such as /bin -> usr/bin, so each one is a plain directory in the jail.
sysdirs=()
for d in /usr /bin /sbin /lib /lib64; do
	if [ -d "$d" ]; then
		sysdirs+=("$d")
	fi
done
sysroot=()
for d in "${sysdirs[@]}"; do
	sysroot+=(-R "$d")
done

# The jail has no /dev, so the probe closes stderr instead of using /dev/null.
probe='for p in "$@"; do
	if touch "$p/probe" 2>&-; then printf "%s=rw " "$p"; rm "$p/probe"; else printf "%s=ro " "$p"; fi
done'

failures=0

# fail NAME MESSAGE LOG
#
# Reports a failed check with the warnings and errors from nsjail's LOG.
fail() {
	echo "FAIL: $1: $2"
	grep -E '^\[(W|E|F)\]' "$3" | grep -v logParams | sed 's/^/    /'
	failures=$((failures + 1))
}

# check NAME SETUP EXPECTED PATHS -- NSJAIL_FLAGS...
#
# For each backend, runs SETUP in a new directory $src, then checks that the
# jail, started with NSJAIL_FLAGS, sees each of the comma-separated PATHS as
# in EXPECTED, such as "/src=ro /src/sub=rw", and that nsjail left the files
# in $src unchanged. NSJAIL_FLAGS write $src as @SRC@. They come before the
# system binds, which a --config among them would otherwise replace.
check() {
	local name=$1 setup=$2 expected=$3 paths
	IFS=, read -ra paths <<<"$4"
	shift 5

	local be src before got
	for be in old new; do
		src=$NSJAIL_MNT_TEST_DIR/$name.$be
		mkdir -p "$src"
		eval "$setup"
		before=$(find "$src" | sort)

		got=$("$NSJAIL_BIN" -Mo -q --experimental_mnt "$be" "${@//@SRC@/$src}" "${sysroot[@]}" \
			-l "$src.log" -- /bin/sh -c "$probe" sh "${paths[@]}")
		got=${got% }
		if [ "$got" != "$expected" ]; then
			fail "$name ($be)" "got '$got', want '$expected'" "$src.log"
		elif [ "$(find "$src" | sort)" != "$before" ]; then
			fail "$name ($be)" "nsjail changed the files in the source" "$src.log"
		else
			echo "PASS: $name ($be)"
		fi
	done
}

# A tmpfs inside the bind source.
sub='mkdir "$src/sub"; mount -t tmpfs none "$src/sub"'

check ro_bind "$sub" "/src=ro /src/sub=ro" "/src,/src/sub" -- -R "@SRC@:/src"
check rw_bind_rw_root "$sub" "/src=rw /src/sub=rw" "/src,/src/sub" -- --rw -B "@SRC@:/src"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed"
	exit 1
fi
