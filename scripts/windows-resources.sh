#!/bin/sh
# Regenerate the Windows resource objects linked into updatecli.
#
# Windows installer detection treats an executable whose file name contains
# "update" as an installer when the image has no application manifest.
# winres/manifest.xml declares requestedExecutionLevel level="asInvoker" and
# uiAccess="false", which disables that heuristic. The generated objects sit
# beside main.go:
#
#   rsrc_windows_amd64.syso
#   rsrc_windows_arm64.syso
#
# Go links a *_GOOS_GOARCH.syso only for that target, so Linux and Darwin
# builds ignore these files. The objects are committed. make build, go build,
# and GoReleaser consume them as they are and do not run this compiler.
#
# After editing winres/manifest.xml, regenerate from the repository root and
# commit the two objects again:
#
#   ./scripts/windows-resources.sh
#
# Pinned compiler and invocation (github.com/akavel/rsrc v0.10.2):
#
#   go install github.com/akavel/rsrc@v0.10.2
#   rsrc -manifest winres/manifest.xml -arch amd64 -o rsrc_windows_amd64.syso
#   rsrc -manifest winres/manifest.xml -arch arm64 -o rsrc_windows_arm64.syso
#
# The script installs that module version, checks that the compiler accepts
# both amd64 and arm64, and only then writes either object. v0.10.2 stores a
# zero COFF timestamp, so running the script twice yields identical bytes.

set -eu

rsrc_module=github.com/akavel/rsrc@v0.10.2

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
manifest=$root/winres/manifest.xml

if [ ! -f "$manifest" ]; then
	echo "missing manifest: $manifest" >&2
	exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

GOFLAGS='' GOBIN=$tmpdir go install "$rsrc_module"

if [ -x "$tmpdir/rsrc" ]; then
	rsrc=$tmpdir/rsrc
elif [ -x "$tmpdir/rsrc.exe" ]; then
	rsrc=$tmpdir/rsrc.exe
else
	echo "pinned rsrc binary was not installed from $rsrc_module" >&2
	exit 1
fi

# Arch() runs before the manifest is opened and before any object is written.
# A missing manifest therefore proves the architecture is accepted without
# touching rsrc_windows_*.syso.
probe_arch() {
	arch=$1
	if "$rsrc" -manifest "$tmpdir/missing-manifest.xml" -arch "$arch" -o "$tmpdir/probe_$arch.syso" >"$tmpdir/probe.out" 2>"$tmpdir/probe.err"; then
		echo "rsrc accepted a missing manifest for $arch" >&2
		exit 1
	fi
	if grep -q "unknown architecture" "$tmpdir/probe.err"; then
		echo "pinned rsrc does not support $arch" >&2
		cat "$tmpdir/probe.err" >&2
		exit 1
	fi
	if [ -e "$tmpdir/probe_$arch.syso" ]; then
		echo "rsrc wrote an object while probing $arch" >&2
		exit 1
	fi
	if ! grep -q "error opening manifest" "$tmpdir/probe.err"; then
		echo "could not confirm that pinned rsrc supports $arch" >&2
		cat "$tmpdir/probe.err" >&2
		exit 1
	fi
}

probe_arch amd64
probe_arch arm64

for arch in amd64 arm64; do
	"$rsrc" -manifest "$manifest" -arch "$arch" -o "$tmpdir/rsrc_windows_$arch.syso"
done

for arch in amd64 arm64; do
	mv "$tmpdir/rsrc_windows_$arch.syso" "$root/rsrc_windows_$arch.syso"
done
