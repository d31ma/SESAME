#!/usr/bin/env bash
#
# Builds sesame-clients.tar.gz: the one file per language that a developer
# copies into their project. This is SESAME's entire SDK distribution — there
# is no package registry and no per-ecosystem manifest.
#
# It exists as a script rather than a tar line in each workflow because CI and
# the release must produce byte-identical archives. A naive `tar clients`
# sweeps in whatever the contract tests last compiled, so a release cut after
# someone ran the C# suite would ship .dll and .pdb files inside a bundle
# advertised as source.
#
# Usage: tools/package-clients.sh <output-tarball>

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <output-tarball>" >&2
	exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$1"
case "$output" in
/*) ;;
*) output="$PWD/$output" ;;
esac
mkdir -p "$(dirname "$output")"

tar -czf "$output" -C "$root" \
	--exclude='bin' \
	--exclude='obj' \
	--exclude='build' \
	--exclude='target' \
	--exclude='__pycache__' \
	--exclude='node_modules' \
	--exclude='.dart_tool' \
	--exclude='*.jar' \
	--exclude='*.class' \
	--exclude='sesame-rust-contract' \
	clients

# The bundle is advertised as source. Anything compiled inside it is a
# packaging bug, and a silent one, so fail rather than ship it.
if compiled="$(tar -tzf "$output" | grep -E '\.(dll|pdb|exe|jar|class|so|dylib|o)$' || true)"; [[ -n "$compiled" ]]; then
	echo "error: the client bundle contains compiled artifacts:" >&2
	echo "$compiled" >&2
	exit 1
fi

echo "built $(basename "$output") ($(du -h "$output" | cut -f1), $(tar -tzf "$output" | grep -cv '/$') files)"
