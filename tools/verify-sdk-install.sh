#!/usr/bin/env bash
#
# Proves a developer can actually use every SESAME SDK the way the READMEs say
# to: take the one file for your language out of sesame-clients.tar.gz, drop it
# into your project, and call it.
#
# There is no package registry and no per-ecosystem manifest. That makes the
# tarball the entire distribution mechanism, so this check is the only thing
# standing between a release and a client nobody can consume. Each case builds
# a throwaway project, copies in the shim exactly as a developer would, then
# compiles and runs code that reads the client's protocol constant.
#
# Usage: tools/verify-sdk-install.sh [output-tarball]

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(tr -d '[:space:]' <"$root/VERSION")"

workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT

# Build the release tarball the same way the release workflow does, then
# consume only what comes out of it. Testing against clients/ directly would
# not catch a file the tarball fails to include.
tarball="${1:-$workspace/sesame-clients.tar.gz}"
echo -n "==> "
"$root/tools/package-clients.sh" "$tarball"
echo "==> version ${version}"

extracted="$workspace/extracted"
mkdir -p "$extracted"
tar -xzf "$tarball" -C "$extracted"
shims="$extracted/clients"

passed=()
failed=()

check() {
	local name="$1"
	shift
	echo "==> ${name}"
	if "$@"; then
		passed+=("$name")
	else
		echo "    FAILED: ${name}" >&2
		failed+=("$name")
	fi
}

# Go is the one client that is not copied. It lives inside the engine's own
# module, so `go get` at the tag resolves it like any other Go package and
# vendoring would be a downgrade.
consume_go() {
	local dir="$workspace/go"
	mkdir -p "$dir"
	cat >"$dir/go.mod" <<EOF
module use-sesame

go 1.24

require github.com/d31ma/sesame v0.0.0

replace github.com/d31ma/sesame => ${root}
EOF
	cat >"$dir/main.go" <<'EOF'
package main

import (
	"fmt"

	"github.com/d31ma/sesame/clients/go/sesame"
)

func main() { fmt.Println("go:", sesame.ProtocolVersion) }
EOF
	(cd "$dir" && GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1 && go run .)
}

consume_node() {
	local dir="$workspace/node"
	mkdir -p "$dir"
	cp "$shims/node/sesame.mjs" "$shims/node/sesame.d.mts" "$dir/"
	cat >"$dir/use.mjs" <<'EOF'
import { PROTOCOL_VERSION } from './sesame.mjs'

console.log('node:', PROTOCOL_VERSION)
EOF
	(cd "$dir" && node use.mjs)
}

consume_python() {
	local dir="$workspace/python"
	mkdir -p "$dir"
	cp "$shims/python/sesame.py" "$dir/"
	echo 'import sesame; print("python:", sesame.PROTOCOL_VERSION)' >"$dir/use.py"
	(cd "$dir" && python3 use.py)
}

consume_rust() {
	local dir="$workspace/rust"
	mkdir -p "$dir"
	cp "$shims/rust/sesame.rs" "$dir/"
	cat >"$dir/use.rs" <<'EOF'
mod sesame;

fn main() { println!("rust: {}", sesame::PROTOCOL_VERSION); }
EOF
	(cd "$dir" && rustc --edition 2021 use.rs -o use 2>/dev/null && ./use)
}

# The Java and Kotlin shims declare package ma.del.sesame, so they are copied
# into the matching directory the way any Java source is.
consume_java() {
	local dir="$workspace/java"
	mkdir -p "$dir/ma/del/sesame"
	cp "$shims/java/Sesame.java" "$dir/ma/del/sesame/"
	cat >"$dir/Use.java" <<'EOF'
import ma.del.sesame.Sesame;

public class Use {
    public static void main(String[] args) {
        System.out.println("java: " + Sesame.PROTOCOL_VERSION);
    }
}
EOF
	(cd "$dir" && javac -d out ma/del/sesame/Sesame.java Use.java && java -cp out Use)
}

consume_kotlin() {
	local dir="$workspace/kotlin"
	mkdir -p "$dir"
	cp "$shims/kotlin/Sesame.kt" "$dir/"
	cat >"$dir/Use.kt" <<'EOF'
import ma.del.sesame.PROTOCOL_VERSION

fun main() = println("kotlin: $PROTOCOL_VERSION")
EOF
	(cd "$dir" && kotlinc Sesame.kt Use.kt -include-runtime -d use.jar 2>/dev/null && java -jar use.jar)
}

consume_csharp() {
	local dir="$workspace/csharp"
	mkdir -p "$dir"
	(
		cd "$dir"
		dotnet new console -o app --force >/dev/null 2>&1
		cp "$shims/csharp/Sesame.cs" app/
		cat >app/Program.cs <<'EOF'
using Sesame;

Console.WriteLine("csharp: " + Client.ProtocolVersion);
EOF
		cd app && dotnet run --nologo -v quiet
	)
}

consume_php() {
	local dir="$workspace/php"
	mkdir -p "$dir"
	cp "$shims/php/sesame.php" "$dir/"
	php -r "require '$dir/sesame.php'; echo 'php: ' . \Sesame\Client::PROTOCOL_VERSION . PHP_EOL;"
}

consume_ruby() {
	local dir="$workspace/ruby"
	mkdir -p "$dir"
	cp "$shims/ruby/sesame.rb" "$dir/"
	echo "require_relative 'sesame'; puts 'ruby: ' + Sesame::PROTOCOL_VERSION" >"$dir/use.rb"
	(cd "$dir" && ruby use.rb)
}

consume_dart() {
	local dir="$workspace/dart"
	mkdir -p "$dir"
	cp "$shims/dart/sesame.dart" "$dir/"
	cat >"$dir/use.dart" <<'EOF'
import 'sesame.dart';

void main() => print('dart: $protocolVersion');
EOF
	(cd "$dir" && dart run use.dart)
}

check go consume_go
check node consume_node
check python consume_python
check rust consume_rust
check java consume_java
check kotlin consume_kotlin
check csharp consume_csharp
check php consume_php
check ruby consume_ruby
check dart consume_dart

echo
echo "==> ${#passed[@]} consumed successfully: ${passed[*]}"
if [[ ${#failed[@]} -gt 0 ]]; then
	echo "==> ${#failed[@]} failed: ${failed[*]}" >&2
	exit 1
fi
