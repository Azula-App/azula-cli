#!/usr/bin/env bash
# End-to-end check of `azula compute` from a cloud sandbox (Claude Code / Codex).
#
# Needs: AZULA_COMPUTE_TOKEN from `azula compute grant` on the Mac host, a
# running `azula compute serve` there with the VM created, and the n0 relay
# hosts plus dns.iroh.link allowlisted in the sandbox's egress (azula-cli
# README). Covers the scenario-catalog rows a real sandbox can exercise
# (openspec change remote-compute-vm, design.md): H1-H4, H8, S4, S7, S9.
#
#   AZULA_COMPUTE_TOKEN=azc1.… vm/e2e/cloud.sh [path/to/azula] [vm-name]
#
# Each step prints PASS/FAIL; the script exits nonzero on the first failure.
set -uo pipefail

AZULA=${1:-target/release/azula}
export AZULA_COMPUTE_VM=${2:-build}
export AZULA_RELAY_ONLY=${AZULA_RELAY_ONLY:-1}
: "${AZULA_COMPUTE_TOKEN:?set AZULA_COMPUTE_TOKEN}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { printf '\n== %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
c() { "$AZULA" compute "$@"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

step "doctor, start the VM, doctor the guest (H1)"
c doctor || fail "doctor"
"$AZULA" vm start "$AZULA_COMPUTE_VM" || fail "vm start"
c doctor --vm "$AZULA_COMPUTE_VM" || fail "doctor --vm"
pass "every stage, including the guest worker"

step "identity of the remote machine"
out=$(c exec -q -- uname -sm) || fail "uname"
[ "$out" = "Linux aarch64" ] || fail "expected 'Linux aarch64', got '$out'"
pass "runs in the arm64 Linux guest"

step "exit code and separate streams (H2)"
c exec -q -- sh -c 'echo to-stdout; echo to-stderr >&2; exit 7' >"$work/o" 2>"$work/e"
rc=$?
[ "$rc" = 7 ] || fail "exit code $rc, want 7"
grep -qx to-stdout "$work/o" || fail "stdout"
grep -q to-stderr "$work/e" || fail "stderr"
grep -q to-stderr "$work/o" && fail "stderr leaked into stdout"
pass "exit 7, stdout/stderr separate"

step "connection drop mid-stream: reattach with exact bytes (S4)"
seq 1 300000 >"$work/expect"
AZULA_COMPUTE_FAULT=drop-after:400000 c exec -q -- seq 1 300000 >"$work/got" 2>"$work/err"
rc=$?
cat "$work/err"
[ "$rc" = 0 ] || fail "exit $rc"
grep -q 'reattach' "$work/err" || fail "the fault never fired (no reattach notice)"
[ "$(sha "$work/got")" = "$(sha "$work/expect")" ] || fail "output differs after reattach"
pass "$(wc -c <"$work/got") bytes, identical after a forced drop"

step "resumable push + pull with forced drops (S7, H4)"
head -c 9000000 /dev/urandom >"$work/blob"
AZULA_COMPUTE_FAULT=drop-after:3000000 c push "$work/blob" e2e/blob.bin 2>"$work/err" || { cat "$work/err"; fail "push"; }
cat "$work/err"
AZULA_COMPUTE_FAULT=drop-after:3000000 c pull e2e/blob.bin "$work/blob.back" 2>"$work/err" || { cat "$work/err"; fail "pull"; }
cat "$work/err"
[ "$(sha "$work/blob")" = "$(sha "$work/blob.back")" ] || fail "round trip differs"
remote=$(c exec -q -- sha256sum e2e/blob.bin | cut -d' ' -f1)
[ "$remote" = "$(sha "$work/blob")" ] || fail "guest copy differs"
pass "9 MB through two forced drops, sha256 identical on all three copies"

step "push a source tree, build it in the VM, pull the binary back (H4)"
mkdir -p "$work/src/lib" "$work/out"
cat >"$work/src/hello.c" <<'EOF'
#include <stdio.h>
#include <sys/utsname.h>
#include "lib/msg.h"
int main(void) { struct utsname u; uname(&u); printf("%s from %s on %s\n", MSG, u.nodename, u.machine); return 0; }
EOF
echo '#define MSG "hello"' >"$work/src/lib/msg.h"
c push -r "$work/src" e2e/src || fail "push -r"
c exec -q --timeout 15m -- sh -c 'command -v cc >/dev/null || { sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential >/dev/null; }; cd e2e/src && cc -O2 -o hello hello.c && ./hello' || fail "build in VM"
c pull e2e/src/hello "$work/out/hello" || fail "pull binary"
file "$work/out/hello" | tee /dev/stderr | grep -q 'ARM aarch64' || fail "artifact isn't an aarch64 ELF"
c pull -r e2e/src "$work/tree" || fail "pull -r"
[ -f "$work/tree/lib/msg.h" ] && [ -f "$work/tree/hello" ] || fail "pulled tree incomplete"
pass "tree in, aarch64 binary and tree out"

step "detach, list, attach, logs (H3)"
ref=$(c exec --detach --label e2e-detach -- sh -c 'for i in 1 2 3; do echo tick$i; sleep 1; done; exit 5') || fail "detach"
echo "job $ref"
c jobs | tee "$work/jobs" | grep -q "${ref#*/}" || fail "jobs doesn't list $ref"
c attach "$ref" >"$work/att"
rc=$?
[ "$rc" = 5 ] || fail "attach exit $rc, want 5"
[ "$(cat "$work/att")" = "$(printf 'tick1\ntick2\ntick3')" ] || fail "attach output: $(cat "$work/att")"
[ "$(c logs --tail 1 "$ref")" = "tick3" ] || fail "logs --tail 1"
pass "detached job replayed in full, exit 5 via attach"

step "client killed mid-job: the job finishes anyway (S9, H8)"
c exec -q --label e2e-survivor -- sh -c 'sleep 6; echo survived' >"$work/kill.out" 2>&1 &
cpid=$!
sleep 3
kill -KILL "$cpid" 2>/dev/null; wait "$cpid" 2>/dev/null
ref=$(c jobs --json | python3 -c 'import json,sys; print(next(j["ref"] for j in json.load(sys.stdin) if j.get("label")=="e2e-survivor"))') || fail "find survivor job"
c attach "$ref" >"$work/surv"
rc=$?
[ "$rc" = 0 ] && grep -qx survived "$work/surv" || fail "survivor: rc=$rc out=$(cat "$work/surv")"
pass "$ref finished after its client was SIGKILLed"

step "timeout"
start=$(date +%s)
c exec -q --timeout 3s -- sleep 60
rc=$?
took=$(( $(date +%s) - start ))
[ "$rc" = 124 ] || fail "timeout exit $rc, want 124"
[ "$took" -lt 20 ] || fail "timeout took ${took}s"
pass "timeout → 124 in ${took}s"

printf '\nALL PASS\n'
