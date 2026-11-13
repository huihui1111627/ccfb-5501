#!/usr/bin/env bash
# Build the fuzzing target + persistent worker.
#   build.sh            -> buggy variant (default, used by fuzzing)
#   build.sh --fixed    -> repaired variant (used by regression)
set -eo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/build"
mkdir -p "$OUT"

MODE="buggy"
DEFS=()
if [[ "${1:-}" == "--fixed" ]]; then
  MODE="fixed"
  DEFS+=(-DDL645_FIXED)
fi

CC="${CC:-clang}"
COMMON=(-O1 -g -fno-omit-frame-pointer -I"$ROOT/target")

# The target library must carry the coverage instrumentation, the worker
# happens to also define the callbacks, so build them separately.
"$CC" "${COMMON[@]}" "${DEFS[@]}" \
  -fsanitize=address -fsanitize-recover=address \
  -fsanitize-coverage=trace-pc-guard,trace-cmp \
  -fno-sanitize-recover=undefined \
  -c "$ROOT/target/dl645.c" -o "$OUT/dl645-$MODE.o"

"$CC" "${COMMON[@]}" "${DEFS[@]}" \
  -fsanitize=address -fsanitize-recover=address \
  -c "$ROOT/engine/worker.c" -o "$OUT/worker-$MODE.o"

"$CC" -g -fno-omit-frame-pointer -fsanitize=address \
  "$OUT/worker-$MODE.o" "$OUT/dl645-$MODE.o" -o "$OUT/worker-$MODE"

# Standalone target used for reproducing a crash with a plain <input> file.
cat > "$OUT/repro_main-$MODE.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int dl645_fuzz_one(const uint8_t *, size_t);
int main(int argc, char **argv)
{
    FILE *f;
    long n;
    uint8_t *buf;
    if (argc < 2) { fprintf(stderr, "usage: %s <input>\n", argv[0]); return 2; }
    f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
    buf = (uint8_t *)malloc(n ? (size_t)n : 1u);
    if (!buf) return 2;
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) return 2;
    fclose(f);
    /* the parser's status code is a protocol result, not a process result:
     * a malformed frame is an expected outcome for a fuzz input */
    (void)dl645_fuzz_one(buf, (size_t)n);
    return 0;
}
EOF
"$CC" "${COMMON[@]}" "${DEFS[@]}" -fsanitize=address \
  "$OUT/repro_main-$MODE.c" "$OUT/dl645-$MODE.o" -o "$OUT/repro-$MODE"

echo "built $OUT/worker-$MODE and $OUT/repro-$MODE"
