#!/usr/bin/env bash
# Builds small, useful text files from the strings embedded in the library.
set -u
LIB="$1"; OUT="$2"; mkdir -p "$OUT"
TMP="$(mktemp)"

{
  echo "== file ==";          file "$LIB"
  echo "== size ==";          ls -la "$LIB"
  echo "== elf header ==";    readelf -h "$LIB" | grep -E "Class|Machine|Type|Entry"
  echo "== build id ==";      readelf -n "$LIB" | grep -i "build id"
  echo "== load segments =="; readelf -lW "$LIB" | grep -E "LOAD"
} > "$OUT/info.txt" 2>&1

strings -a -t x -n 6 "$LIB" > "$TMP"

# Source files the game was built from (a map of the code base)
grep -oE "handheld/[A-Za-z0-9_./-]+\.(cpp|h|hpp)" "$TMP" | sort -u > "$OUT/source_files.txt"
sed 's|/[^/]*$||' "$OUT/source_files.txt" | sort | uniq -c | sort -rn > "$OUT/source_dirs.txt"

# Readable function names (compiler-embedded) related to rendering
grep -E "::[A-Za-z_~0-9<>]+\(" "$TMP" \
  | grep -iE "render|particle|cull|frustum|visib|occlu|chunk|mesh|draw|lod|fog|weather|cloud|sky|shadow|entity|actor|animat|batch" \
  > "$OUT/render_funcs.txt"

{
  echo "source files:  $(wc -l < "$OUT/source_files.txt")"
  echo "render funcs:  $(wc -l < "$OUT/render_funcs.txt")"
} > "$OUT/counts.txt"
rm -f "$TMP"
cat "$OUT/info.txt" "$OUT/counts.txt"
