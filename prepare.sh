#!/usr/bin/env bash
# Usage: bash prepare.sh /sdcard/Download/libminecraftpe.so [repo-name]
set -euo pipefail
LIB="${1:?usage: bash prepare.sh /path/to/libminecraftpe.so [repo-name]}"
REPO="${2:-mc-ghidra}"
[ -f "$LIB" ] || { echo "File not found: $LIB"; exit 1; }
for c in xz split git gh; do
  command -v "$c" >/dev/null || { echo "Missing '$c'. Run: pkg install -y xz-utils coreutils git gh"; exit 1; }
done

mkdir -p parts
rm -f parts/part_*
echo "Compressing and splitting (a few minutes, no output until done)..."
xz -T0 -6 -c "$LIB" | split -b 90M -d -a 3 - parts/part_
du -sh parts
ls parts

git init -q -b main 2>/dev/null || git init -q
git checkout -q -B main
git add -A
git -c user.name="mc-re" -c user.email="mc-re@example.invalid" commit -q -m "Add library parts and Ghidra workflow" || true

# 'workflow' scope is required to push .github/workflows files
gh auth status >/dev/null 2>&1 || gh auth login -h github.com -p https -w -s workflow
gh auth setup-git
git config http.postBuffer 524288000

echo "Creating PRIVATE repo '$REPO' and pushing (needs a good connection)..."
gh repo create "$REPO" --private --source=. --remote=origin --push
echo
echo "Done. Open the repo on github.com -> Actions tab to watch the run."
