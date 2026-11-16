#!/usr/bin/env bash
# language: bash, file: install.sh
set -e

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

[ -f wibeh4ck.py ] || { echo "[-] wibeh4ck.py not found. Run from repo root." >&2; exit 1; }

chmod +x wibeh4ck.py

bindir="$HOME/.local/bin"
mkdir -p "$bindir"
ln -sf "$root/wibeh4ck.py" "$bindir/wibeh4ck"
echo "[+] $bindir/wibeh4ck -> $root/wibeh4ck.py"

case ":$PATH:" in
    *":$bindir:"*) ;;
    *)  echo "[!] $bindir is not on PATH. Add to your shell rc:"
        echo "    export PATH=\"$bindir:\$PATH\"" ;;
esac

echo "[*] running --update (may take several minutes)..."
python3 wibeh4ck.py --update --no-clear

echo
echo "Done."
echo "  try:     wibeh4ck --help"
echo "  update:  wibeh4ck --update"
