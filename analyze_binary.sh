#!/bin/bash
# Analyse complète du binaire kexd

echo "════════════════════════════════════════════════════════════════"
echo "ANALYSE BINAIRE - TARNWICK TK-220 ENCODER"
echo "════════════════════════════════════════════════════════════════"

BINARY="./kexd"

if [ ! -f "$BINARY" ]; then
    echo "[-] Binaire $BINARY non trouvé!"
    exit 1
fi

echo ""
echo "[*] ÉTAPE 1: file ./kexd"
echo "────────────────────────────────────────────────────────────────"
file "$BINARY"

echo ""
echo "[*] ÉTAPE 2: checksec --file=./kexd"
echo "────────────────────────────────────────────────────────────────"
checksec --file="$BINARY"

echo ""
echo "[*] ÉTAPE 3: strings -a ./kexd | grep -Ei 'KX01|key|site|provision|secret'"
echo "────────────────────────────────────────────────────────────────"
strings -a "$BINARY" | grep -Ei 'KX01|key|site|provision|secret|FLAG|CTF|auth|decode|encode|PASSWORD'

echo ""
echo "[*] ÉTAPE 4: Toutes les strings significatives"
echo "────────────────────────────────────────────────────────────────"
strings -a "$BINARY" | head -100

echo ""
echo "[*] ÉTAPE 5: Recherche de patterns hex intéressants"
echo "────────────────────────────────────────────────────────────────"
strings -a "$BINARY" | grep -E '^[0-9A-F]{8,}$' | head -20

echo ""
echo "[+] Analyse terminée!"
