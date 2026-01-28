#!/bin/bash
echo "Baue HopperLang Compiler..."

ZSTD_LIB="./zstd/lib/libzstd.a"

if [ ! -f "$ZSTD_LIB" ]; then
    echo "libzstd.a nicht gefunden!"
    exit 1
fi

echo "✓ Lokales zstd gefunden: $ZSTD_LIB"

ALL_LIBS=$(find ./llvm/lib -name "libLLVM*.a" | sort -r | sed 's|.*/lib\(LLVM[^.]*\)\.a|-l\1|' | tr '\n' ' ')

echo "Kompiliere compiler.cpp zu hplc (mit RPATH)..."

# WICHTIG: -Wl,-rpath,@executable_path/llvm/lib setzt den Library-Pfad
/usr/bin/clang++ -std=c++17 -frtti compiler.cpp -o hplc \
-I./llvm/include \
-I./zstd/lib \
-L./llvm/lib \
$ALL_LIBS \
$ZSTD_LIB \
-lz -lcurses -lm -lpthread \
-Wl,-rpath,@executable_path/llvm/lib

if [ -f "./hplc" ]; then
    echo "Build erfolgreich! Compiler: ./hplc"
    echo ""
    echo "Verwendung:"
    echo "  ./hplc main.hpl output.o"
    echo "  clang output.o -o program"
    echo "  ./program"
else
    echo "Build fehlgeschlagen!"
    exit 1
fi
