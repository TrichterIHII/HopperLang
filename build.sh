#!/bin/bash
echo "Build HopperLang Compiler..."

ZSTD_LIB="./zstd/lib/libzstd.a"

if [ ! -f "$ZSTD_LIB" ]; then
    echo "libzstd.a not found"
    exit 1
fi

echo "Local zstd foud: $ZSTD_LIB"

ALL_LIBS=$(find ./llvm/lib -name "libLLVM*.a" | sort -r | sed 's|.*/lib\(LLVM[^.]*\)\.a|-l\1|' | tr '\n' ' ')

echo "Compile compiler.cpp to hplc with RPATH..."

# -Wl,-rpath,@executable_path/llvm/lib  to set libary path
/usr/bin/clang++ -std=c++17 -frtti compiler.cpp -o hplc \
-I./llvm/include \
-I./zstd/lib \
-L./llvm/lib \
$ALL_LIBS \
$ZSTD_LIB \
-lz -lcurses -lm -lpthread \
-Wl,-rpath,@executable_path/llvm/lib

if [ -f "./hplc" ]; then
    echo "Build success! Compiler: ./hplc"
    echo ""
    echo "Usage:"
    echo "  ./hplc main.hpl output.o"
    echo "  clang output.o -o program"
    echo "  ./program"
else
    echo "Build failed!"
    exit 1
fi
