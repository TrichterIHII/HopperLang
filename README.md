# HopperLang

A programming language made for programmers. Try it out and enjoy it!

**Support:** [trichterih.dev@gmail.com](mailto:trichterih.dev@gmail.com)

---

# How to use HopperLang (Syntax)

Create a `main.hpl` file in the same directory as `hplc` (or specify another source file as the first argument).

## 1. Imports

Import a single file:

```text
<?import path/to/file.hpl>
```

Import all `.hpl` files from a directory:

```text
<?import path/to/directory/*>
```

---

## 2. Functions

Declare a public function:

```text
$[datatype] function_name([datatype] arg1, [datatype] arg2) {
    ...
}
```

* `$` declares a public function that can also be accessed from imported `.hpl` files.
* Replace `[datatype]` with the return type.
* Replace `function_name` with your function name.
* `$main()` is reserved for the program entry point.
* Parameters work similarly to Java or C++.
* Varargs (`...`) are planned but not implemented yet.

Return a variable:

```text
variable#return;
```

Call a function:

```text
function_name(arg1, arg2);
```

**Note:** Functions from different files must currently have unique names. A recommended naming scheme is:

```text
math_max()
string_split()
player_move()
```

---

## 3. Compiler / System Actions

Append `#` to a variable to invoke a compiler action.

Available actions:

```text
variable#print;
variable#scan;
variable#return;
variable#stopWithExitCode;
```

Meaning:

* `#print` – print the value
* `#scan` – read user input
* `#return` – return the value
* `#stopWithExitCode` – terminate the program with the given exit code

---

## 4. Statements

### If statement

```text
if(condition) {
    ...
}
```

### Loop

```text
times(n) {
    ...
}
```

Executes the body `n` times.

---

# Building the Compiler

The HopperLang compiler is written in **C++17** and uses **LLVM**.

## Requirements

* LLVM (stored in `./llvm`)
* Zstandard (`./zstd/lib/libzstd.a`)
* clang++
* C++17
* zlib
* ncurses
* pthread

---

## Build using build.sh (recommended)

Make the script executable:

```bash
chmod +x build.sh
```

Build the compiler:

```bash
./build.sh
```

The script automatically:

* checks for `libzstd.a`
* links all local LLVM libraries
* builds `compiler.cpp`
* creates the executable `hplc`

---

## Build using CMake

Alternatively, build the project using the included `CMakeLists.txt`.

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

---

# Compiling HopperLang Programs

Compile a HopperLang source file:

```bash
./hplc main.hpl output.o
```

Link the generated object file:

```bash
clang output.o -o program
```

Run the program:

```bash
./program
```

---

# Project Structure

```text
HopperLang/
│
├── .vscode/
├── llvm/
├── zstd/
├── build.sh
├── CMakeLists.txt
├── compiler.cpp
├── LICENSE
├── README.md
├── hplc
├── main.hpl
├── output.o
└── program
```

`output.o`, `program`, and `hplc` are generated during the build process.

---

# HDKs (Hopper Development Kits)

Current version:

```text
hdk_0
```

### math.hpl

```text
math_max(int a, int b)
```

Returns the larger value.

```text
math_min(int a, int b)
```

Returns the smaller value.

```text
math_pow(int a, int n)
```

Returns `aⁿ`.

---

Copyright (c) TrichterIH
