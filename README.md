# HopperLang
A Coding Language made for Programmers. Try it out and LOVE it!

Buy me a coffee: trichterih.dev@gmail.com

# How to use it (Syntax)
Create a filee main.hpl in the same directory where the compiler.cpp is. 
(Or use a custom path in the 1st arg behind hplc (out of the build.sh||build.mk).)

1. Imports:
    Use <?import path/to/file.hpl> to import a file.
    Use <?import path/to/dir> to import a all hpl-files in a directory.

2. Methods:
    Use $[datatype] func_name([dt] arg1, [dt]... args) {body} to declare a function.
    The $stands for a public method which is also accessable in other hpl files.
    Replace [datatype] with the datatype which the function will return.
    Replace func_name whith the name of the function (Note: $main() is reserved for main-method!).
    Args are same like in java ect. (Note: Varargs not implementated yet!).
    Use var#return; to return a variable (Note: only working with a single variable!).
    Access to methods with func_name(arg, args);
    --Note: implementated functions/methods in other files can't have same names! tipp: use classname_funcname()!

3. Sys/Compiler Actions / Hard-Methods:
    use # behind a variable, to use a sys/compiler action:
    --#return: return statement
    --#print: sys out
    --#scan: sys in

4. Statements
    if() us like in c, c++, ect...
    times(int n) {} reputates body n times
    

# How to Compile HPL-Code

The compiler.cpp is in C++17. 

Needed: your hpl code including main.hpl (or custom path), compiler, build file

1. Build with the build.sh: ./build.sh     (ONLY MAC SUPPORT!)
2. Now you have a hplc file (should be about 600.000 lines code)
3. Compile the hplc file: ./hplc main.hpl output.o
4. Link output.o: clang output.o -o program
5. Execute program: ./program
6. Done!

IMPORTANT:
YOUR PROJECT STRUCTURE SHOULD BE:

HopperLang(ROOT_FOLDER)
-.vscode
-llvm
-zstd
build.sh
CMakeLists.txt
compiler.cpp
hplc
LICENSE
main.hpl
output.o
program
README.md

Some files are created by executing the commands (output.o, programm). You need to add the llvm16 lib and zstd.


# HDKs

Newest HDK: hdk_0 (

1. math.hpl
    math_max(int a, int b) - returns the higher number
    math_min(int a, int b) - returns the lowest number
    math_pow(int a, int n) - returns a^n

