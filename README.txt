# QRL utilities in C

Still in its draft

Based from github.com/theqrl/qrl

Requires:

-lcrypto -lleveldb -ljson-c -lsnappy -lpthread

Ubuntu: `sudo apt install lib{leveldb,json-c,ssl}-dev`

Build dependencies: `libbost-dev`

# Building

`make -j4`

# Building on msys2 (ucrt64)

```
pacman -S mingw-w64-ucrt-x86_64-{leveldb,json-c,boost,openssl,gcc,make}
make -j4

```
Note that ASan isn't supported on non LLVM/Clang based environent on msys2,
so remove those `-fsanitize=address`.

# Known building issues

Compiling with gcc produces linker from undefined symbols in librandomx.a. 
This seems to be a problem when linking a C++ library [which uses the C++
standard libs] using a C compiler. And that C compiler couldn't properly
call ld with appropriate flags needed by a C++ library. Either (1) use a C++
compiler, or (2) pass appropriate linker flags with `-Wl,someflags` or some
library when using a C compiler or (3) use the C compiler to only compile
into .o objects and use a C++ compiler to link those objects.

# License

Parts of this source directory are written by the QRL/C contributors and others.

See the accompanying notice at every sources for it's author
and license.

