# QRL utilities in C

Still in its draft

Based from github.com/theqrl/qrl

Requires:

- lcrypto -lleveldb -ljson-c -lsnappy -lpthread

Ubuntu: `yes | sudo apt install lib{leveldb,json-c,ssl}-dev`

Build dependencies: `libbost-dev`

# Known issues

Compiling with gcc produces linker from undefined symbols in librandomx.a. 
This seems to be a problem when linking a C++ library [which uses the C++
standard libs] using a C compiler. And that C compiler couldn't properly
call ld with appropriate flags needed by a C++ library. Either use a C++
compiler, or pass appropriate linker flags with `-Wl,someflags` when using
a C compiler or maybe use clang.

# License

Parts of this source directory are written by the QRL/C contributors and others.

Sources written by the QRL contributors are released under their License.

Sources written by the QRLC contributors are released under MIT License.

See the accompanying notice at every sources for it's author
and license.

