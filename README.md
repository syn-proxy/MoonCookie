MoonCookie is a TCP SYN proxy implementation.
It currently support TCP SYN cookies and three different SYN authentication strategies.

Installation
============
1. `git submodule update --init --recursive`
2. Compile Phobos in the `phobos` submodule. Follow instructions there.
3. `cd build ; cmake .. ; make ; cd ..`
4. ./phobos/build/phobos tcp-proxy[-standalone].lua <params>

MoonCookie requires gcc 5 or later. You can use

    CC=gcc-5 CXX=g++-5 cmake ..

to set the compiler if gcc 5 is not your default.


Usage
=====

