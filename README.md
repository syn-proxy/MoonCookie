MoonCookie is a TCP SYN proxy implementation.
It currently supports TCP SYN cookies and three different SYN authentication strategies.

Installation
============
1. `git submodule update --init --recursive`
2. Compile libmoon in the `libmoon` submodule. Follow instructions there.
3. `cd build ; cmake .. ; make ; cd ..`
4. ./libmoon/build/libmoon mooncookie.lua <params>

Usage
=====
Usage is shown with -h
