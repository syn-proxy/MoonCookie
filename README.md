CAUTION
=======
As of now, proof of concept, contains hard coded MACs/IPs. ARP task and other required features for a first release are coming soon.

MoonCookie is a TCP SYN proxy implementation.
It currently supports TCP SYN cookies and three different SYN authentication strategies.

Installation
============
1. `git submodule update --init --recursive`
2. Compile Phobos in the `phobos` submodule. Follow instructions there.
3. `cd build ; cmake .. ; make ; cd ..`
4. ./phobos/build/phobos tcp-proxy-standalone.lua <params>

Usage
=====
Usage is shown with -h
