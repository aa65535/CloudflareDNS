CloudflareDNS
========

Build
-----

    ./autogen.sh
    ./configure && make
    ./src/cfdns -c cfroute.txt -l /path/to/resolve.txt -s 8.8.8.8
