#!/bin/sh
gcc poc.c -o poc -static -masm=intel -m32 -lpthread
mv poc root
cd root; find . -print0 | cpio -o --null --format=newc --owner=root > ../debugfs.cpio
cd ../

sh run.sh
