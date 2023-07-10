#!/bin/sh
gcc exploit.c -o exploit -static -masm=intel -D_FILE_OFFSET_BITS=64 -lfuse -lpthread -luring -ldl -g -Wall -Wextra
mv exploit root
cd root; find . -print0 | cpio -o --null --format=newc --owner=root > ../debugfs.cpio
cd ../

sh run.sh
