#!/bin/bash

pushd .
yasm -D__linux__ -g dwarf2 -f elf64 aesnix64asm.s -o aesnix64asm.o
#gcc -m64 -o aesni aesni.c aesnix64asm.o
gcc -m64 -c aesni.c
ar cru libaesni.a *.o
popd


