CFLAGS=-Wmissing-prototypes -Wdeclaration-after-statement -O2 -Wall

targets: curve25519-donna.so curve25519-donna-c64.so

test: test-donna test-donna-c64

clean:
	rm -f *.o *.so *.pp 

curve25519-donna.so: curve25519-donna.o
	gcc -shared -o curve25519-donna.so curve25519-donna.o

curve25519-donna.o: curve25519-donna.c
	gcc -c curve25519-donna.c $(CFLAGS) -m32

curve25519-donna-c64.so: curve25519-donna-c64.o
	gcc -shared -o curve25519-donna-c64.so curve25519-donna-c64.o

curve25519-donna-c64.o: curve25519-donna-c64.c
	gcc -c curve25519-donna-c64.c $(CFLAGS) -m64
