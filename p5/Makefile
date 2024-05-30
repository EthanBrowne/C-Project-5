CC = gcc
CFLAGS = -Wall -std=c99 -g
hash: hash.o sha256.o sha256constants.o
sha256test: sha256test.o sha256.o sha256constants.o

hash.o: hash.c sha256.h sha256constants.h
sha256.o: sha256.c sha256.h sha256constants.h
sha256constants.o: sha256constants.c sha256constants.h
sha256test.o: sha256test.c sha256constants.h sha256.h

hash.c: sha256.h sha256constants.h
sha256.c: sha256.h sha256constants.h
sha256constants.c: sha256constants.h
sha256test.c: sha256constants.h sha256.h

clean:
	rm -f hash hash.o sha256.o sha256constants.o sha256test sha256test.o