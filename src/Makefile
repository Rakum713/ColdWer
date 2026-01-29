CC = x86_64-w64-mingw32-gcc
OUTPUT = ../cw/coldwer.o

all: coldwer

coldwer: coldwer.c
	$(CC) coldwer.c -o $(OUTPUT)

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
