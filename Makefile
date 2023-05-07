CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lcrypto
OBJ = stnc.o stnc2.o

default: all

all: stnc2

stnc2: stnc2.o
	$(CC) $(CFLAGS) -o stnc2 stnc2.o $(LDFLAGS)

stnc2.o: stnc2.c stnc2.h
	$(CC) $(CFLAGS) -c stnc2.c

clean:
	rm -f stnc2 stnc2.o