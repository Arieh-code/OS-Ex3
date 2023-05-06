CC = gcc
CFLAGS = -Wall -Wextra
OBJ = stnc.o

default: all

all: stnc

stnc: $(OBJ)
	$(CC) $(CFLAGS) -o stnc $(OBJ)

stnc.o: stnc.c stnc.h
	$(CC) $(CFLAGS) -c stnc.c

clean:
	rm -f stnc $(OBJ)
