#Makefile for Key Server
#IN PROGRESS!!!

CC=gcc
CFLAGS=-I. -Wall -lssl -lcrypto
DEPS = security.h globals.h hashmap.h
OBJ = main.o security.o hashmap.o

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)


keyServer: $(OBJ)
		$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean: 
		rm -f ./*.o
