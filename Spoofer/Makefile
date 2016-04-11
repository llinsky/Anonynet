#Makefile for Spoofer

CC=gcc
CFLAGS=-I. -Wall -lssl -lcrypto -lm
DEPS = encrypt_decrypt.h aes.h
OBJ = spoofer.o encrypt_decrypt.o aes.o

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)


spoofer: $(OBJ)
		$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean: 
		rm -f ./*.o
