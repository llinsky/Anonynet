#Makefile for Router, update as needed
#IN PROGERESS!!!

CC=gcc
CFLAGS=-I. -Wall -lssl -lcrypto
DEPS = globals.h security.h print_packets.h aes.h
OBJ = main.o security.o print_packets.o aes.o

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)


nodeKeyExchange: $(OBJ)
		$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean: 
		rm -f ./*.o
