#Makefile for Router, update as needed
#IN PROGERESS!!!

CC=gcc
CFLAGS=-I. -Wall -lssl -lcrypto
DEPS = print_packets.h header.h aes.h 
OBJ = frecv.o aes.o print_packets.o

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)


receiver: $(OBJ)
		$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean: 
		rm -f ./*.o
