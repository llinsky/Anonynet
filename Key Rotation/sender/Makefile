#Makefile for Router, update as needed
#IN PROGERESS!!!

CC=gcc
CFLAGS=-I. -Wall -lssl -lcrypto
DEPS = print_packets.h header.h aes.h 
OBJ = fsend.o aes.o print_packets.o

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)


sender: $(OBJ)
		$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean: 
		rm -f ./*.o
