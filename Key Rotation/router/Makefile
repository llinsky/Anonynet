#Makefile for Router, update as needed
#IN PROGERESS!!!

CC=gcc
CFLAGS=-I. -Wall -lssl -lcrypto
DEPS = get_packets.h print_packets.h packet_response.h globals.h security.h aes.h hashmap.h encrypt_decrypt.h
OBJ = main.o get_packets.o print_packets.o packet_response.o security.o aes.o hashmap.o encrypt_decrypt.o

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)


customRouter: $(OBJ)
		$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean: 
		rm -f ./*.o
