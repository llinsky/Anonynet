/*Various Printing functions*/
#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include "globals.h"
#include <netinet/ip_icmp.h>

void print_gyn_header(const struct gyn_header*);

void print_routing_entry(const struct route_entry*);

void print_aes_key(unsigned char* key,int size);
