//
// Global vars/preprocessor macros go here

#pragma once

#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/ip.h> 
#include <net/if.h>
#include <pcap/pcap.h>
#include "hashmap.h"

#define PUBLIC_KEY_TYPE 20
#define PRIVATE_KEY_TYPE 21
#define KEY_ACK_TYPE 22
#define PROTO_TYPE1 0x88b5
#define PROTO_TYPE2 0x88b6

struct route_entry{
    
    uint32_t address;
    uint32_t next_hop;
    int send_index;
};


struct global_vars { 
   	int send_sock_fd;
	map_t routing_table; //to replace routing table eventually
   	int sockets[20];
	uint16_t my_addr;
   	int numifaces;
	int numaddresses;
	unsigned char keys[20*16]; //decryption key for each interface index. Assuming interface indices stay between 0 and 10
	int ifaces[20];
};

struct session_entry {
	uint16_t host_id;
	uint8_t sym_key[16];
	struct timeval timestamp;
};

struct gyn_header
{
	uint16_t dest; //destination
	uint16_t src;
	uint16_t seq;
	uint16_t pkt_size; // bytes. payload only (starting at byte 18)
	uint16_t pkt_type;
	uint16_t unused;
	uint16_t ether_type; // 0x0101 for normal (encrypted) traffic. 0x0102 for key exchange data (unencrypted header)
	uint32_t crypto_padding; //cryptographic padding, used for 0x0101 ether_types. all 0's for key exchange
};

extern struct global_vars vars; //singleton object
