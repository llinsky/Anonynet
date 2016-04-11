/***********************************************************************************
*  This file will define methods for working with aes encryption                   *
************************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/ip.h> 
#include <net/if.h>
#include <pcap/pcap.h>

struct session_entry {
	uint16_t host_id;
	uint8_t sym_key[16];
	struct timeval timestamp;
};

int get_aes_key(uint16_t dest,unsigned char* key);
