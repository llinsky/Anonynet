//
//
// Function responses to received packets

#include <stdio.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "aes.h"
#include "globals.h"
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

int send_packet(unsigned char* packet, int size, struct sockaddr_ll* sockaddrll);
int get_route_logic(uint32_t dest,int* index);
int gyn_packet_handler(unsigned char* packet, int size, struct sockaddr_ll* sockaddrll, int if_index);
