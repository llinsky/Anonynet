/*Function definitions for getting packets for our router*/

#include <stdio.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "globals.h"
#include "print_packets.h"
#include <netinet/ip_icmp.h>

void get_packets();
