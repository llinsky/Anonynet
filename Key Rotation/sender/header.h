#include <stdio.h> //for printf
#include <stdlib.h>
#include <string.h> //memset
#include <sys/socket.h>    //for socket ofcourse
#include <fcntl.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header 
#include <pthread.h>
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h> 








typedef struct lookup_header{
	unsigned char dest1[12];		//dest1 and dest2 together contains encrypted destination.
	unsigned short ether_type;
	unsigned char dest2[4];
}lookup_header_t;

struct session_entry {
	uint16_t host_id;
	uint8_t sym_key[16];
	struct timeval timestamp;
};

typedef struct anonymous_header{
	
	//unsigned short dest_val;
	unsigned short src_val;
	unsigned short seq_num;
	unsigned short custom_pkt_type;
	//unsigned short size;
	//unsigned short count_of_seqnum_in_nack;  // this will say the count of sequence numbers in NACK message
	//unsigned short ether_type;
	
}anonymous_header_t;
          
typedef struct custom_header{
	
	unsigned short dest_val;
	unsigned short src_val;
	unsigned short seq_num;
	unsigned short custom_pkt_type;
	unsigned short size;
	unsigned short count_of_seqnum_in_nack;  // this will say the count of sequence numbers in NACK message
	unsigned short ether_type;
	
}custom_header_t;

struct gyn_header
{
	uint16_t dest; //destination
	uint16_t src;
	uint16_t seq;
	uint16_t pkt_size; // bytes. payload only (starting at byte 18)
	uint16_t pkt_type;
	uint16_t unused;
	uint16_t ether_type; 
	uint32_t crypto_padding; //cryptographic padding, used for 0x0101 ether_types. all 0's for key exchange
};

