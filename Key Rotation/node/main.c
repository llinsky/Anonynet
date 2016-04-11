#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "globals.h"
#include "security.h"
#include "aes.h"

#define BUF_SIZE		4096


uint16_t my_addr=0;

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc < 3){
		printf("Usage: ./nodeKeyExchange ethX my_addr\n");	
	}
	else{
		strcpy(ifName, argv[1]);
		my_addr=atoi(argv[2]);
	}	

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
	    printf("socket error");
		return 0;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

//	printf("Using interface index %d\n\n",if_idx.ifr_ifindex);
	generate_rsa_key_pair(1024);
	while(1){
		
		//Generate RSA key pair for secure key exchange	
//		printf("============================================================================\n");
		printf("\tInitiating public key exchange\n");
		//Now send out our public keys
		send_public_key(sockfd,if_idx.ifr_ifindex);
		//sleep(10);
		uint16_t i;
		unsigned char symkey[16];
		memset(symkey,0,16);
//		printf("\n\tSaved keys: \n");
		for(i=1;i<10;i++){
			if(i!=my_addr){
				get_aes_key(i,symkey);	
//				printf("\t\tKey for address %hu: ", i);
//				print_aes_key(symkey,16);
			}	

		}
//		printf("\n\tPublic key exchange subprocess exiting\n");
///		printf("===========================================================================\n");
		sleep(30);
	}
	close(sockfd);
	return 0;
}
