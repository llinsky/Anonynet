/*

Spoofer.c

Creates fake traffic patterns (in our case, traffic that looks like FTP) according to a random distribution of sources, receivers, delays, file-sizes, etc.

Uses an encrypted handshake identical to the FTP handshake from an outsider, and determines whether there is currently network usage in progress at the destination node or source node (in which case it avoids this combination). We will need to take care to make sure the average amount of traffic on each node is equal in the long run.


Instructions: Run on every node.

sudo ./spoofer <ethX> <myAddr>


*/

//Side note: Team SAM needs to add random padding to the front of their blocks, and now check this flag as well


/* 

After address of encrypted header, byte 8 will be the flag:

0x00 - normal
0x01 - spoof request
0x02 - spoof affirmative reply (should still send a smaller file with negative reply, will send lots of small ones)
0x03 - spoof negative reply
0x04 - spoof garbage

*/

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/fcntl.h>


#include "aes.h"
#include "encrypt_decrypt.h"

#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

#define BUF_SIZE		2048

#define NUM_ENTRIES 6

#define PACKET_SIZE 1500

#define AVG_SESSION_FREQ 4

struct custom_header {
	uint16_t dest; //destination -- might make bigger
	uint16_t junk1;
	uint32_t junk2;
	uint8_t flag;
	uint8_t junk3;
	uint16_t junk4;
	//uint16_t ether_type; //added into packet manually, this part can't be encrypted
};

// this function creates the arbitrary behavior function with the following format:
// fsize in KBs (uint32_t) -> periods in seconds (uint32_t)
// fsizes can vary from 50% to 500% of the value given (logarithmic) 
void createpdf (double fsizes[], double periods[], double pdf[])
{
	//fsizes = malloc(sizeof(NUM_ENTRIES*sizeof(double)));
	//periods = malloc(sizeof(NUM_ENTRIES*sizeof(double)));
	//pdf = malloc(sizeof(NUM_ENTRIES*sizeof(double)));
	
	double time_constant = 4.0/AVG_SESSION_FREQ;
	
	int i;
	double start = 1;
	for (i=0; i<NUM_ENTRIES; i++) //using arbitrary discrete transformation of Poisson rate to create pdf
	{
		fsizes[i] = 5*start;
		periods[i] = time_constant*sqrt(sqrt((start))) + 1;
		start = start*10;
	}
	
	
	double sum = 0;
	for (i=0; i<NUM_ENTRIES; i++)
	{
		sum += periods[i];
	}
	for (i=0; i<NUM_ENTRIES; i++)
	{
		pdf[i] = periods[i]/sum;
	}
	
}

void print_aes_key(unsigned char* key,int size){
	int i;
	for(i=0;i<size;i++){
		printf("%X",key[i]);	
	}
	printf("\n");
	return;
}


int main (int argc, char *argv[])
{
	//setup sockets and stuff
	
	unsigned char recvbuf[BUF_SIZE];
	unsigned char sendbuf[BUF_SIZE];
	
	if (argc != 4)
	{
		printf("Usage: sudo ./spoofer <ethX> <myAddr> <nextHopAddr> \n\n");
		return -1;
	}
	
	char ifName[IFNAMSIZ];
	strcpy(ifName, argv[1]);
	
	int MY_ADDR = atoi(argv[2]);
	int RTR_ADDR = atoi(argv[3]);
	
	//HARDCODE for now the range of available addresses as 1-6 (routers will be 7-9)
	int ADDR_MIN = 1;
	int ADDR_MAX = 4;
	
	
	struct sockaddr_ll raw_address;
	raw_address.sll_family=AF_PACKET;
	raw_address.sll_protocol=htons(ETH_P_ALL);

	//Create send sock
	int send_sock;
	send_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(send_sock < 0){
		perror("Error creating send socket\n");
		return -1;
	}
	struct ifreq ifr;
	struct packet_mreq mr;
	
	int sock_size;
	int recv_size;
	int sock;
	
	sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
		
	if(sock<0){
		printf("Uhoh, couldn't create socket");
		return -1;
	}
	
	//set to non-blocking
	if(fcntl(sock,F_SETFL,O_NONBLOCK)<0){
		perror("Error setting nonblocking\n");
	}
	
	
	
	//Bind socket to interface
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sock,SIOCGIFINDEX,&ifr);	
	raw_address.sll_ifindex=ifr.ifr_ifindex;
	bind(sock,(const struct sockaddr*)&raw_address,sizeof(struct sockaddr_ll));
	
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;

	if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		perror("setsockopt(PACKET_MR_PROMISC) failed");
		return 1;
	}
	
	/*Get interface index*/
	memset(&ifr,0,sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifName,IFNAMSIZ-1);
	if(ioctl(send_sock,SIOCGIFINDEX,&ifr)<0){
		perror("IOCTL ERROR\n");
		return -1;
	}
	else{
		//printf("Found send interface....\n");
	}
	
	memset(sendbuf,0,BUF_SIZE);
	memset(recvbuf,0,BUF_SIZE);
	
	struct sockaddr_ll send_address;

	memset(&send_address,0,sizeof(struct sockaddr_ll));
	send_address.sll_ifindex=ifr.ifr_ifindex;
	send_address.sll_halen=ETH_ALEN;
	send_address.sll_protocol=htons(ETH_P_ALL);
	send_address.sll_family=AF_PACKET;
	send_address.sll_addr[0]=0xFF;	
	send_address.sll_addr[1]=0xFF;	
	send_address.sll_addr[2]=0xFF;	
	send_address.sll_addr[3]=0xFF;	
	send_address.sll_addr[4]=0xFF;	
	send_address.sll_addr[5]=0xFF;	
	send_address.sll_addr[6]=0xFF;	
	send_address.sll_addr[7]=0xFF;	
	
	
	struct custom_header *customhdr = malloc(sizeof(struct custom_header));
	unsigned char header_encrypted[16];
	int sent=0, bytes;
	
	
	srand ( time(NULL) ); //initialize random numbers
    double random_number, cdf_sum;
	int i, next_index;
	int fsize, delay;
	int dest;
	
	unsigned char key_link[16]; //we only need key link, everything else besides crypto header is garbage
	get_aes_key(RTR_ADDR,key_link);
	
	double fsizes[NUM_ENTRIES]; 
	double periods[NUM_ENTRIES]; 
	double pdf[NUM_ENTRIES];
	int skip_dest[NUM_ENTRIES];
	memset(skip_dest, 0, sizeof(skip_dest));
	
	createpdf(fsizes, periods, pdf);
	
	int packets_to_send, waited, avoid;
	
 
	
	//sleep(20); // so we don't have to synchronize turning them on -- //unnecessary
	
	//We will not check end node for now
	/*
	pid_t pid; 
	pid = fork(); 
	if (pid == 0) {
		int busy = 0;
		while (1) //this process just listens for spoof requests and tells if we're busy
		{
			while (1)
			{
				avoid = 0;
				recv_size = recvfrom(sock,recvbuf,BUF_SIZE,0,(struct sockaddr*)&raw_address,(socklen_t*)&sock_size);
				busy = 1;
				if (recv_size < 0)
				{
					if (waited > 10)
					{
						busy = 0
						break; //no packets were found, no competition to worry about
					}
					waited++;
					sleep(0.01);
					//printf("Nothing being received\n");
					continue;
				}
				else if (raw_address.sll_pkttype==PACKET_OUTGOING)
				{
					
					unsigned char dest_jumbled[16];
					unsigned char dest_decrypted[16];
					memcpy(dest_jumbled,recvbuf,12);
					memcpy(&dest_jumbled[12],&recvbuf[14],4);
					int decrypted_text_len = decrypt(dest_jumbled, 16 , &vars.keys[16*if_index], NULL, dest_decrypted);
					uint16_t pkt_dest;
					unsigned char flag;
					memcpy(&pkt_dest, &dest_decrypted, sizeof(uint16_t));
					memcpy(&flag, &(dest_decrypted+8), sizeof(unsigned char));
					
					if (flag != 0x00)
					{
						avoid = 1;
						break;
					}
				}
				else
				{
					unsigned char dest_jumbled[16];
					unsigned char dest_decrypted[16];
					memcpy(dest_jumbled,recvbuf,12);
					memcpy(&dest_jumbled[12],&recvbuf[14],4);
					int decrypted_text_len = decrypt(dest_jumbled, 16 , &vars.keys[16*if_index], NULL, dest_decrypted);
					uint16_t pkt_dest;
					unsigned char flag;
					memcpy(&pkt_dest, &dest_decrypted, sizeof(uint16_t));
					memcpy(&flag, &(dest_decrypted+8), sizeof(unsigned char));
					
					if (flag != 0x00)
					{
						avoid = 1;
						break;
					}
				}
			}
			//now listen for a second and send responses
			int c;
			
			for (c=0; c<10; c++)
			{
				recv_size = recvfrom(sock,recvbuf,BUF_SIZE,0,(struct sockaddr*)&raw_address,(socklen_t*)&sock_size);
				
				if ((recv_size < 0) || (raw_address.sll_pkttype==PACKET_OUTGOING))
				{
					break;
				}
				
				unsigned char dest_jumbled[16];
				unsigned char dest_decrypted[16];
				memcpy(dest_jumbled,recvbuf,12);
				memcpy(&dest_jumbled[12],&recvbuf[14],4);
				int decrypted_text_len = decrypt(dest_jumbled, 16 , &vars.keys[16*if_index], NULL, dest_decrypted);
				uint16_t pkt_dest;
				unsigned char flag;
				memcpy(&pkt_dest, &dest_decrypted, sizeof(uint16_t));
				memcpy(&flag, &(dest_decrypted+8), sizeof(unsigned char));
				
				if (flag==0x01)
				{
					//send affirmative reply
				}
				sleep(0.1);
			}
			
			
		}
			
		return 0;
	} 
	*/
	
	
	while (1)
	{
		random_number = ((double) rand())/RAND_MAX;
		
		printf("About to make a cdf\n");
		
		//first determine which group
		next_index = NUM_ENTRIES-1;
		cdf_sum = 0;
		for (i=0; i<NUM_ENTRIES; i++)
		{
			cdf_sum += pdf[i];
			if (cdf_sum >= random_number)
			{
				next_index = i;
				break;
			}
		}
		
		printf("Made a cdf\n");
		
		
		//check for outgoing packets/incoming packets to the machine to avoid competition, if found: delay and 'continue' 
		
		printf("About to check for competition at this node . . .\n");
		
		waited = 0;
		avoid = 0;
		uint16_t ether_type=0x0000;	
		while (1)
		{
			recv_size = recvfrom(sock,recvbuf,BUF_SIZE,0,(struct sockaddr*)&raw_address,(socklen_t*)&sock_size);
			memcpy(&ether_type,recvbuf+12,2);
			//printf("Ether_type: %2X\n",ether_type);
			if (recv_size <= 0)
			{
				if (waited > 10)
				{
					printf("I was not receiving any packets\n");
					break; //no packets were found, no competition to worry about
				}
				waited++;
				sleep(0.05);
				//printf("Nothing being received\n");
				continue;
			}
			else if ((raw_address.sll_pkttype==PACKET_OUTGOING) && (ether_type==0x88b5))
			{
				//now decrypt packet and determine address and add one to skip_dest array. this will adjust our traffic distribution to stay uniform
			//	printf("Detected outgoing packets!!\n");
				unsigned char dest_jumbled[16];
				unsigned char dest_decrypted[16];
				memcpy(dest_jumbled,recvbuf,12);
				memcpy(&dest_jumbled[12],&recvbuf[14],4);
				int decrypted_text_len = decrypt(dest_jumbled, 16 , key_link, NULL, dest_decrypted);
				uint16_t pkt_dest;
				memcpy(&pkt_dest, &dest_decrypted, sizeof(uint16_t));
				
				if (dest_decrypted[7] == 0x00)
				{
					skip_dest[pkt_dest]++;
					avoid = 1;
					break;
				}
			}
			else if (ether_type==0x88b5)
			{
				//now decrypt packet and determine address and add one to skip_dest array. this will adjust our traffic distribution to stay uniform
			//	printf("Detected incoming packets\n");
				unsigned char dest_jumbled[16];
				unsigned char dest_decrypted[16];
				memcpy(dest_jumbled,recvbuf,12);
				memcpy(&dest_jumbled[12],&recvbuf[14],4);
				int decrypted_text_len = decrypt(dest_jumbled, 16 , key_link, NULL, dest_decrypted);
				uint16_t pkt_dest;
				memcpy(&pkt_dest, &dest_decrypted, sizeof(uint16_t));
				
				if (dest_decrypted[7] == 0x00)
				{
					skip_dest[pkt_dest]++;
					avoid = 1;
					break;
				}
			}
			else{
				printf("Received strange ethertype: %2X\n",ether_type);
			}
		}
		
		
		//next determine destination randomly - DONE
		
		dest = MY_ADDR;
		while (dest == MY_ADDR)
		{
			dest = rand()%((ADDR_MAX+1)-ADDR_MIN) + ADDR_MIN;
			if (dest%3 == 0) // avoid routers
			{
				dest = MY_ADDR;
				continue;
			}
			if (skip_dest[i] > 0)
			{
				dest = MY_ADDR;
				skip_dest[i]--;
			}
		}
		
		
		//now check if the coast is clear at destination -- if not, change index to something small
		//basically check 100 packets or one second, whichever comes last. if you get an affirmative or negative, break
		
		//not doing this for now ^
		/*
		if (!avoid)
		{
			unsigned char packet_buf[PACKET_SIZE]; //'random' (uninitialized) buffer -- may make this more random later
			

			uint16_t pkt_dest = (uint16_t) dest;
			
			//printf("\tAbout to assign dest . . .\n");
			customhdr->dest = pkt_dest;
			//printf("\tAbout to assign flag . . .\n");
			customhdr->flag = 0x01;
			customhdr->junk1 = MY_ADDR;
			//printf("\tAbout to assign junk . . .\n");
			customhdr->junk2 = ((uint32_t) rand());
			
			//printf("\tAbout to encrypt header . . .\n");
			
			encrypt(((unsigned char *) customhdr), sizeof(struct custom_header), key_link, NULL, header_encrypted);
			
			memcpy(packet_buf,header_encrypted,12);
			memcpy(&packet_buf[14],&header_encrypted[12],4);
			packet_buf[12] = 0x88; //ethertype for normal 'encrypted' packets
			packet_buf[13] = 0xb5; 	
		}
		*/
		
		
		if (avoid)
		{
			next_index = -1; //send smallest file, avoid interfering
		}
		else
		{
			next_index = 0;
		}
		
		//next determine exact file size for this group - DONE
		
		printf("Determining file size . . .\n");
		
		if (next_index >= 0)
		{
			fsize = fsizes[next_index];
			fsize = (int) ((((double) (rand()%450))/100.0)*((double) fsize)); //size in KB

			
			printf("\tFile size: %d KB\n", fsize);
			
			//next determine exact delay to wait after completion - DONE
			
			delay = rand()%((int)(2*periods[next_index]));
			
			printf("\tDelay: %d\n\n", delay);
			
			//now send fake file
			
			packets_to_send = (fsize*1024)/PACKET_SIZE;
			if ((fsize%PACKET_SIZE) != 0)
			{
				packets_to_send++;
			}
			
			sent = 0;
			
			printf("About to spoof packets to %d. . .\n", ((int) dest));
			int printed = 0;
			while (sent < packets_to_send)
			{
				sent++;

				
				unsigned char packet_buf[PACKET_SIZE]; //'random' (uninitialized) buffer -- may make this more random later
				

				uint16_t pkt_dest = (uint16_t) dest;
				
				//printf("\tAbout to assign dest . . .\n");
				customhdr->dest = pkt_dest;
				//printf("\tAbout to assign flag . . .\n");
				customhdr->flag = 0x04;
				//printf("\tAbout to assign junk . . .\n");
				customhdr->junk2 = ((uint32_t) rand());
				
				//printf("\tAbout to encrypt header . . .\n");
				
				int length_encrypted = encrypt(((unsigned char *) customhdr), sizeof(struct custom_header), key_link, NULL, header_encrypted);
				//printf("Encrypted header (%d bytes) : ",length_encrypted);
				
				//print_aes_key(header_encrypted, length_encrypted);	
				memcpy(packet_buf,header_encrypted,12);
				memcpy(&packet_buf[14],&header_encrypted[12],4);
				packet_buf[13] = 0x88; //ethertype for normal 'encrypted' packets
				packet_buf[12] = 0xb5; 
				
				if ((sent%1000 == 1)&&printed < 10)
				{
					printed++;
					printf("\tAbout to send packets . . .\n");
				}
				
				bytes = sendto(send_sock, packet_buf, PACKET_SIZE, 0, (struct sockaddr*)&send_address, sizeof(send_address));
				if (bytes < 0)
				{
					printf("\nSend failed!!!!!\n");
				}
			}
			
			//now wait for delay and do it all over again!
			printf("Done sending files, delaying for %d seconds\n\n", delay);
		}
		else
		{
			printf("Ran into collision, delaying for %d seconds\n\n", delay);
		}
		sleep(delay);
		
	}
	
	
	return 0;
}














