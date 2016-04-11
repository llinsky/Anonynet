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


#include "security.h"
#include "hashmap.h"
#include "globals.h"

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

#define BUF_SIZE		4096



#define DEFAULT_IF	"eth0"

//#define MY_ADDR 1


//Key server

/*

Accepts key exchange requests, and writes entries to a secure file.

An entry is as follows:

Host ID		Shared Key			Timestamp (of first request packet, sent as part of the packet)	
1			0x3aef5dea5007		129920110														
3			...
4

Session-ID is a random variable that may be used to enable key transitions in the middle of a session. Created by hash of first handshake 
packet.

The exchange protocol is as follows.

1. Server receives request of format:
	Header | Host's Public Key | Host Timestamp
	(proto = 20)

2. Server responds with message of format:
	Header | Server generated AES key encrypted with host’s public key | Host Timestamp (timestamp included for identification)
	(proto = 21)
	
3. Host responds with message of format:
	Header | ACK
	(proto = 22)
	
The server now has a shared symmetric key. Write to file /tmp/sesh_keys

The server now checks the file for duplicates every time it is accessed. In the case of multiple keys for the same Host ID, delete 
the one with the smallest time-stamp.



Maintaining state:
	
*/

struct custom_header {
	uint16_t dest; //destination
	uint16_t src;
	uint16_t seq;
	uint16_t pkt_size; // bytes. payload only (starting at byte 18)
	uint16_t pkt_type;
	uint16_t unused;
	uint16_t ether_type; // 0x0101 for normal (encrypted) traffic. 0x0102 for key exchange data (unencrypted header)
	uint32_t crypto_padding; //cryptographic padding, used for 0x0101 ether_types. all 0's for key exchange
};

struct session_entry {
	uint16_t host_id;
	uint8_t sym_key[16];
	struct timeval timestamp;
};

struct session_state {
	int stage; //stage of the transaction: 0=not started, 1=received public key, 2=received ack (complete)
	
	uint16_t host_id;
	
	uint8_t generated_sym_key[16];
	
	struct timeval timestamp; //timeout after 60 seconds? maybe later
};

/* Subtract the `struct timeval' values X and Y, storing the result in RESULT. Returns -1 if x<y, 1 if x>y, else 0.  */

int timeval_cmp(struct timeval *x, struct timeval *y)
{
	if (x->tv_sec == y->tv_sec)
	{
		if (x->tv_usec < y->tv_usec)
		{
			return -1;
		}
		else if (x->tv_usec > y->tv_usec)
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else if (x->tv_sec > y->tv_sec)
	{
		return 1;
	}
	else
	{
		return -1;
	}
 }

void writeToSessionFile(struct session_entry *sesh_entry)
{
	//writes session entry to file, rectifies any ties
	
	FILE* fp;
	fp= fopen("/tmp/sesh_keys","w+");
	
	//first check for existing session for this host
	struct session_entry *line;
	struct session_entry *file_entry;
	
	int line_index = 0;
	int foundDup = 0;

    while (fread(line, sizeof(struct session_entry), 1, fp)) {
        
		file_entry = (struct session_entry*) line;
		
		if (file_entry->host_id == sesh_entry->host_id)
		{
			//got a match, check timestamps.
			if (timeval_cmp(&(sesh_entry->timestamp),&(file_entry->timestamp)) == 1)
			{
				close(fileno(fp));
				return; //keep entry in file
			}
			else if (timeval_cmp(&(sesh_entry->timestamp),&(file_entry->timestamp)) == -1)
			{
				foundDup = 1;
				break; //we will assume there weren't TWO duplicates, because then something is wrong
			}
			else
			{
				//check first 4 bytes of sesh_entry. very unlikely they will be equal
				if (memcmp((sesh_entry->sym_key),file_entry->sym_key,sizeof(file_entry->sym_key)) > 0)
				{
					close(fileno(fp));
					return; //keep entry in file
				}
				else if (memcmp((sesh_entry->sym_key),file_entry->sym_key,sizeof(file_entry->sym_key)) > 0)
				{
					foundDup = 1;
					break; //we will assume there weren't TWO duplicates, because then something is wrong
				}
				else
				{
					printf("\nDuplicate error. Session already was in file with same timestamp and key\n");
					close(fileno(fp));
					return;
				}
			}
		}
		else
		{
			line_index++;
		}
    }
	close(fileno(fp));
	
	
	if (foundDup)
	{
		//append sesh_entry to end of file
		FILE *append_sesh_file;
		append_sesh_file = fopen("/tmp/sesh_keys", "a");
		fwrite(sesh_entry, sizeof(struct session_entry), 1, append_sesh_file);
		close(fileno(append_sesh_file));
		return;
	}
	
	
	//now delete and replace with sesh entry, unless there was a 'better' existing version in the file
	
	FILE *old_sesh_file;
	old_sesh_file = fopen("/tmp/sesh_keys", "r");
	
	FILE *new_sesh_file;
	new_sesh_file = fopen("/tmp/sesh_keys_temp", "w");
	int lineNumber = 0;
	int len;

	if (old_sesh_file != NULL) {
		while ((len = fread(line, sizeof(struct session_entry), 1, old_sesh_file)))
		{
			if (len != 1) 
			{
				printf("ERROR: File not even multiple of session entry length.\n");
				break;
			}
			else {
				lineNumber++;
				if (lineNumber == line_index) {

					fwrite(sesh_entry, sizeof(struct session_entry), 1, new_sesh_file);
				} else {
					fwrite(line, sizeof(struct session_entry), 1, new_sesh_file);
				}
			}
		}
	} else {
		printf("ERROR");
	}
	remove("/tmp/sesh_keys");
	rename("/tmp/sesh_keys_temp", "/tmp/sesh_keys");
	close(fileno(old_sesh_file));
	close(fileno(new_sesh_file));

	
	printf("Deleted duplicate for host %d",sesh_entry->host_id);
	return;
}



int main(int argc, char *argv[])
{
	unsigned char recvbuf[BUF_SIZE];
	unsigned char sendbuf[BUF_SIZE];

	struct sockaddr_ll raw_address;
	raw_address.sll_family=AF_PACKET;
	raw_address.sll_protocol=htons(ETH_P_ALL);

	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	memset(sendbuf,0,BUF_SIZE);
	memset(recvbuf,'\0',BUF_SIZE);
	
	int sock_size;
	int recv_size;
	int sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	
	if(sock<0){
		printf("Uhoh, couldn't create socket");
		return -1;
	}
	
	struct ifreq ifr;
	
	//Bind socket to interface
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sock,SIOCGIFINDEX,&ifr);	
	raw_address.sll_ifindex=ifr.ifr_ifindex;
	bind(sock,(const struct sockaddr*)&raw_address,sizeof(struct sockaddr_ll));
	
	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;

	if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		perror("setsockopt(PACKET_MR_PROMISC) failed");
		return 1;
	}
	
	
	//Create send sock
	int send_sock;
	send_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

	if(send_sock < 0){
		perror("Error creating send socket\n");
		return -1;
	}
	
	/*Get interface index*/
	memset(&ifr,0,sizeof(struct ifreq));
	strncpy(ifr.ifr_name, argv[1],IFNAMSIZ-1);
	if(ioctl(send_sock,SIOCGIFINDEX,&ifr)<0){
		perror("IOCTL ERROR\n");
		return -1;
	}
	else{
		printf("Found send interface....\n");
	}
	
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
	
	map_t session_map = hashmap_new();
	struct session_state *seshptr;
	struct session_entry sesh_entry;
	
	struct custom_header *customhdr;
	int num_errors = 0;
	int sent=0;
	
	while(1)
	{

		recv_size = recvfrom(sock,recvbuf,BUF_SIZE,0,(struct sockaddr *)&raw_address,(socklen_t*)&sock_size);
		
		if (recv_size < 0)
		{
			num_errors++;
			printf("Error #%d\n",num_errors);
			continue;
		}
		
		printf("\nGot packet\n");
		
		customhdr = (struct custom_header*)recvbuf;
		if (customhdr->ether_type==0x0102) //this is a key exchange message
		{
			memset(sendbuf, 0, 256);
			memset(&sesh_entry, 0, sizeof(sesh_entry));
			
			printf("\tPacket is a Key Exchange message\n");
			
			if (((uint32_t) customhdr->dest) != MY_ADDR)
			{
				printf("Forwarding to appropriate host\n");
				continue;
			}
			
			if (customhdr->pkt_type == 20) //host has requested session
			{
				printf("Initiating key exchange with host %hu...\n",customhdr->src);
				if ((customhdr->pkt_size < 88) || (recv_size < (customhdr->pkt_size+sizeof(struct custom_header))))
				{
					printf("Packet size error (%d), incorrect format (%d)\n",customhdr->pkt_size,recv_size);
					continue;
				}
				
				if (((uint32_t) customhdr->src) == MY_ADDR)
				{
					printf("Received message from self.\n");
					continue;
				}
				printf("Checking hashmap...\n");	
				if (hashmap_get(session_map, ((uint32_t) customhdr->src), ((void**) &seshptr)) == MAP_OK) //no entry should be present
				{
					printf("Duplicate session: host %d\t stage:%d \time:%d s. Existing one deleted.\n",seshptr->host_id,seshptr->stage,seshptr->timestamp.tv_sec);
					hashmap_remove(session_map, ((uint32_t) customhdr->src));
				}
				printf("Done checking hashmap...\n");
				if (((uint32_t) customhdr->src) == MY_ADDR)
				{
					printf("Received message from self.\n");
					continue;
				}
				
				seshptr = malloc(sizeof(struct session_state));
				uint8_t key[16];
				uint8_t encrypted_key[128];
				printf("Generating AES key...\n");
				if (generate_aes128_key(key))
				{
					printf("About to encrypt AES key\n");
					RSA* pubkey=get_public_key_from_array(recvbuf+sizeof(struct custom_header));
					encrypt_with_public_key(pubkey,key, encrypted_key,sizeof(key));
					printf("Done encrypting AES key\n");	
					memcpy(&(seshptr->timestamp),(customhdr + sizeof(customhdr) + sizeof(RSA)), sizeof(struct timeval));
					seshptr->stage = 1;
					memcpy(seshptr->generated_sym_key, (customhdr + sizeof(customhdr)), sizeof(key));
					seshptr->host_id = customhdr->src;
					
					hashmap_put(session_map,((uint32_t) seshptr->host_id), ((void**) &seshptr));
					
					customhdr = (struct custom_header*) sendbuf;
					customhdr->dest=seshptr->host_id;
					customhdr->src=MY_ADDR;
					customhdr->pkt_type = ((uint16_t) 21);
					customhdr->pkt_size = ((uint16_t) sizeof(encrypted_key));
					memcpy((sendbuf+sizeof(customhdr)), encrypted_key, sizeof(encrypted_key));
					memcpy((sendbuf+sizeof(customhdr)+sizeof(encrypted_key)), &(seshptr->timestamp), sizeof(struct timeval));
					if ((sent = sendto(send_sock, sendbuf, ((unsigned int)(sendbuf+sizeof(customhdr)+ sizeof(encrypted_key) + sizeof(struct timeval))), 0, (struct sockaddr*)&send_address, sizeof(send_address))) < 0){
						perror("Send failed!!!!!\n");
						return -1;
					}
					printf("\tSent encrypted key response %d bytes. . .\n",sent);
					
					RSA_free(pubkey);
				}
				else
				{
					perror("Key generation error\n");
					return -1;
				}
			}
			else if (customhdr->pkt_type == 21) //Encrypted symmetric key (this is sent by key exchange server, not destined to us)
			{
				//this message is not destined for key exchange server
				continue;
			}
			else if (customhdr->pkt_type == 22) //ACK
			{
				if (((uint32_t) customhdr->src) == MY_ADDR)
				{
					printf("Received message from self.\n");
					continue;
				}
				if (hashmap_get(session_map, ((uint32_t) customhdr->src), seshptr) == MAP_MISSING) //entry should be present
				{
					printf("Received mysterious ACK");
					continue;
				}
					
				if (seshptr->stage == 2)
				{
					seshptr->stage = 3;
					
					sesh_entry.host_id = seshptr->host_id;
					memcpy(&((&sesh_entry)->sym_key), &(seshptr->generated_sym_key), 16);
					memcpy(&((&sesh_entry)->timestamp),&(seshptr->timestamp),sizeof(struct timeval));
					
					writeToSessionFile(&sesh_entry);
					
				}
			}
			else
			{
				printf("Error: Bad value of session state.\n");
			}
			
		}
		
	}
	close(sock);
	
	hashmap_free(session_map);
	
	return 0;
}
