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


#include "security.h"
#include "hashmap.h"
#include "globals.h"

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

#define BUF_SIZE		2048



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

/* //(Defined in globals.h)
struct session_entry {
	uint16_t host_id;
	uint8_t sym_key[16];
	struct timeval timestamp;
};
*/

struct session_state {
	int stage; //stage of the transaction: 0=not started, 1=received public key, 2=received ack (complete)
	
	uint16_t host_id;
	
	uint8_t generated_sym_key[16];
	
	struct timeval timestamp; //timeout after 60 seconds? maybe later
};

/* Returns -1 if x<y, 1 if x>y, else 0.  */
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
	
	//printf("\tWriting session key to file...\n");
	FILE* fp;
	fp= fopen("/tmp/sesh_keys","r");
	int file_exists=1;
	if(fp==NULL){
		file_exists=0;
	}	
	//first check for existing session for this host
	struct session_entry *line=malloc(sizeof(struct session_entry));
	struct session_entry *file_entry=NULL;
	
	int line_index = 0;
	int foundDup = 0;
	if(file_exists){
	   while (!feof(fp)) {
			fread(line, sizeof(struct session_entry), 1, fp);
			file_entry = (struct session_entry*) line;
			
			if (file_entry->host_id == sesh_entry->host_id)
			{
				//printf("\tAlready have an entry for host %hu...\n",sesh_entry->host_id);
				//got a match, check timestamps.
				if (timeval_cmp(&(sesh_entry->timestamp),&(file_entry->timestamp)) ==-1)
				{
					fclose(fp);
					//printf("\tCurrent entry is newer, not going to overwrite\n");
					return; //keep entry in file
				}
				else if (timeval_cmp(&(sesh_entry->timestamp),&(file_entry->timestamp)) == 1)
				{
					foundDup = 1;
					//printf("\tCurrent entry is older, going to overwrite it\n");
					break; //we will assume there weren't TWO duplicates, because then something is wrong
				}
				else
				{
					//printf("\tTimestamps are the same. This shouldn't happen!!\n");
					//check first 4 bytes of sesh_entry. very unlikely they will be equal
					if (memcmp((sesh_entry->sym_key),file_entry->sym_key,sizeof(file_entry->sym_key)) > 0)
					{
						fclose(fp);
						return; //keep entry in file
					}
					else if (memcmp((sesh_entry->sym_key),file_entry->sym_key,sizeof(file_entry->sym_key)) < 0)
					{
						foundDup = 1;
						break; //we will assume there weren't TWO duplicates, because then something is wrong
					}
					else
					{
						//printf("\nDuplicate error. Session already was in file with same timestamp and key\n");
						fclose(fp);
						return;
					}
				}
			}
			else
			{
				line_index++;
			}
	    }
	}
	if(fp!=NULL){
		fclose(fp);
	}
	
	if (!foundDup)
	{
		//append sesh_entry to end of file
		//printf("\tAppending to session keys file\n");
		FILE *append_sesh_file;
		append_sesh_file = fopen("/tmp/sesh_keys", "a+");
		int bytes_written=fwrite(sesh_entry, sizeof(char),sizeof(struct session_entry), append_sesh_file);
		if(bytes_written<0){
			//printf("Error writing to sesh_keys file");
		}
		else{
			//printf("Wrote %d bytes\n",bytes_written);
		}
		fclose(append_sesh_file);
		return;
	}
	
	
	//now delete and replace with sesh entry, unless there was a 'better' existing version in the file
	//printf("\tReplacing session key...\n");	
	fp = fopen("/tmp/sesh_keys", "r+");
	if(fp==NULL){
		//printf("Error opening session keys file to replace\n");
	}
	//fseek to line where we found duplicate to replace
	fseek(fp,line_index*sizeof(struct session_entry),SEEK_SET);
	fwrite(sesh_entry,sizeof(char),sizeof(struct session_entry),fp);
	fclose(fp);
	free(line);
	
	//printf("\tReplaced duplicate for host %d\n",sesh_entry->host_id);
	return;
}




int index_exists(int* ifaces,int index,int count){
	int i;
	for(i=0;i<count;i++){
		if(ifaces[i]==index){
			//already listiening on this port
			return 1;
		}
	}
	//not listening on this interface yet
	return 0;
}





int init_recv_socket(char *iface){
	int sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll raw_address;
	struct ifreq ifr;
	raw_address.sll_family=AF_PACKET;
	raw_address.sll_protocol=htons(ETH_P_ALL);
	memset(&ifr,0,sizeof(struct ifreq));
	strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);
	ioctl(sock,SIOCGIFINDEX,&ifr);
	raw_address.sll_ifindex=ifr.ifr_ifindex;
	int bind1=bind(sock,(const struct sockaddr*)&raw_address,sizeof(struct sockaddr_ll));		
	if(bind1<0){
		//printf("bind issue\n");
	}
	else{
		//printf("Listener bound to %s.....\n",iface);
	}
	/*Set sock to promiscuous*/
	struct packet_mreq mr;
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex=ifr.ifr_ifindex;
	mr.mr_type=PACKET_MR_PROMISC;
	if(setsockopt(sock,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr))<0){
		perror("Setsockopt(PROMISC) failed");
	}
	else{
//		printf("Interface %s set to promiscuous....\n",iface);
	}
	fcntl(sock,F_SETFL,O_NONBLOCK);
	return sock;
}


int load_recv_socks(int *sockets, int *iface_index, int send_sock_fd)
{
	FILE* fp;
	fp=fopen("rtr.config","r");
	char iface[10];
	struct ifreq ifr;
	uint16_t address,next_hop;
	
	memset(iface,'\0',10);
	int count=0;
	
	//int nodeID;
	//fscanf(fp,"%d",&nodeID); //changing format of rtr.config
	while(fscanf(fp,"%s %hu %hu",iface,&address,&next_hop)==3 && count<5 ){	
		strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);
		if(ioctl(send_sock_fd,SIOCGIFINDEX,&ifr)<0){
			printf("IOCTL ERROR \n");
		}
		if(!index_exists(iface_index,ifr.ifr_ifindex,count)){
			iface_index[count]=ifr.ifr_ifindex;
			sockets[count] = init_recv_socket(ifr.ifr_name);
			count++;
		}		
	}
	
	//printf("\tListening on %d ports....\n",count);
	fclose(fp);
	//printf("\tRouting table built.....\n");
	
	return count;
}




int main(int argc, char *argv[])
{
	unsigned char recvbuf[BUF_SIZE];
	unsigned char sendbuf[BUF_SIZE];
	
	//for router config -- not set for one port interface
	int sockets[10];
	int iface_index[10];
   	int numports = 0;

	struct sockaddr_ll raw_address;
	raw_address.sll_family=AF_PACKET;
	raw_address.sll_protocol=htons(ETH_P_ALL);

	char ifName[IFNAMSIZ];
	
	int sock_size;
	int recv_size;
	int sock;
	
	//Create send sock
	int send_sock;
	send_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(send_sock < 0){
		perror("Error creating send socket\n");
		return -1;
	}
	struct ifreq ifr;
	struct packet_mreq mr;
	
	if (argc < 2)
	{
		printf("\nUsage: sudo ./keyServer [my addr] [interface (optional)]\n");
		return -1;

	}
	
	int MY_ADDR = atoi(argv[1]);
	//printf("My address: %d\n",MY_ADDR);
	
	/* Get interface name */
	if (argc > 2)
	{
		strcpy(ifName, argv[2]); //if you don't pass in an interface, it assumes you are a router and load from rtr.config
		
		sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
		
		if(sock<0){
			printf("Uhoh, couldn't create socket");
			return -1;
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
		strncpy(ifr.ifr_name, argv[2],IFNAMSIZ-1);
		if(ioctl(send_sock,SIOCGIFINDEX,&ifr)<0){
			perror("IOCTL ERROR\n");
			return -1;
		}
		else{
			//printf("Found send interface....\n");
		}
	}
	else
	{
		//printf("Loading sockets for each interface . . .\n");
		numports = load_recv_socks(sockets, iface_index, send_sock);
		
	}

	memset(sendbuf,0,BUF_SIZE);
	memset(recvbuf,'\0',BUF_SIZE);

	
	
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
	int last_index = 0;
	int sent=0;
	int i;
	
	
	while(1)
	{
		if (numports == 0)
		{
			recv_size = recvfrom(sock,recvbuf,BUF_SIZE,0,(struct sockaddr*)&raw_address,(socklen_t*)&sock_size);
			if ((recv_size < 0) || raw_address.sll_pkttype==PACKET_OUTGOING)
			{
				continue;
			}
			send_address.sll_ifindex=ifr.ifr_ifindex;
			last_index = ifr.ifr_ifindex;
		}
		else
		{
			for(i=0;i<numports;i++){
				recv_size = recvfrom(sockets[i],recvbuf,BUF_SIZE,0,(struct sockaddr*)&raw_address,(socklen_t*)&sock_size);
				if(recv_size>0 && raw_address.sll_pkttype!=PACKET_OUTGOING){
					last_index = iface_index[i];
					send_address.sll_ifindex=last_index;
					//printf("Got a hit!\n");
					break;
				}
			}

			if ((recv_size < 0) || raw_address.sll_pkttype==PACKET_OUTGOING)
			{
				continue;
			}
		}
			
		
		//printf("\n\nGot packet on interface: %d\n", last_index);
		
		customhdr = (struct custom_header*)recvbuf;
		if (customhdr->ether_type==0x88b6) //this is a key exchange message
		{
			memset(sendbuf, 0, 256);
			memset(&sesh_entry, 0, sizeof(sesh_entry));
			
		/*	printf("\tPacket is a Key Exchange message\n");
			
			printf("\n\t\tHeader received: \n");
			printf("\t\t\tdest: %4X \n",customhdr->dest);
			printf("\t\t\tsrc: %4X \n",customhdr->src);
			printf("\t\t\tseq: %4X \n",customhdr->seq);
			printf("\t\t\tpkt_size: %4X \n",customhdr->pkt_size);
			printf("\t\t\tpkt_type: %4X \n",customhdr->pkt_type);
			printf("\t\t\tether_type: %4X \n",customhdr->ether_type);
			printf("\t\t\tpadding: %8X \n",customhdr->crypto_padding);
		*/	
			
			if (((uint32_t) customhdr->dest) != MY_ADDR)
			{
		//		printf("\tForwarding to appropriate host\n");
				continue;
			}
			
			if (customhdr->pkt_type == 20) //host has requested session
			{
		//		printf("\tInitiating key exchange with host %hu...\n",customhdr->src);
				if ((customhdr->pkt_size < 88) || (recv_size != (customhdr->pkt_size+sizeof(struct custom_header))))
				{
					printf("\t\nPacket size error (%d), incorrect format (%d)\n",customhdr->pkt_size,recv_size);
					continue;
				}
				
				if (((uint32_t) customhdr->src) == MY_ADDR)
				{
					printf("\tReceived message from self.\n");
					continue;
				}
		//		printf("\tChecking hashmap...\n");	
				if (hashmap_get(session_map, ((uint32_t) customhdr->src), ((void**) &seshptr)) == MAP_OK) //no entry should be present
				{
		//			printf("\tDuplicate session: host %d\t stage:%d \ttime:%d s. Existing one deleted.\n",seshptr->host_id,seshptr->stage,seshptr->timestamp.tv_sec);
					
					if (hashmap_remove(session_map, ((uint32_t) customhdr->src)) == MAP_MISSING)
					{
						printf("\t\tWeird hashmap remove error\n");
					}
					
				}
		//		printf("\tDone checking hashmap...\n");
				if (((uint32_t) customhdr->src) == MY_ADDR)
				{
					printf("\tReceived message from self.\n");
					continue;
				}
				
				seshptr = malloc(sizeof(struct session_state));
				memset(seshptr, 0, sizeof(struct session_state));
				
				uint8_t key[16];
				uint8_t encrypted_key[128];
				int encrypt_size;
				memset(key, 0, 16);
				memset(encrypted_key, 0, 128);
		//		printf("\tGenerating AES key...\n");
				if (generate_aes128_key(key))
				{
/*					printf("\tAES key raw for host %hu:\t\t",customhdr->src);
					for (i=0;i<16;i++)
					{
						printf("%2X ",key[i]);
					}
					printf("\n");*/
					
		//			printf("\n\tAbout to encrypt AES key\n");
					RSA* pubkey=get_public_key_from_array(recvbuf+sizeof(struct custom_header));
					encrypt_size=encrypt_with_public_key(pubkey,key, encrypted_key,sizeof(key));

		//			printf("\tAES key Encrypted:\n\t\t");
					for (i=0;i<encrypt_size;i++)
					{
		//				printf("%2X ",encrypted_key[i]);
					}
		//			printf("\n\tDone encrypting AES key, encrypted size is %d\n",encrypt_size);	
					memcpy(&(seshptr->timestamp),(recvbuf + sizeof(struct custom_header) +customhdr->pkt_size-sizeof(struct timeval) ), sizeof(struct timeval));
		//			printf("Received timestamp: %ld.%06ld\n",seshptr->timestamp.tv_sec,seshptr->timestamp.tv_usec);
					seshptr->stage = 1;
					memcpy(seshptr->generated_sym_key, key, sizeof(key));
					seshptr->host_id = customhdr->src;
					
					hashmap_put(session_map,((uint32_t) seshptr->host_id), seshptr);
					
					customhdr = (struct custom_header*) sendbuf;
					customhdr->dest=seshptr->host_id;
					customhdr->src=MY_ADDR;
					customhdr->seq=0;
					customhdr->unused=0xffff;
					customhdr->crypto_padding=0;
					customhdr->pkt_type = ((uint16_t) 21);
					customhdr->ether_type = ((uint16_t) 0x88b6);
					customhdr->pkt_size = ((uint16_t) sizeof(encrypted_key) + sizeof(struct timeval));
					memcpy((sendbuf+sizeof(struct custom_header)), encrypted_key, encrypt_size);
					memcpy((sendbuf+sizeof(struct custom_header)+encrypt_size), &(seshptr->timestamp), sizeof(struct timeval));
					
					if ((sent = sendto(send_sock, sendbuf, (sizeof(struct custom_header)+ encrypt_size + sizeof(struct timeval)), 0, (struct sockaddr*)&send_address, sizeof(send_address))) < 0){
						perror("\t\nSend failed!!!!!\n");
						return -1;
					}
		//			printf("\tSent encrypted key response %d bytes. . .\n",sent);
					
					RSA_free(pubkey);
				}
				else
				{
					perror("\t\nKey generation error\n");
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
					printf("\tReceived message from self.\n");
					continue;
				}
				if (hashmap_get(session_map, ((uint32_t) customhdr->src), ((void**) &seshptr)) == MAP_MISSING) //entry should be present
				{
//					printf("\tReceived mysterious ACK\n");
					continue;
				}
				
		//		printf("\tGot ACK, checking entry\n");
				
				if (seshptr->stage == 1)
				{
					seshptr->stage = 2;
					
					sesh_entry.host_id = seshptr->host_id;
					memcpy(&((&sesh_entry)->sym_key), &(seshptr->generated_sym_key), 16);
					memcpy(&((&sesh_entry)->timestamp),&(seshptr->timestamp),sizeof(struct timeval));
					
		//			printf("\tEntry and stage found: writing to file\n");
					
					writeToSessionFile(&sesh_entry);
					
					if (hashmap_remove(session_map, ((uint32_t) seshptr->host_id)) == MAP_MISSING)
					{
						printf("\t\tWeird hashmap remove error - was trying to remove entry after writing to file\n");
					}
				}
				else
				{
					printf("\nError: Bad value of session state.\n\n");
				}
			}
			else
			{
				printf("Unknown packet type for key exchange\n");
			}
			
		}
		
	}
	close(sock);
	
	int j;
	for(j=0;j<numports;j++){
		close(sockets[j]);
	}
	
	hashmap_free(session_map);
	
	return 0;
}
