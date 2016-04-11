/* main program for customRouter */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ip.h> 
#include <netinet/ether.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include "get_packets.h"
#include "print_packets.h"
#include "security.h"
#include "aes.h"
#include "globals.h"
#include <net/if_arp.h>
#include <stdio.h>
#include "hashmap.h"
#include <inttypes.h>

struct global_vars vars;


void init_recv_sockets(char* iface, int index){
	int sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	vars.sockets[index]=sock;
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
		printf("bind issue\n");
	}
	else{
//		printf("Listener bound to %s.....\n",iface);
	}
	//Set sock to promiscuous
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
}

int index_exists(int index,int count){
	int i;
	for(i=0;i<count;i++){
		if(vars.ifaces[i]==index){
			//already listiening on this port
			return 1;
		}
	}
	//not listening on this interface yet
	return 0;
}

void build_routing_table()
{
	FILE* fp;
	fp=fopen("rtr.config","r");
	char iface[10];
	struct ifreq ifr;
	uint32_t address,next_hop;
	memset(iface,'\0',10);
	int count=0,numinterfaces=0;
	
	struct route_entry *route;
	
	vars.routing_table = hashmap_new();
	//Get my address from .config file
	//fscanf(fp,"%hu",&vars.my_addr); //passing in as arg now
	//printf("\tMy address: %hu\n",vars.my_addr);
	while(fscanf(fp,"%s %" SCNd32 " %" SCNd32 "\n",iface,&address,&next_hop)==3 && count<50 ){
		//Now create new routing table entry
		
		if (hashmap_get(vars.routing_table, address, ((void**) &route)) == MAP_OK) 
		{
			printf("\n\nError: Duplicate entry in routing table. Bad format for rtr.config \n\n");
		}
		
		route = malloc(sizeof(struct route_entry));
		
		route->address = address;
		route->next_hop = next_hop;		
		strncpy(ifr.ifr_name,iface,IFNAMSIZ-1);
		if(ioctl(vars.send_sock_fd,SIOCGIFINDEX,&ifr)<0){
			printf("IOCTL ERROR \n");
		}
		route->send_index=ifr.ifr_ifindex;
		
//		print_routing_entry(&(vars.routing_table[count]));
		//Listen on new interface if we're not already
		
		if(!index_exists(ifr.ifr_ifindex,count)){
			init_recv_sockets(ifr.ifr_name,numinterfaces);
			vars.ifaces[numinterfaces] = ifr.ifr_ifindex;
			numinterfaces++;
		}
		count++;
		if (hashmap_put(vars.routing_table, address, route) != MAP_OK)
		{
			printf("Error adding entry to hashmap \n\n");
			return;
		}
		printf("\t\tAdded entry to routing table for dest: %d \n", address);
	}
	
	vars.numifaces=numinterfaces;
	vars.numaddresses=count;
	printf("\tListening on %d ports....\n",numinterfaces);
	printf("\tRouting for %d addresses...\n",count);
	fclose(fp);
	printf("\tRouting table built.....\n");
}

void refresh_routing_table()
{
	//optional: implement scheduled refresh based on ospf later
}

void init_send_socket(){
	int fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(fd<0){
		perror("Error creating socket\n");
	}	
	vars.send_sock_fd=fd;
//	printf("Send Socket initialized....\n");
}

void close_sockets(){
	close(vars.send_sock_fd);
	int i;
	for(i=0;i<vars.numifaces;i++){
		close(vars.sockets[i]);
	}
}

int main(int argc, char *argv[]){
	
	printf("============================================================================\n");
	printf("\tStarting Custom Router\n");
	
	if (argc != 2)
	{
		printf("\nUsage: sudo ./customRouter [my addr]\n");
		return -1;

	}
	
	int MY_ADDR = atoi(argv[1]);
	vars.my_addr = MY_ADDR; //passing in as arg now
	printf("\tMy address: %hu\n",vars.my_addr);
	
	init_send_socket();
	build_routing_table();
	//Fork process, one to route, one to exchange keys
	pid_t pid=fork();
	if(pid>0){
		printf("\tCapturing and routing packets...\n");
		printf("============================================================================\n\n");
		get_packets(); //Route and capture packets indefinitely
	}	
	else if(pid==0){//Child process to do key exchange
		sleep(5);
		//Generate RSA key pair for secure key exchange	
		printf("============================================================================\n");
		printf("\tInitiating public key exchange\n");
		generate_rsa_key_pair(1024);
		//Now send out our public keys
		send_public_key();
	}	
	else{
		printf("fork() failed\n");
		return -1;
	}
	if(pid>0){
		printf("\nError: Shouldn't reach this point.\n");
	}	
	else if(pid==0){
		sleep(10);
		printf("\n\tSaved keys: \n");
		uint16_t i;
		unsigned char symkey[16];
		memset(symkey,0,16);
		for(i=1;i<vars.numaddresses+2;i++){
			if(i==vars.my_addr){
				continue;
			}
			get_aes_key(i,symkey);	
			printf("\t\tNode %hu: ",i);
			print_aes_key(symkey,16);
			
			
		}
		printf("\n\tKey exchange subprocess exiting....\n");
		printf("============================================================================\n");
	}
	//Now this thread should re-exchange keys every 30 seconds, allowing for a more secure system
	
	if(pid==0){
		
		uint16_t i;
		unsigned char symkey[16];
		while(1){
			sleep(30);
			printf("============================================================================\n");
			printf("\tRe-exchanging symmetric keys \n");
			//Now send out our public keys
			send_public_key();
			//Print out new public keys	
			sleep(10);
			memset(symkey,0,16);
			for(i=1;i<vars.numaddresses+2;i++){
				if(i==vars.my_addr){
					continue;
				}
				get_aes_key(i,symkey);	
				printf("\t\tNode %hu: ",i);
				print_aes_key(symkey,16);
				
				
			}
			printf("\n\tKey exchange subprocess exiting....\n");
			printf("============================================================================\n");
		}
	}
	
	close_sockets();
	hashmap_free(vars.routing_table);
	
	return 1;
}
