#include "print_packets.h"



void print_gyn_header(const struct gyn_header* gyn){
	printf("Destination: %hu\n",gyn->dest);
	printf("Source: %hu\n",gyn->src);
	printf("Sequence number: %hu\n",gyn->seq);
	printf("Packet Size: %hu\n",gyn->pkt_size);
	printf("Packet Type: %hu\n",gyn->pkt_type);
	printf("Ether Type: %hu\n",gyn->ether_type);	
	printf("Crypto Padding: %u\n",gyn->crypto_padding);
}

void print_routing_entry(const struct route_entry* route){
	printf("ROUTING ENTRY:\n");
	printf("Interface index: %u\n",route->send_index);
	printf("Address: %u\n",route->address);
	printf("Next_hop: %u\n",route->next_hop);
	
}

void print_aes_key(unsigned char* key,int size){
	int i;
	for(i=0;i<size;i++){
		printf("%X",key[i]);	
	}
	printf("\n");
	return;
}
