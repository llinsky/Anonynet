//
//
//packet_response.c

#include "packet_response.h"
#include <sys/ioctl.h>
#include "print_packets.h"
#include <net/if.h>
#include "get_packets.h"
#include <sys/socket.h>
#include <net/ethernet.h>
//#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include "encrypt_decrypt.h"
#include "hashmap.h"

int gyn_packet_handler(unsigned char *packet, int size, struct sockaddr_ll* sockaddrll, int if_index){
	
	/* declare pointers to packet headers */
	struct gyn_header *gyn;  /* The ethernet header [1] */

	/* define gyn protocol header */
	gyn = (struct gyn_header*)(packet);
	//print_gyn_header(gyn);
	if(gyn->ether_type==PROTO_TYPE1){//Normal, encrypted packet
		//get interface to send out on.
		
		unsigned char dest_jumbled[16];
		unsigned char dest_decrypted[16];
		memcpy(dest_jumbled,packet,12);
		memcpy(&dest_jumbled[12],&packet[14],4);
		//printf("Decrypting with key for iface %d: ",if_index);
		//print_aes_key(&vars.keys[16*if_index],16);	
		//printf("\tEncrypted header: ");
		//print_aes_key(dest_jumbled,16);
		int decrypted_text_len = decrypt(dest_jumbled, 16 , &vars.keys[16*if_index], NULL, dest_decrypted);
		if(decrypted_text_len==-1){
//			printf("Decrypt Error \n");
			return -1;
		}		
		uint16_t pkt_dest;
		memcpy(&pkt_dest, &dest_decrypted, sizeof(uint16_t));
		//printf("\tDecrypted header (destination address): %hu\n",pkt_dest);	
		int index;
		int logic_found=get_route_logic(((uint32_t)pkt_dest),&index);
		sockaddrll->sll_ifindex=index;
		
		//send out on interface
		int result=0;
		int encrypted_text_len = encrypt(dest_decrypted, decrypted_text_len , &vars.keys[16*index], NULL, dest_jumbled);
		if(encrypted_text_len==-1){
			return -1;
		}
		memcpy(packet,dest_jumbled,12);
		memcpy(&packet[14],&dest_jumbled[12],4);
		//printf("\tRe-Encrypted Header: ");
		//print_aes_key(dest_jumbled,16);	
		//printf("\tSending on interface %d\n\n",index);	
		if(logic_found){
			result=send_packet(packet,size,sockaddrll);
		}
		else{
			printf("\tError finding route\n");
			return -1;
		}
		if(result<0){
			//perror("Error sending packet:");
		}
		return 1;
	}	
	else if(gyn->ether_type==PROTO_TYPE2 && gyn->dest!=vars.my_addr){//This is an unencrypted key exchange packet
		//get interface to send out on.
//		printf("\tForwarding Key Exchange Packet, proto %hu from %hu to %hu\n",gyn->pkt_type,gyn->src,gyn->dest);
		int index;
		int logic_found=get_route_logic(((uint32_t)gyn->dest),&index);
		
		sockaddrll->sll_ifindex=index;
		
		//send out on interface
		int result=0;
		if(logic_found){
			result=send_packet(packet,size,sockaddrll);
		}
		if(result<0){
			//perror("Error sending packet:");
		}
		return 1;
	}
	else if(gyn->ether_type==PROTO_TYPE2 && gyn->dest==vars.my_addr){
//		printf("\tKey exchange packet destined for me!!\n");
		sleep(2);	
		struct route_entry* route;
		if (hashmap_get(vars.routing_table, gyn->src, ((void**) &route)) == MAP_MISSING) 
		{
			printf("\nError: Missing entry in routing table during key exchange. Bad format for rtr.config \n");
			return -1;
		}
		else
		{
			unsigned char symkey[16];
			if(route->address==route->next_hop){
				get_aes_key(route->address,symkey);
//				printf("Copying this key to index %d \n",route->send_index);
				memcpy(&vars.keys[(route->send_index)*16], symkey, 16);
//				printf("This key in memory: ");
//				print_aes_key(&vars.keys[(route->send_index)*16],16);
			}	
		}
		return 1;
	}
	else{
		//printf("\tInvalid ethertype received \n");
		return -1;
	}
}

int send_packet(unsigned char* packet, int size, struct sockaddr_ll* sockaddrll){
	int bytes_written=0;
//	printf("\tSending to interface %d\n",sockaddrll->sll_ifindex);
	bytes_written=sendto(vars.send_sock_fd,packet,size,0,(struct sockaddr*)sockaddrll,sizeof(struct sockaddr_ll));
	return bytes_written;
}

int get_route_logic(uint32_t dest,int* index){
	struct route_entry *route;
	if (hashmap_get(vars.routing_table, dest, ((void**) &route)) == MAP_MISSING) 
	{
		printf("\tCould not find route for destination: %hu\n",dest);
		return 0;
	}
	
	*index = route->send_index;
	return 1;
}



