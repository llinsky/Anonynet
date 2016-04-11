

#include "get_packets.h"
#include <linux/if_packet.h>
#include "print_packets.h"
#include <unistd.h>
#include <net/ethernet.h>
#include "packet_response.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <fcntl.h>

void get_packets(){
	struct sockaddr_ll newsockaddr;
	unsigned char recvbuf[2048];
	memset(recvbuf,'\0',2048);
	int sock_size=sizeof newsockaddr;
	int recv_size,i;
	
	struct sockaddr_ll sockaddrll;

	//Prepare sockaddr
	sockaddrll.sll_family=AF_PACKET;
	sockaddrll.sll_protocol=htons(ETH_P_ALL);
	sockaddrll.sll_halen=6;
	sockaddrll.sll_addr[0]=0x00;
	sockaddrll.sll_addr[1]=0x00;
	sockaddrll.sll_addr[2]=0x00;
	sockaddrll.sll_addr[3]=0x00;
	sockaddrll.sll_addr[4]=0x00;
	sockaddrll.sll_addr[5]=0x00;
	sockaddrll.sll_addr[6]=0x00;
	sockaddrll.sll_addr[7]=0x00;

	while(1){

		for(i=0;i<vars.numifaces;i++){
			recv_size = recvfrom(vars.sockets[i],recvbuf,2048,0,(struct sockaddr*)&newsockaddr,(socklen_t*)&sock_size);
			if(recv_size>0 && newsockaddr.sll_pkttype!=PACKET_OUTGOING){
				gyn_packet_handler(recvbuf,recv_size, &sockaddrll, newsockaddr.sll_ifindex);
			}
		
		}
	}
	

}


