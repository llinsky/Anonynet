
#include "header.h" 
#include "aes.h"
#include <openssl/conf.h>
#include <net/if.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "aes.h"
#include "print_packets.h"


//for now key_link is equal to key_node, changes later






void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();
/* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


int setup_key_socket(int index){
	
	int sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll sock_addr;
	sock_addr.sll_family=AF_PACKET;
	sock_addr.sll_protocol=htons(ETH_P_ALL);
	sock_addr.sll_ifindex=index;
	int bind_success=bind(sock,(const struct sockaddr*)&sock_addr,sizeof(struct sockaddr_ll));
	if(bind_success<0){
		perror ("Bind error ");
		return -1;
	}	
	
	//Set to promiscuous
	struct packet_mreq mr;
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex=index;
	mr.mr_type=PACKET_MR_PROMISC;
	if(setsockopt(sock,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr))<0){
		perror("Setsockopt(PROMISC) failed");
	}
	return sock;
}


int main (int argc,char *argv[])
{
	//Three phrases to randomly choose between to send
	char* phrase1="The angry elf swore to exact revenge one day.";
	char* phrase2="We are praying nothing goes wrong during this demo";
	char* phrase3="USC football team never should have hired Steve Sarkisian";

	if(argc<5)
   	{
		 printf("Usage: ./sender <iface> <my address> <dest address> <next hop address> \n");
		 exit(1);
	}
	
	/* A 256 bit key for link */
	unsigned char key_link[16];
	/* A 256 bit key for node */
	unsigned char key_node[16];
	/* A 128 bit IV */
	unsigned char *iv = NULL;
   	struct sockaddr_ll device; 
	char* interface = argv[1];
	uint16_t src = (uint16_t) atoi(argv[2]);
	uint16_t dest = (uint16_t) atoi(argv[3]);
	uint16_t next_hop = (uint16_t) atoi(argv[4]);
	int sock_fd=0,recv_sock=0;
	int counter=0;
        //Get key_links
	get_aes_key(next_hop,key_link);
	//get node key
	get_aes_key(dest,key_node); 

	printf("Sending from address %hu \n", src);
	printf("Sending to address %hu \n",dest);
	printf("Next hop address %hu \n\n",next_hop);
	printf("Using link key ");
	print_aes_key(key_link,16);
	printf("Using destination key ");
	print_aes_key(key_node,16);


    	if((device.sll_ifindex = if_nametoindex (interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
       		exit (EXIT_FAILURE);
   	 }

	    // Fill out sockaddr_ll.
    	device.sll_family = AF_PACKET;
    
	device.sll_addr[0]  = 0x22;		//this need not be 22, but have to be filled out
    	device.sll_addr[1]  = 0x22;		 
    	device.sll_addr[2]  = 0x22;
    	device.sll_addr[3]  = 0x22;
   	device.sll_addr[4]  = 0x22;
    	device.sll_addr[5]  = 0x22;
  
   	device.sll_halen = ETHER_ADDR_LEN;
    	device.sll_protocol=htons(ETH_P_ALL);


    //Create a raw socket
    	sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	
	if(sock_fd == -1){
		//socket creation failed, may be because of non-root privileges
       		 perror("Failed to create socket");
       		 exit(1);
   	 }

	//Bind socket to interface
	int rc=setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)+1);

	if(rc!=0){

		perror("Socket Error");
        return 1;
	}

	//Setup key socket
	recv_sock=setup_key_socket(device.sll_ifindex);
	//Set socket to be non-blocking
	rc = fcntl(recv_sock,F_SETFL,O_NONBLOCK);
	if(rc<0){
		printf("Nonblocking socket error\n");
	}
	/* Initialise the library */
  	ERR_load_crypto_strings();
  	OpenSSL_add_all_algorithms();
  	OPENSSL_config(NULL);


	unsigned short ether_type= 0x88B5;
  	




	unsigned char dest_buffer[15];
	memcpy(dest_buffer,&dest,2);
	dest_buffer[7]=0;
	/* Create destination header:  */
	unsigned char tmp[1500];
	unsigned char cipher_header[18];
	int ciphertext_len_part_1 = encrypt ((unsigned char *) dest_buffer,15, key_link, iv,tmp);
  	memcpy(cipher_header,tmp,12);
  	memcpy(cipher_header+14,tmp+12,4);
  	memcpy(cipher_header+12,&ether_type,sizeof (unsigned short));
	
	
	/*Create Second header */
	struct gyn_header customhdr;
	customhdr.dest=dest;
	customhdr.src=src;
	customhdr.seq=1;
	customhdr.pkt_size=0;	
	customhdr.pkt_type=20;
	customhdr.ether_type=0x88b5;
	ciphertext_len_part_1 = encrypt((unsigned char *)&customhdr,sizeof(struct gyn_header),key_node,iv,tmp);
	int custhdrsize=ciphertext_len_part_1;
	int phraselen=0;
	/*Form packet*/
	unsigned char packet[1500];
	unsigned char recvbuf[1500];
	int sent_size=0;
	int recv_size=0;
	int errcounter=0;
	int rn;
	struct gyn_header* gynhdr;
	socklen_t devsize=sizeof(device);
	memcpy(packet,cipher_header,18);
	memcpy(packet+18,tmp,ciphertext_len_part_1);
	/* Encrypt the second part (ACTUAL DATA PACKETS) and also fill it to cipher_packet*/

	while(1){
		//Choose a phrase and send it
		rn=rand()%3;	
		if(rn==0){
			phraselen=strlen(phrase1);	
			ciphertext_len_part_1=encrypt((unsigned char *)phrase1,phraselen,key_node,iv,tmp);
			memcpy(packet+18+custhdrsize,tmp,ciphertext_len_part_1);
		}
		else if(rn==1){
			phraselen=strlen(phrase2);	
			ciphertext_len_part_1=encrypt((unsigned char *)phrase2,phraselen,key_node,iv,tmp);
			memcpy(packet+18+custhdrsize,tmp,ciphertext_len_part_1);
		}
		else{
			phraselen=strlen(phrase3);	
			ciphertext_len_part_1=encrypt((unsigned char *)phrase3,phraselen,key_node,iv,tmp);
			memcpy(packet+18+custhdrsize,tmp,ciphertext_len_part_1);
		}
	//	printf("Sending this ciphertext: \n\t");
	//	print_aes_key(packet+18+custhdrsize,ciphertext_len_part_1);
  		//at this stage the whole cipher_packet is ready to send
      		sent_size=sendto (sock_fd,packet,18+custhdrsize+ciphertext_len_part_1,0, (struct sockaddr *) &device, sizeof (device)) ;
  		if (sent_size<0){
			errcounter++;
		}
	
		//Check key socket	
		recv_size=recvfrom(recv_sock,recvbuf,1500,0,(struct sockaddr *) &device,&devsize);
		if(recv_size>0){
			gynhdr = (struct gyn_header*) recvbuf;	
			if(gynhdr->ether_type==0x88b6){
				if(gynhdr->dest==src && gynhdr->src==next_hop && (gynhdr->pkt_type==21 || gynhdr->pkt_type==22)){
					printf("Detected link key change. Using new key ");
					sleep(2);
					get_aes_key(next_hop,key_link);
					print_aes_key(key_link,16);
					//Now re encrypt header
					ciphertext_len_part_1 = encrypt((unsigned char *) dest_buffer, 15,key_link,iv,tmp);
					memcpy(cipher_header,tmp,12);
					memcpy(cipher_header+14,tmp+12,4);
					memcpy(packet,cipher_header,18);	
					
				}
				else if(gynhdr->dest==src && gynhdr->src==dest && (gynhdr->pkt_type==21 || gynhdr->pkt_type==22)){
					printf("Detecting node key change. Using new key ");
					sleep(2);
					get_aes_key(dest,key_node);
					print_aes_key(key_node,16);
					//Now re encrypt Second header		
					ciphertext_len_part_1 = encrypt((unsigned char *) &customhdr,sizeof(struct gyn_header),key_node,iv,tmp);
					memcpy(packet+18,tmp,ciphertext_len_part_1);
				}
			}
			
		}

		counter++;
		if(counter%100000==0){
			printf("Packets attempted: %d \n",counter);
			sleep(2);
		}		
	}
//	printf("Packets attempted: %d	Packets unsuccessful: %d \n",counter, errcounter);

	return 1;
}













	


