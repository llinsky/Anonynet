#include "header.h"
#include "aes.h"
#include <stdio.h>
#include "print_packets.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <net/if.h>




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


int main(int argc, char *argv[])
{


	struct sockaddr_ll device;
  	unsigned char tmp[16];


	//get the file name and prepare memory space
	if(argc<5){
		printf("Usage: ./receiver <interface> <my address> <src address> <prev hop> \n");
		exit(1);
	}
	char* interface= argv[1];
	uint16_t dest = (uint16_t) atoi(argv[2]);
	uint16_t src = (uint16_t) atoi(argv[3]);
	uint16_t prev_hop = (uint16_t) atoi(argv[4]);
	
	unsigned char link_key[16];	
	unsigned char node_key[16];
	get_aes_key(src,node_key);
	get_aes_key(prev_hop,link_key);


	printf("Using link key ");
	print_aes_key(link_key,16);
	printf("Using node key ");
	print_aes_key(node_key,16);
	

  // this device is for sending, not receiving
	bzero(&device,sizeof(device));
    
  	if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
       		perror ("if_nametoindex() failed to obtain interface index ");
       		exit (EXIT_FAILURE);
   	 }
	

	  //Fill out sockaddr_ll device.
	device.sll_family = AF_PACKET;
		
	device.sll_addr[0]  = 0x22;		
	device.sll_addr[1]  = 0x22;		
	device.sll_addr[2]  = 0x22;
	device.sll_addr[3]  = 0x22;
	device.sll_addr[4]  = 0x22;
	device.sll_addr[5]  = 0x22;
		
	device.sll_halen = ETHER_ADDR_LEN;
	device.sll_protocol=htons(ETH_P_ALL);




  //Create a raw socket
	int sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  
	if(sock_fd == -1){
    	//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

	//bind to specified device
	if(bind(sock_fd,(struct sockaddr*) &device,sizeof(device))<0){
		printf("Bind failed\n");
	}
	//Set to promiscuous mode

	struct packet_mreq mr;
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex=device.sll_ifindex;
	mr.mr_type=PACKET_MR_PROMISC;
	if(setsockopt(sock_fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr))<0){
		perror("Setsockopt(PROMISC) failed");
	}
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);	

	unsigned short ether_type=0x88B5;
	int packet_read_size = 0;
	int numpackets = 0;
  	unsigned char cipher_packet[2000];
	unsigned char plain_packet[2000];
	socklen_t dev_size = sizeof(device);
	lookup_header_t *cipher_header;  
	struct gyn_header* gynhdr=NULL;
	while(1){

    
		packet_read_size = recvfrom(sock_fd,cipher_packet,2000,0,(struct sockaddr *) &device, &dev_size);
		if (packet_read_size < 0){ 
			printf("Recv error\n");	
		}
		cipher_header = (lookup_header_t *) cipher_packet;	
		gynhdr = (struct gyn_header *) cipher_packet;
		if(cipher_header->ether_type==ether_type){	
			
			numpackets++;
			if(numpackets%1000000 == 0 && numpackets!=0){
				decrypt(cipher_packet+18+32,packet_read_size-18-32,node_key,NULL,plain_packet);
				printf("Packets received: %d \n",numpackets);
				printf("Most recent packet received: \n");	
				printf("\t Encrypted: ");
				print_aes_key(cipher_packet+18+32,packet_read_size-18-32);
				printf("\t Decrypted: %s\n",plain_packet);
				memset(plain_packet,'\0',2000);	
				
			}	
		}		
		//See if key exchange packet for me, in that case update key
		else if(cipher_header->ether_type==0x88b6 && gynhdr->dest==dest){
			if(gynhdr->src==src && (gynhdr->pkt_type==22 || gynhdr->pkt_type==21)){
				sleep(3);
				printf("Detected end node key change. Using new key: ");
				get_aes_key(src,node_key);
				print_aes_key(node_key,16);

			}			
			else if(gynhdr->src==prev_hop && (gynhdr->pkt_type==21 || gynhdr->pkt_type==22)){
				sleep(3);	
				printf("Detected link key change. Using new key: ");
				get_aes_key(prev_hop,link_key);
				print_aes_key(link_key,16);
			}

		}

    
    
	}
  
}
