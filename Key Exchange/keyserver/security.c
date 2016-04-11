/***************************************
*  This file contains implementations  * 
*  for functions related to encryption *
****************************************/
#include "security.h"

int generate_rsa_key_pair(int size){
	RSA* rsa=NULL;
	BIGNUM* bn=NULL;
	BIO *bp_public=NULL;
	BIO *bp_private=NULL;
	unsigned long e=RSA_F4;
	bn=BN_new();
	int success = BN_set_word(bn,e); 
	if(success!=1){	
		printf("Issue with BN_set_word\n");
	}
	rsa=RSA_new();
	success = RSA_generate_key_ex(rsa,size,bn,NULL);
 	if(success!=1){
		printf("Issue with RSA generation\n");
	}	
	//Now save the key to a file
	bp_public= BIO_new_file("publickey.pem","w+");
	success=PEM_write_bio_RSAPublicKey(bp_public,rsa);
	if(success!=1){
		printf("Issue writing the public key to file\n");	
	}
	bp_private=BIO_new_file("privatekey.pem","w+");
	success=PEM_write_bio_RSAPrivateKey(bp_private,rsa,NULL,NULL,0,NULL,NULL);
	if(success!=1){
		printf("Issue writing the private key to file\n");
	}
	
	//Free pointers
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(rsa);
	BN_free(bn);
	return success;
}

int generate_aes128_key(unsigned char* key){
	memset(key,0,16);
	//Use RAND_bytes to generate a key	
	if(!RAND_bytes(key,16)){
		printf("Error generating random key\n");
		return -1;
	}
	//Now open a file and write the key to it, for backup for now
	FILE* fp;
	fp= fopen("aeskey.txt","w+");
	int bytes_written=fwrite(key,sizeof(char),16,fp);	
	if(bytes_written!=16){
		printf("Error writing to aes file\n");
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 1;
}

RSA* get_public_key_from_array(unsigned char* key){
	RSA* rsa=NULL;
	BIO* keybio;
	keybio=BIO_new_mem_buf(key,-1);
	rsa=PEM_read_bio_RSAPublicKey(keybio,&rsa,NULL,NULL);
	if(rsa==NULL){
		printf("\tError creating RSA public key\n");
	}
	BIO_free_all(keybio);
	return rsa;
}
int decrypt_with_private_key(RSA* privkey, unsigned char* ciphertext,unsigned char* plaintext, int len){
	int decrypt_len=RSA_private_decrypt(len,ciphertext,plaintext,privkey,RSA_PKCS1_PADDING);
	if(decrypt_len==-1){
		printf("Error decrypting with private key\n");
	}
	return decrypt_len;
}
int encrypt_with_public_key(RSA* pubkey,unsigned char* plaintext,unsigned char* ciphertext,int len){
	int encrypt_len=RSA_public_encrypt(len,plaintext,ciphertext,pubkey,RSA_PKCS1_PADDING);
	if(encrypt_len==-1){
		printf("Error encrypting with public key\n");
	}
	return encrypt_len;

}
RSA* get_private_key(){
	RSA* rsa=NULL;	
	FILE* bp=fopen("privatekey.pem","r");
	if(bp==NULL){
		printf("Error opening private key file\n");
	}
	rsa=PEM_read_RSAPrivateKey(bp,NULL,NULL,NULL);
	if(rsa==NULL){
		printf("Error reading private key from file\n");
	}
	fclose(bp);
	return rsa;
}

void wait_for_key_reply(uint16_t src,int index){
	int sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll sock_addr;
	socklen_t sockaddr_size=sizeof(sock_addr);
	sock_addr.sll_family=AF_PACKET;
	sock_addr.sll_protocol=htons(ETH_P_ALL);
	sock_addr.sll_ifindex=index;
	int bind_success=bind(sock,(const struct sockaddr*)&sock_addr,sizeof(struct sockaddr_ll));
	if(bind_success<0){
		perror ("Bind error ");
		return;
	}	
	
	//Set to promiscuous
	struct packet_mreq mr;
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex=index;
	mr.mr_type=PACKET_MR_PROMISC;
	if(setsockopt(sock,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr))<0){
		perror("Setsockopt(PROMISC) failed");
	}
	unsigned char recvbuf[2048];
	memset(recvbuf,'\0',2048);
	int recv_size,done=0;
	//open file to write tempkeys to
	while(!done){
		recv_size=recvfrom(sock,recvbuf,2048,0,(struct sockaddr*)&sock_addr,&sockaddr_size);
		if(recv_size>0&& sock_addr.sll_pkttype!=PACKET_OUTGOING){
			struct gyn_header* gyn=(struct gyn_header*)recvbuf;
			if(gyn->ether_type==PROTO_TYPE2 && gyn->pkt_type==PRIVATE_KEY_TYPE && gyn->src==src){
				printf("Received the symmetric key!\n");
				done=1;
				handle_symmetric_key(recvbuf);	
				unsigned char sendbuf[2048];
				memset(sendbuf,'\0',2048);
				struct gyn_header* send_hdr=(struct gyn_header*)sendbuf;
				send_hdr->ether_type=PROTO_TYPE2;
				send_hdr->dest=src;
				send_hdr->seq=0;
				send_hdr->pkt_size=0;
				send_hdr->pkt_type=KEY_ACK_TYPE;
				int sent=sendto(sock,sendbuf,sizeof(struct gyn_header)+send_hdr->pkt_size,0,(struct sockaddr*)&sock_addr,sizeof(struct sockaddr_ll));
				if(sent<0){
					perror("Error sending key ACK\n");
				}
			}
			else{
				printf("\tIncorrect ether_type or pkt_type: %X\n",gyn->ether_type);
			}
		}
	}	

}

void handle_symmetric_key(unsigned char* packet){
	struct gyn_header* gyn=(struct gyn_header*)packet;
	unsigned char enc_sym_key[129];
	unsigned char dec_sym_key[129];
	memset(enc_sym_key,'\0',129);
	memset(dec_sym_key,'\0',129);
	memcpy(enc_sym_key,packet+sizeof(struct gyn_header),16);
	printf("Encrypted symmetric key: %s\n",enc_sym_key);	
	RSA* privkey=NULL;
	get_private_key(privkey);	
	decrypt_with_private_key(privkey,enc_sym_key,dec_sym_key,gyn->pkt_size-sizeof(struct timeval));
	printf("Decrypted symmetric key: %s\n",dec_sym_key);
	
	return;
	
}
