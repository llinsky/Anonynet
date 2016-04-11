/***************************************
*  This file contains implementations  * 
*  for functions related to encryption *
****************************************/
#include "security.h"
#include "hashmap.h"

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

int send_public_key(){
	int bytes_written=0,bytes_read=0;
	unsigned char packet[1500];
	memset(packet,'\0',1500);
	struct timeval tv;
	//prepare sockaddr
	struct sockaddr_ll sockaddrll;
	sockaddrll.sll_family=AF_PACKET;
	sockaddrll.sll_protocol=htons(ETH_P_ALL);
	sockaddrll.sll_halen=6;
	sockaddrll.sll_addr[0]=0xFF;
	sockaddrll.sll_addr[1]=0xFF;
	sockaddrll.sll_addr[2]=0xFF;
	sockaddrll.sll_addr[3]=0xFF;
	sockaddrll.sll_addr[4]=0xFF;
	sockaddrll.sll_addr[5]=0xFF;
	
	//prepare gyn_header
	struct gyn_header gyn;
	gyn.dest=0;
	gyn.src=vars.my_addr;
	gyn.seq=0;
	gyn.pkt_type=PUBLIC_KEY_TYPE;
	gyn.ether_type=PROTO_TYPE2;
	//Read in the public key	
	FILE* fp=fopen("publickey.pem","r");
	if((bytes_read=fread(packet+sizeof(struct gyn_header),sizeof(unsigned char),sizeof(packet)-sizeof(struct gyn_header),fp))<0){
		perror("Error reading from public key file: ");
		return -1;
	}
	if(bytes_read==sizeof(packet)-sizeof(struct gyn_header)){
		printf("Uh-oh, it's likely that the file is too big for one packet\n");
	}
	fclose(fp);
	//Set packet size
	gyn.pkt_size=bytes_read+sizeof(struct timeval);
	//Iterate through routing table and send the file to each
	uint16_t i;
	int key_socket;
	struct route_entry *route;
	for(i=1;i<vars.my_addr;i++){
		
		if (hashmap_get(vars.routing_table, i, ((void**) &route)) == MAP_MISSING) 
		{
			printf("\nError: Missing entry in routing table during key transfer.\n");
			return -1;
		}
		
		gyn.dest= (uint16_t) route->address;
		printf("\tExchanging keys with node %hu...\n",gyn.dest);
		sockaddrll.sll_ifindex=route->send_index;
//		printf("\tUsing interface %d\n",sockaddrll.sll_ifindex);
		key_socket=setup_key_socket(route->send_index);
		//now copy gyn header to packet
		memset(packet,0,sizeof(struct gyn_header));
		memcpy(packet,&gyn,sizeof(struct gyn_header));
		//get timestamp
		gettimeofday(&tv,NULL);
		//append timestamp to packet after checking size
		if(sizeof(struct timeval)+sizeof(struct gyn_header)+bytes_read>1500){
			printf("Public key packet too large!");
			return -1;
		}
		memcpy(&packet[sizeof(struct gyn_header)+bytes_read],&tv,sizeof(struct timeval));
		//send packet on correct interface to address
		bytes_written=sendto(vars.send_sock_fd,packet,gyn.pkt_size+sizeof(struct gyn_header),0,(struct sockaddr*)&sockaddrll,sizeof(struct sockaddr_ll));
		if(bytes_written<0){
			perror("Error sending public key:");
		}
		else{
//			printf("\tSent %d bytes \n",bytes_written);
		}
		//Now wait for reply message
//		printf("\tWaiting for response...\n");
		wait_for_key_reply(gyn.dest,key_socket);
		close(key_socket);
	}		
	return bytes_written;

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

void test_RSA_encryption(){
	unsigned char message[129];
  	strncpy((char*)message,"Hello. This is Timothy.",sizeof(message));
	unsigned char ciphertext[129];
	unsigned char decrypted[129];
	memset(ciphertext,'\0',129);
	memset(decrypted,'\0',129);
	FILE* fp=fopen("publickey.pem","r");
	RSA* pubkey=NULL;
	RSA* privkey=NULL;
	
	//Get public key
	if((pubkey=PEM_read_RSAPublicKey(fp,&pubkey,NULL,NULL))==NULL){
		printf("Error reading public key from file\n");
		return;
	}
	fclose(fp);
	printf("Original message: %s\n",message);	
	int encrypt_len=encrypt_with_public_key(pubkey,message,ciphertext,23);
	printf("Encrypted message: %s\n",ciphertext);
	privkey=get_private_key();
	fp=fopen("privatekeyTEST.pem","w+");
		
	int success=PEM_write_RSAPrivateKey(fp,privkey,NULL,NULL,0,NULL,NULL);
	fclose(fp);
	if(success!=1){
		perror("Issue writing the private key to file: ");
	}
	decrypt_with_private_key(privkey,ciphertext,decrypted,encrypt_len);
	printf("Decrypted message: %s\n",decrypted);
	RSA_free(pubkey);
	RSA_free(privkey);
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
void wait_for_key_reply(uint16_t src,int sock){
	unsigned char recvbuf[2048];
	struct sockaddr_ll sock_addr;
	socklen_t sockaddr_size=sizeof(sock_addr);
	sock_addr.sll_family=AF_PACKET;
	sock_addr.sll_protocol=htons(ETH_P_ALL);
	memset(recvbuf,'\0',2048);
	int recv_size,done=0;
	//open file to write tempkeys to
	while(!done){
		recv_size=recvfrom(sock,recvbuf,2048,0,(struct sockaddr*)&sock_addr,&sockaddr_size);
		if(recv_size>0&& sock_addr.sll_pkttype!=PACKET_OUTGOING){
			struct gyn_header* gyn=(struct gyn_header*)recvbuf;
			if(gyn->ether_type==PROTO_TYPE2 && gyn->pkt_type==PRIVATE_KEY_TYPE && gyn->src==src){
				done=1;
				handle_symmetric_key(recvbuf);	
				unsigned char sendbuf[2048];
				memset(sendbuf,'\0',2048);
				struct gyn_header* send_hdr=(struct gyn_header*)sendbuf;
				send_hdr->ether_type=PROTO_TYPE2;
				send_hdr->dest=src;
				send_hdr->src=vars.my_addr;
				send_hdr->seq=0;
				send_hdr->pkt_size=0;
				send_hdr->pkt_type=KEY_ACK_TYPE;
				int sent=sendto(sock,sendbuf,sizeof(struct gyn_header)+send_hdr->pkt_size,0,(struct sockaddr*)&sock_addr,sizeof(struct sockaddr_ll));
				if(sent<0){
					perror("Error sending key ACK\n");
				}
			}
			else{
//				printf("\tIncorrect ether_type or pkt_type: %X\n",gyn->ether_type);
			}
		}
	}	

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

void handle_symmetric_key(unsigned char* packet){
	struct gyn_header* gyn=(struct gyn_header*)packet;
	unsigned char enc_sym_key[129];
	unsigned char dec_sym_key[129];
	memset(enc_sym_key,'\0',129);
	memset(dec_sym_key,'\0',129);
	memcpy(enc_sym_key,packet+sizeof(struct gyn_header),gyn->pkt_size-sizeof(struct timeval));
//	printf("\t Encrypted symmetric key: ");
//	print_aes_key(enc_sym_key,gyn->pkt_size-sizeof(struct timeval));
	RSA* privkey=NULL;
	privkey=get_private_key();	
	decrypt_with_private_key(privkey,enc_sym_key,dec_sym_key,gyn->pkt_size-sizeof(struct timeval));
//	printf("\tDecrypted symmetric key: ");
//	print_aes_key(dec_sym_key,16);
	//Create session entry and write to file	
	struct session_entry sesh_entry;
	sesh_entry.host_id=gyn->src;
	memcpy(sesh_entry.sym_key,dec_sym_key,16);
	memcpy(&sesh_entry.timestamp,packet+sizeof(struct gyn_header)+gyn->pkt_size-sizeof(struct timeval),sizeof(struct timeval));
	writeToSessionFile(&sesh_entry);
	return;
	
}


void writeToSessionFile(struct session_entry *sesh_entry)
{
	//writes session entry to file, rectifies any ties
	
	printf("\t\tWriting session key to file...\n");
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
		//		printf("\tAlready have an entry for host %hu...\n",sesh_entry->host_id);
				//got a match, check timestamps.
				if (timeval_cmp(&(sesh_entry->timestamp),&(file_entry->timestamp)) ==-1)
				{
					fclose(fp);
		//			printf("\tCurrent entry is newer, not going to overwrite\n");
					return; //keep entry in file
				}
				else if (timeval_cmp(&(sesh_entry->timestamp),&(file_entry->timestamp)) == 1)
				{
					foundDup = 1;
		//			printf("\tCurrent entry is older, going to overwrite it\n");
					break; //we will assume there weren't TWO duplicates, because then something is wrong
				}
				else
				{
					printf("\tTimestamps are the same. This shouldn't happen!!\n");
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
						printf("\nDuplicate error. Session already was in file with same timestamp and key\n");
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
	//	printf("\tAppending to session keys file\n");
		FILE *append_sesh_file;
		append_sesh_file = fopen("/tmp/sesh_keys", "a+");
		int bytes_written=fwrite(sesh_entry, sizeof(char),sizeof(struct session_entry), append_sesh_file);
		if(bytes_written<0){
			printf("Error writing to sesh_keys file");
		}
		else{
	//		printf("Wrote %d bytes\n",bytes_written);
		}
		fclose(append_sesh_file);
		return;
	}
	
	
	//now delete and replace with sesh entry, unless there was a 'better' existing version in the file
//	printf("\tReplacing session key...\n");	
	fp = fopen("/tmp/sesh_keys", "r+");
	if(fp==NULL){
		printf("Error opening session keys file to replace\n");
	}
	//fseek to line where we found duplicate to replace
	fseek(fp,line_index*sizeof(struct session_entry),SEEK_SET);
	fwrite(sesh_entry,sizeof(char),sizeof(struct session_entry),fp);
	fclose(fp);
	free(line);
	
//	printf("\tReplaced duplicate for host %d\n",sesh_entry->host_id);
	return;
}


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




