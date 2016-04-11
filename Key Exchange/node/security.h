/*This file contains definitions for functions related to encryption and decryption*
*                                                                                  *
************************************************************************************/
#include <openssl/rsa.h>
#include <openssl/pem.h> 
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include "print_packets.h"
#include <net/ethernet.h>
#include <unistd.h>
#include <sys/time.h>
#include "globals.h"

int generate_rsa_key_pair(int size);//This function generates and rsa key pair and writes them to files
int generate_aes128_key(unsigned char* key);//This function generates an aes key and, writes it to a file, and fills it into the array passed to it
int send_public_key(int sockfd,int index);//This function sends our public key to all 
int decrypt_with_private_key(RSA* privkey,unsigned char* ciphertext,unsigned char* plaintext, int len);
int encrypt_with_public_key(RSA* pubkey, unsigned char* plaintext, unsigned char* ciphertext, int len);
RSA* get_private_key();
RSA* get_public_key_from_array(unsigned char* key);//This gets a public key from a PEM formatted char array
void test_RSA_encryption();
void wait_for_key_reply(uint16_t src, int sock);
int setup_key_socket(int index);
void handle_symmetric_key(unsigned char* packet);
void writeToSessionFile(struct session_entry* sesh_entry);
int timeval_cmp(struct timeval* x, struct timeval* y);




