#include "aes.h"



int get_aes_key(uint16_t dest,unsigned char* key){
	FILE* fp=fopen("/tmp/sesh_keys","r");
	struct session_entry key_entry;
	if(fp==NULL){
		printf("\tError opening session keys file. Unable to retrieve key.\n");
		return -1;
	}	
	while(!feof(fp)){
		fread(&key_entry,sizeof(struct session_entry),1,fp);
		if(key_entry.host_id==dest){
			//Copy into key array
			memcpy(key,key_entry.sym_key,16);
			return 1;
		}
		
	}	
	//Not able to find key
	printf("\tUnable to retrieve specified key\n");
	return -1;


}


