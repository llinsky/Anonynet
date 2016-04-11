/***********************************************************************************
*  This file will define methods for working with aes encryption                   *
************************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include "globals.h"
#include "print_packets.h"

int get_aes_key(uint16_t dest,unsigned char* key);
