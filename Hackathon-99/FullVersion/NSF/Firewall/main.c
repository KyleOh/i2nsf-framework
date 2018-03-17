#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include "nsf-facing-interface.h"
#include "../../Interfaces/nsf-sff-interface.h"
#include "../../Interfaces/mysql-interface.h"
#include "../../Interfaces/constants.h"


int main(int argc, char *argv[]) {
    if(argc != 1) { 
        printf("Usage: ./firewall \n");
        exit(-1);
    }

	start_confd();


    return 0;
}
