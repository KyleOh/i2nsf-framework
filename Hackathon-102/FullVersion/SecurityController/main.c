#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include "dlist.h"
#include "developer-secu-controller-interface.h"


int main(int argc, char *argv[]) {
    if(argc != 1) { 
        printf("Usage: ./developer \n");
        exit(-1);
    }

	start_confd();


    return 0;
}
