#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include "nsf-secu-controller-interface.h"
#include "../../Interfaces/nsf-sff-interface.h"
#include "../../Interfaces/mysql-interface.h"
#include "../../Interfaces/constants.h"

int ipHeaderLen;
int getCurrentTime() {
}

void processUdpProtocol(uint8_t *data, int dataLen, struct iphdr *ipheader) {
	struct udphdr *udpheader;

	//TODO
	

//    free(packet);
}

void processPacket(uint8_t *data, int dataLen, int protocol) {
    if(protocol != TUNNELING_PROTOCOL) return;

    ipHeaderLen = sizeof(struct iphdr);
    struct iphdr *ipheader = (struct iphdr *) (data + ipHeaderLen); /* After outter IP header */
   
	/* Print Ip Header Info*/
	printIPHeader(ipheader);

	if (ipheader->protocol == SENDER_PROTOCOL) {
		printf("SENDER PROTOCOL\n");
	} else if(ipheader->protocol == UDP_PROTOCOL) {
		processUdpProtocol(data, dataLen, ipheader);
	}
}


void *nsf_sff_interface(void *arg) {
    char *interfaceName = (char *) arg;
    start_listening(interfaceName, &processPacket, DPI_MODE);
    return NULL;
}


int main(int argc, char *argv[]) {
    if(argc < 2) { 
        printf("Usage: ./dpi [interface name] \n");
        exit(-1);
    }

    pthread_t nsf_sff_interface_thread;
    int thread_id;

    if(MysqlInitialize()) {
        thread_id = pthread_create(&nsf_sff_interface_thread, NULL, nsf_sff_interface, (void *)argv[1]);
        if(thread_id < 0) {
            printf("thread create error \n");
            exit(-1);
        }

        start_confd();
    } else {
        fprintf(stderr, "\nMysqlInitialize() Failed\n");
    }


    return 0;
}
