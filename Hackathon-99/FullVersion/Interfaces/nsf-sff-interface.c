#include "nsf-sff-interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>

#define ETHER_TYPE 0x0800 /* IP Protocol */

//#define ETH_FRAME_LEN 1518


void printUdpHeader(struct udphdr *udphdr) {
	printf("\n\n/********** UDP HEADER **********/\n");

	printf("udphdr.source = %d\n", ntohs(udphdr->source));
	printf("udphdr.dest = %d\n", ntohs(udphdr->dest));
	printf("udphdr.len = %d\n", ntohs(udphdr->len));

	printf("/***************************/\n\n");
}

void printTcpHeader(struct tcphdr *tcphdr) {
	printf("\n\n/********** TCP HEADER **********/\n");

	printf("tcphdr.source_port = %d\n", ntohs(tcphdr->th_sport));
	printf("tcphdr.dest_port = %d\n", ntohs(tcphdr->th_dport));
	printf("tcphdr.seq = %d\n", ntohs(tcphdr->th_seq));
	printf("tcphdr.ack = %d\n", ntohs(tcphdr->th_ack));
	printf("tcphdr.data_offset = %d\n", ntohs(tcphdr->th_off));
	printf("tcphdr.reserved = %d\n", ntohs(tcphdr->th_x2));
	printf("tcphdr.flags = %d\n", ntohs(tcphdr->th_flags));
	printf("tcphdr.window = %d\n", ntohs(tcphdr->th_win));
	printf("tcphdr.check_sum = %d\n", ntohs(tcphdr->th_sum));
	printf("tcphdr.urgent_pointer = %d\n", ntohs(tcphdr->th_urp));

	printf("/***************************/\n\n");
}

void printIPHeader(struct iphdr *iph) {

    printf("\n\n/**********IPHEADER**********/\n");
    printf("iphdr.ihl = %d\n", iph->ihl);
    printf("iphdr.version = %d\n", iph->version);
    printf("iphdr.tos = %d\n", iph->tos);
    printf("iphdr.tot_len = %d\n", htons(iph->tot_len));
    printf("iphdr.frag_off = %d\n", iph->frag_off);
    printf("iphdr.ttl = %d\n", iph->ttl);
    printf("iphdr.protocol = %d\n", iph->protocol);
    printf("Source IP Address: %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
    printf("Destination IP Address: %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));

    printf("/***************************/\n\n");
}

void printMacAddress(struct ether_header * eh) {
    printf("\n\n/**********MAC ADDRESS**********/\n");
    printf("Destination MAC: %x:%x:%x:%x:%x:%x\n",
                                eh->ether_shost[0],
                                eh->ether_shost[1],
                                eh->ether_shost[2],
                                eh->ether_shost[3],
                                eh->ether_shost[4],
                                eh->ether_shost[5]);

    printf("Destination MAC: %x:%x:%x:%x:%x:%x\n",
                                eh->ether_dhost[0],
                                eh->ether_dhost[1],
                                eh->ether_dhost[2],
                                eh->ether_dhost[3],
                                eh->ether_dhost[4],
                                eh->ether_dhost[5]);
    printf("/***************************/\n\n");
}

/* The destBuffer should bigger than (2 + metadataNum + dataLen) * sizeof(uint8_t). */
void attach_inspection_result(uint8_t *destBuffer, uint8_t actionCode, uint8_t metadataNum, uint8_t *metadataCodes) {
    memcpy(destBuffer, &actionCode, sizeof(uint8_t));
    memcpy((destBuffer + sizeof(uint8_t)), &metadataNum, sizeof(uint8_t));
    memcpy((destBuffer + sizeof(uint8_t) * 2), metadataCodes, sizeof(uint8_t) * metadataNum);
}


void attach_outter_encapsulation(uint8_t *destBuffer, char *srcIP, char *destIP, int whichProtocol, int packetLen) {
    struct iphdr iphdr;     /* IP Header */

    iphdr.ihl = 5;
    iphdr.version = 4;
    iphdr.tos = 0;
    iphdr.tot_len = htons(packetLen);
    iphdr.id = htons(rand() % 65535);
    iphdr.frag_off = 0;
    iphdr.ttl = 64;
    iphdr.protocol = whichProtocol;
    iphdr.saddr = inet_addr(srcIP);
    iphdr.daddr = inet_addr(destIP);

    memcpy(destBuffer, &iphdr, sizeof(struct iphdr));
}

void sendPacket(uint8_t *packet) {
    struct iphdr *iphdr = (struct iphdr *)packet;

    int sockfd = socket(PF_INET, SOCK_RAW, iphdr->protocol);
    int turn_on = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &turn_on, sizeof(turn_on)) < 0) {
        printf("setsockopt() error\n");
        return;
    }

    struct sockaddr_in din;
    din.sin_family = AF_INET;
    din.sin_port = 0;
    din.sin_addr.s_addr = iphdr->daddr; //inet_addr();

    if(sendto(sockfd, packet, htons(iphdr->tot_len), 0,
            (struct sockaddr*) &din, sizeof(din)) < 0) {
        printf("sendto() error: %s\n", strerror(errno));
        return;
    }

}

bool start_listening(char *ifName, PacketProcessFunction processFunction, int mode) {
    printf("ifname: %s\n", ifName);
    fflush(stdout);
   
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE));
    if(sockfd == -1) {
        printf("socket() error\n");
        fflush(stdout);
        return false;
    }

    char buffer[ETH_FRAME_LEN] = {0};
    char sender[INET6_ADDRSTRLEN];
    int receivedBytes = 0;
    int sockopt;

    struct ether_header *eh = (struct ether_header *) buffer;
    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ether_header));
	struct tcphdr *tcp_header = (struct tcphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
	char *contents = (buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct ifreq ifopts;
    struct sockaddr_storage sender_addr;

    /* promisicuous mode */
    strncpy(ifopts.ifr_name, ifName, strlen(ifName) + 1);
    ioctl(sockfd, SIOCGIFFLAGS, &ifopts);


    //ifopts.ifr_flags |= IFF_PROMISC;
    //ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

    /* Allow the socket to be reused - incase connection is closed prematurely */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    


    /* Bind to device */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, strlen(ifName)) == -1)	{
        perror("SO_BINDTODEVICE");
        close(sockfd);
        exit(EXIT_FAILURE);
    }



    int packetCounter = 0;
    while(true) {
        receivedBytes = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        if(receivedBytes == -1) {
            printf("recvfrom() error\n");
            return false;
        }
	
        buffer[receivedBytes] = '\0';


//		struct iphdr *original_iphdr = (struct iphdr *)(iph + sizeof(struct iphdr) + );

      /*  if(iph->protocol != TUNNELING_PROTOCOL 
				&& iph->protocol != SENDER_PROTOCOL
				&& iph->protocol != UDP_PROTOCOL
				&& iph->protocol != ICMP_PROTOCOL
				&& iph->protocol != TCP_PROTOCOL
				&& iph->protocol != IGMP_PROTOCOL) continue;*/

		if(mode == FIREWALL_MODE 
				&& (unsigned long)(iph->daddr) != (unsigned long)(inet_addr(FIREWALL_IP))) continue;
		else if(mode == DPI_MODE 
				&& (unsigned long)(iph->daddr) != (unsigned long)(inet_addr(DPI_IP))) continue;
		else if((unsigned long)(iph->saddr) == (unsigned long)(inet_addr(LOOP_BACK)) 
				&& (unsigned long)(iph->daddr) == (unsigned long)(inet_addr(LOOP_BACK))) continue; 


        printf("------------------------Packet: %d-----------------------------\n", packetCounter++);
		printf("\nProtocol Num:%d\n",iph->protocol);
		printf("ETH_FRAME_LEN: %d\n",ETH_FRAME_LEN);
        printf("Received Bytes: %d\n", receivedBytes);
		printf("IP header size: %d\n", sizeof(struct iphdr));
		printf("Ether header size: %d\n", sizeof(struct ether_header));
		printf("TCP header size: %d\n", sizeof(struct tcphdr));
		printf("contents: %s\n",contents);

		printIPHeader(iph);
		printTcpHeader(tcp_header);
        //printMacAddress(eh);
        //printIPHeader(iph);
        
        /* The processing function which is passed from caller */
        (*processFunction)((uint8_t *)(iph), receivedBytes - sizeof(struct ether_header), iph->protocol);

        fflush(stdout);
    }
    return true;
}



