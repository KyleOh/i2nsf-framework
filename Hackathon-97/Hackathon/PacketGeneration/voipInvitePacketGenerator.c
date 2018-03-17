#include "udpPacketGenerator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../Interfaces/constants.h"

#define BUF_SIZE 256
#define MAX_PAYLOAD_SIZE 1024

#define RED "\x1B[31m"
#define RESET "\x1B[0m"

uint8_t* generateVoipInvitePacket(char *userName, char *fromPhoneNumber, char *toPhoneNumber, char *user_agent, char *srcIp) {
	uint8_t *data = (uint8_t *)malloc(MAX_PAYLOAD_SIZE);
	int ic = 0; // index counter
	char method[8] = "INVITE ";
	char requestUri[64] = "";
	strcat(requestUri, "sip:");
	strcat(requestUri, toPhoneNumber);
	strcat(requestUri, " ");
	char version[16] = "SIP/2.0\r\n";
	char via[128] = "";
	strcat(via, "Via: SIP/2.0/UDP ");
	strcat(via, srcIp);
	strcat(via, ":5060;branch=z9hG4bKnp104984053-44ce4a41");
	strcat(via, srcIp);
	strcat(via, ";rport\r\n");

	char from[128] = "";
	strcat(from, "From: \"");
	strcat(from, userName);
	strcat(from, "\" <sip:");
	strcat(from, fromPhoneNumber);
	strcat(from, ">;tag=6433ef9\r\n");

	char to[128] = "";
	strcat(to, "To: <sip:");
	strcat(to, toPhoneNumber);
	strcat(to, ">\r\n");

	char callId[64] = "";
	strcat(callId, "Call-ID: 105090259-446faf7a");
	strcat(callId, "@");
	strcat(callId, srcIp);
	strcat(callId, "\r\n");

	char cseq[32] = "CSeq: 1 INVITE\r\n";

	char userAgent[64] = "User-Agent: ";
	strcat(userAgent, user_agent);
	strcat(userAgent, " SIPPS IP Phone Version 2.0.51.16\r\n");

	char expire[16] = "Expires: 120\r\n";
	char accept[32] = "Accept: application/sdp\r\n";
	char contentType[32] = "Content-Type: application/sdp\r\n";
	char contentLength[32] = "Content-Length: 272\r\n";
	char contact[64] = "";
	strcat(contact, "Contact: <sip:");
	strcat(contact, fromPhoneNumber);
	strcat(contact, "@");
	strcat(contact, srcIp);
	strcat(contact, ">\r\n");
	char maxForward[32] = "Max-Forwards: 70\r\n";
	char allow[128] = "Allow: INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, INFO\r\n\r\n";

	memcpy(data, method, 7); ic += 7;// method
	memcpy(data + ic, requestUri, strlen(requestUri)); ic += strlen(requestUri); // request line
	memcpy(data + ic, version, 9); ic += 9; // version
	memcpy(data + ic, via, strlen(via)); ic += strlen(via); // via
	memcpy(data + ic, from, strlen(from)); ic += strlen(from);
	memcpy(data + ic, to, strlen(to)); ic += strlen(to);
	memcpy(data + ic, callId, strlen(callId)); ic += strlen(callId);
	memcpy(data + ic, cseq, strlen(cseq)); ic += strlen(cseq);
	memcpy(data + ic, userAgent, strlen(userAgent)); ic += strlen(userAgent);
	memcpy(data + ic, expire, strlen(expire)); ic += strlen(expire);
	memcpy(data + ic, accept, strlen(accept)); ic += strlen(accept);
	memcpy(data + ic, contentType, strlen(contentType)); ic += strlen(contentType);
	memcpy(data + ic, contentLength, strlen(contentLength)); ic += strlen(contentLength);
	memcpy(data + ic, contact, strlen(contact)); ic += strlen(contact);
	memcpy(data + ic, maxForward, strlen(maxForward)); ic += strlen(maxForward);
	memcpy(data + ic, allow, strlen(allow)); ic += strlen(allow);

	data[ic] = '\0';
	
		
	printf("\n[VoIP/VoLTE] Packetgenerator sended the packet for VoIP/VoLTE\n");
	printf("From: ");
	printf(RED "%s\n" RESET, fromPhoneNumber);
	printf("To: ");
	printf(RED "%s\n" RESET, toPhoneNumber);
	printf("User-Agent: ");
	printf(RED "%s\n" RESET, user_agent);
	//printf("\n\n%s\n", (char *)data); 


	return data;
}

// from udpPacketGenerator.h
// int generateUdpPacket (char* interface, char* srcIPv4Address, char* destIPv4Address, int srcPort, int destPort, char* contents)
int main(int argc, char *args[]) {
	if(argc != 2) {
		printf("usage: ./voipInvitePacketGenerator destIPAddress \n");
		return -1;
	}

	FILE *fp;
	int readn, split_buf_num = 0, index = 0;
	char buf[BUF_SIZE], src_ip[16], if_name[20] = {'\0'};
	char *dest_ip;
	char *split_buf[30];
	uint8_t *data;
	char* toPhoneNum;

	if(strcasecmp(args[1], "STAFF_1") == 0){
		dest_ip = STAFF_1;
		toPhoneNum = PHONE_OF_STAFF_1;
	}
	else if (strcasecmp(args[1], "STAFF_2") == 0){
		dest_ip = STAFF_2;
		toPhoneNum = PHONE_OF_STAFF_2;
	}
	else if (strcasecmp(args[1], "MANAGER") == 0){
		dest_ip = MANAGER;
		toPhoneNum = PHONE_OF_MANAGER;
	}
	else {
		dest_ip = PRESIDENT;
		toPhoneNum = PHONE_OF_PRESIDENT;
	}


	/* Ex - inet 192.168.30.132/24 brd 192.168.30.255 scope global eth0 */
	system("ip addr | grep \"eth0\" | grep \"inet\" | grep \"brd\" >> /tmp/temp.txt");
	fp = fopen("/tmp/temp.txt", "r");
	if(fp == NULL) {
		printf("File open failed \n");
		return -1;
	}



	memset(buf, 0x00, BUF_SIZE);
	readn = fread(buf, BUF_SIZE - 1, 1, fp);
	fclose(fp);
	system("rm /tmp/temp.txt");

	split_buf[split_buf_num] = strtok(buf, " ");
	while(split_buf[split_buf_num] != NULL) {
		split_buf_num++;
		split_buf[split_buf_num] = strtok(NULL, " ");
	}

	/* IP Address */
	char *endPoint = strchr(split_buf[1], '/');
	int endIndex = (int)(endPoint - split_buf[1]);
	strncpy(src_ip, split_buf[1], endIndex);
	src_ip[endIndex] = '\0';

	/* Interface Name */
	endPoint = strchr(split_buf[6], '\n');
	endIndex = (int)(endPoint - split_buf[6]);
	strncpy(if_name, split_buf[6], endIndex);
	if_name[endIndex] = '\0';


	//printf("src_ip: %s\n", src_ip);
	//printf("if_name: %s\n", if_name);


	// uint8_t* generateVoipInvitePacket(char *userName, char *fromPhoneNumber, char *toPhoneNumber, char *host, char *srcIp)
	data = generateVoipInvitePacket("yys", "11111@voip.black.com", toPhoneNum, "nero", src_ip);
	/* 5060 is used for sip port number in UDP/TCP */
	generateUdpPacket(if_name, src_ip, dest_ip, 5060, 5060, data);

	data = generateVoipInvitePacket("yys", "22222@voip.lol.com", toPhoneNum, "nero", src_ip);
	generateUdpPacket(if_name, src_ip, dest_ip, 5060, 5060, data);
	
	data = generateVoipInvitePacket("yys", "0930@voip.skku.com", toPhoneNum, "nero", src_ip);
	generateUdpPacket(if_name, src_ip, dest_ip, 5060, 5060, data);

	data = generateVoipInvitePacket("yys", "99999@voip.iot.com", toPhoneNum, "sipcli", src_ip);
	generateUdpPacket(if_name, src_ip, dest_ip, 5060, 5060, data);

	data = generateVoipInvitePacket("yys", "12345@voip.sec.com", toPhoneNum, "eyebeam", src_ip);
	generateUdpPacket(if_name, src_ip, dest_ip, 5060, 5060, data);

	data = generateVoipInvitePacket("yys", "555555@voip.imtl.com", toPhoneNum, "friendly-scanner", src_ip);
	generateUdpPacket(if_name, src_ip, dest_ip, 5060, 5060, data);

	free(data);
	return 0;
}
