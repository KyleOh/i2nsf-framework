/*********************************************************************
 * ConfD Subscriber intro example
 * Implements a DHCP server adapter
 *
 * (C) 2005-2007 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>

#include <confd_lib.h>
#include <confd_cdb.h>

/* include generated file */
#include "ietf-i2nsf-capability.h"

/********************************************************************/

#define BUF_LEN 1000

int nsf_num = -2;

static int read_conf(struct sockaddr_in *addr)
{
    int i, j;
    int rsock;
	char nsf_name[BUFSIZ];
    struct in_addr src_ip;
	int capability_exist;
	char temp_capa[300];
	char temp[100];


    if ((rsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
        confd_fatal("Failed to open socket\n");

    if (cdb_connect(rsock, CDB_READ_SOCKET, (struct sockaddr*)addr,
                      sizeof (struct sockaddr_in)) < 0)
        return CONFD_ERR;
    if (cdb_start_session(rsock, CDB_RUNNING) != CONFD_OK)
        return CONFD_ERR;
    cdb_set_namespace(rsock, ietf_i2nsf_capability__ns);
	nsf_num++;
	printf("nsf_num: %d\n", nsf_num);
	if (nsf_num > -1) {
	cdb_pushd(rsock, "nsf/nsfs[%d]", nsf_num);

	//NSF Name
	cdb_get_str(rsock, &nsf_name[0], BUFSIZ, "nsf-name");
	printf("NSF Name: %s\n", nsf_name);
//	strncpy(nsf_name,"abc",sizeof("abc"));
	strncpy(temp_capa,nsf_name,sizeof(nsf_name));


	//NSF Address
	cdb_get_ipv4(rsock, &src_ip,"nsf-address/ipv4-address");
    printf("Src IP: %s\n", inet_ntoa(src_ip));
	strcpy(temp,inet_ntoa(src_ip));
	strncat(temp_capa, ",", sizeof(","));
	strncat(temp_capa, temp, sizeof(temp));

	//Time
	cdb_cd(rsock, "generic-nsf-capabilities/net-sec-capabilities/time");
	cdb_get_bool(rsock, &capability_exist,"time-inteval/absolute-time-inteval/start-time");
    printf("Start Time: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",start-time", sizeof("start-time"));


	cdb_get_bool(rsock, &capability_exist,"time-inteval/absolute-time-inteval/end-time");
    printf("End Time: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",end-time", sizeof("end-time"));


	//Condition
	cdb_cd(rsock, "../condition");
	cdb_get_bool(rsock, &capability_exist,"packet-security-condition/packet-security-ipv4-condition/pkt-sec-cond-ipv4-src");
    printf("IPv4 Src Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",pkt-sec-cond-ipv4-src", sizeof("pkt-sec-cond-ipv4-src"));


	cdb_get_bool(rsock, &capability_exist,"packet-security-condition/packet-security-ipv4-condition/pkt-sec-cond-ipv4-dest");
    printf("IPv4 Dest Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",pkt-sec-cond-ipv4-dest", sizeof("pkt-sec-cond-ipv4-dest"));


	cdb_get_bool(rsock, &capability_exist,"url-category-condition/pre-defined-category");
    printf("URL Pre Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",pre-defined-category", sizeof("pre-defined-category"));


	cdb_get_bool(rsock, &capability_exist,"url-category-condition/user-defined-category");
    printf("URL User Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",user-defined-category", sizeof("user-defined-category"));
	capability_exist = 0;


	cdb_get_bool(rsock, &capability_exist,"packet-payload-condition/pkt-payload-content");
    printf("Pkt Payload Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",pkt-payload-content", sizeof("pkt-payload-content"));
	capability_exist = 0;


	//Action
	cdb_cd(rsock, "../action/ingress-action/ingress-action-type");
	cdb_get_bool(rsock, &capability_exist,"pass");
    printf("Pass Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",pass", sizeof("pass"));
	capability_exist = 0;

	cdb_get_bool(rsock, &capability_exist,"drop");
    printf("Drop Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",drop", sizeof("drop"));
	capability_exist = 0;

	cdb_get_bool(rsock, &capability_exist,"reject");
    printf("Reject Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",reject", sizeof("reject"));
	capability_exist = 0;

	cdb_get_bool(rsock, &capability_exist,"alert");
    printf("Alert Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",alert", sizeof("alert"));
	capability_exist = 0;

	cdb_get_bool(rsock, &capability_exist,"mirror");
    printf("Mirror Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",mirror", sizeof("mirror"));
	capability_exist = 0;

	cdb_get_bool(rsock, &capability_exist,"log");
    printf("Log Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",log", sizeof("log"));
	capability_exist = 0;

	cdb_get_bool(rsock, &capability_exist,"syslog");
    printf("Mirror Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",syslog", sizeof("syslog"));
	capability_exist = 0;

	cdb_get_bool(rsock, &capability_exist,"session-log");
    printf("Mirror Capa: %d\n", capability_exist);
//	capability_exist = 1;
	if (capability_exist == 1)
		strncat(temp_capa, ",session-log", sizeof("session-log"));
	capability_exist = 0;

	printf("%s\n", temp_capa);

	///socket code////
	int client_fd,len;
	struct sockaddr_in client_addr;
	
	client_fd = socket(PF_INET, SOCK_STREAM, 0);

	client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(55552);

	if(connect(client_fd,(struct sockaddr *)&client_addr, sizeof(client_addr)) == -1)
	{
		printf("Can't connect\n");
		close(client_fd);
		return -1;
	}

	send(client_fd, (char *)temp_capa, sizeof(temp_capa), 0);
	close(client_fd);
	printf("Send: %s\n", temp_capa);
	}
    return cdb_close(rsock);
}

/********************************************************************/

int start_confd(void)
{
    struct sockaddr_in addr;
    int subsock;
    int status;
    int spoint;

    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONFD_PORT);

    confd_init("firewall", stderr, CONFD_TRACE);

    /*
     * Setup subscriptions
     */
    if ((subsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
        confd_fatal("Failed to open socket\n");

    if (cdb_connect(subsock, CDB_SUBSCRIPTION_SOCKET, (struct sockaddr*)&addr,
                      sizeof (struct sockaddr_in)) < 0)
        confd_fatal("Failed to cdb_connect() to confd \n");

    if ((status = cdb_subscribe(subsock, 3, ietf_i2nsf_capability__ns, &spoint, "/nsf"))
        != CONFD_OK) {
        fprintf(stderr, "Terminate: subscribe %d\n", status);
        exit(0);
    }
    if (cdb_subscribe_done(subsock) != CONFD_OK)
        confd_fatal("cdb_subscribe_done() failed");
    printf("Subscription point = %d\n", spoint);

    /*
     * Read initial config
     */
    if ((status = read_conf(&addr)) != CONFD_OK) {
        fprintf(stderr, "Terminate: read_conf %d\n", status);
        exit(0);
    }
    /* This is the place to HUP the daemon */

    while (1) {
        static int poll_fail_counter=0;
        struct pollfd set[1];

        set[0].fd = subsock;
        set[0].events = POLLIN;
        set[0].revents = 0;

        if (poll(&set[0], 1, -1) < 0) {
            perror("Poll failed:");
            if(++poll_fail_counter < 10)
                continue;
            fprintf(stderr, "Too many poll failures, terminating\n");
            exit(1);
        }

        poll_fail_counter = 0;
        if (set[0].revents & POLLIN) {
            int sub_points[1];
            int reslen;


            if ((status = cdb_read_subscription_socket(subsock,
                                                       &sub_points[0],
                                                       &reslen)) != CONFD_OK) {
                fprintf(stderr, "terminate sub_read: %d\n", status);
                exit(1);
            }
            if (reslen > 0) {
                if ((status = read_conf(&addr)) != CONFD_OK) {
                    fprintf(stderr, "Terminate: read_conf %d\n", status);
                    exit(1);
                }
            }

            fprintf(stderr, "Read new config, updating dhcpd config \n");
            /* this is the place to HUP the daemon */

            if ((status = cdb_sync_subscription_socket(subsock,
                                                       CDB_DONE_PRIORITY))
                != CONFD_OK) {
                fprintf(stderr, "failed to sync subscription: %d\n", status);
                exit(1);
            }
        }
    }
}

/********************************************************************/
