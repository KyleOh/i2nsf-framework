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
#include "nsf-facing-interface.h"

/********************************************************************/


static void do_rule(int rsock, FILE *fp)
{
//   struct in_addr *ip_list;
   struct confd_time time;
   char temp_rule[300];
   char temp_itoa[300];
   int i;
   unsigned int rule_id;
   char rule_name[BUFSIZ];
   char rule_content[BUFSIZ];
   confd_value_t *src_ip_list;
   int src_ip_num;
   int action;
   char *str_action;

	cdb_get_u_int32(rsock, &rule_id,"rule-id");
	printf("rule-id: %d\n", rule_id);
	cdb_get_str(rsock, &rule_name[0], BUFSIZ, "rule-name");
	printf("rule-name: %s\n",rule_name);
	cdb_cd(rsock, "condition/packet-security-condition/packet-security-ipv4-condition");

	cdb_get_list(rsock, &src_ip_list, &src_ip_num, "pkt-sec-cond-ipv4-src");
	printf("Src Pkt Num: %d\n", src_ip_num);
    for (i=0; i<src_ip_num; i++) {
	    printf("Src IP: %s\n", inet_ntoa(CONFD_GET_IPV4(&src_ip_list[i])));
    }
/*	cdb_get_list(rsock, &dest_ip_list, &dest_ip_num, "pkt-sec-cond-ipv4-dest");
	printf("Src Pkt Num: %d\n", dest_ip_num);
    for (i=0; i<dest_ip_num; i++) {
	    printf("Dest IP: %s\n", inet_ntoa(CONFD_GET_IPV4(&dest_ip_list[i])));
    }*/

	cdb_cd(rsock, "../../packet-payload-security-condition");

	cdb_get_str(rsock, &rule_content[0], BUFSIZ, "pkt-payload-content");
	printf("Web Content: %s\n",rule_content);


	cdb_cd(rsock, "../generic-context-condition/schedule");
	//cdb_get_time(rsock, &time, "start-time");
	//printf("Start TIme: %s\n", time);
	//cdb_get_time(rsock, &time, "end-time");
	//printf("End Time: %s\n", time);

	cdb_cd(rsock, "../../../action/");
	cdb_get_enum_value(rsock, &action, "ingress-action-type");
	switch(action) {
		case nsf_facing_interface_pass:
			str_action = "pass";
			printf("Action : pass\n");
			break;
		case nsf_facing_interface_drop:
			str_action = "drop";
			printf("Action : drop\n");
			break;
		case nsf_facing_interface_reject:
			str_action = "reject";
			printf("Action : reject\n");
			break;
		case nsf_facing_interface_alert:
			str_action = "alert";
			printf("Action : alert\n");
			break;
		case nsf_facing_interface_mirror:
			str_action = "mirror";
			printf("Action : mirror\n");
			break;
	}


	//////////////////////////////////////////////
	//
	sprintf(temp_rule, "%s ip [",str_action);
	for(i = 0; i < (src_ip_num -1); i++) {
		strncat(temp_rule, inet_ntoa(CONFD_GET_IPV4(&src_ip_list[i])), sizeof(temp_rule)); 
		strncat(temp_rule, ",", sizeof(temp_rule));
	}
	strncat(temp_rule, inet_ntoa(CONFD_GET_IPV4(&src_ip_list[i])), sizeof(temp_rule));

	strncat(temp_rule, "] any -> any", sizeof(temp_rule));



/*	for(i = 0; i < (dest_ip_num -1); i++) {
		strncat(temp_rule, inet_ntoa(CONFD_GET_IPV4(&dest_ip_list[i])), sizeof(temp_rule)); 
		strncat(temp_rule, ",", sizeof(temp_rule));
	}
	strncat(temp_rule, inet_ntoa(CONFD_GET_IPV4(&dest_ip_list[i])), sizeof(temp_rule));
	printf("Dest IP: %s\n", inet_ntoa(CONFD_GET_IPV4(&dest_ip_list[i])));*/


	strncat(temp_rule, " any (msg:\"Website Reject\"; content:\"", sizeof(temp_rule));
	strncat(temp_rule, rule_content, sizeof(temp_rule));
	strncat(temp_rule, "\"; nocase; sid:", sizeof(temp_rule));
	sprintf(temp_itoa, "%d", rule_id);
	strncat(temp_rule, temp_itoa, sizeof(temp_rule));
	strncat(temp_rule, "; rev:1;)\n", sizeof(temp_rule));

	fputs(temp_rule,fp);


}

static int read_conf(struct sockaddr_in *addr)
{
    FILE *fp, *fp_temp, *fp_suricata_yaml;
	int policy_num, rule_num;
    int i, j;
    int rsock;
	char temp_policy_name[100];
	char temp_policy_file_location[100];
	char temp_yaml_content[100];
	char temp_cp[100];
	char policy_name[BUFSIZ];
	int temp_fp_location;


    if ((rsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
        confd_fatal("Failed to open socket\n");

    if (cdb_connect(rsock, CDB_READ_SOCKET, (struct sockaddr*)addr,
                      sizeof (struct sockaddr_in)) < 0)
        return CONFD_ERR;
    if (cdb_start_session(rsock, CDB_RUNNING) != CONFD_OK)
        return CONFD_ERR;
    cdb_set_namespace(rsock, nsf_facing_interface__ns);

	
	system("cp ~/suricata-3.2.1/suricata_web.yaml /etc/suricata/suricata_web.yaml");

	fp_temp = fopen("/etc/suricata/suricata.yaml.temp","w+"); 
	fp_suricata_yaml = fopen("/etc/suricata/suricata_web.yaml","r+");

	while(!feof(fp_suricata_yaml)) {
		fgets(temp_yaml_content, sizeof(temp_yaml_content), fp_suricata_yaml);
		if(strstr(temp_yaml_content, "rule-files:") != NULL) {
			printf("Succes\n");
			temp_fp_location = ftell(fp_suricata_yaml);

			while(!feof(fp_suricata_yaml)) {
				fgets(temp_yaml_content, sizeof(temp_yaml_content), fp_suricata_yaml);
				fputs(temp_yaml_content, fp_temp);
			}
		}
	}

	fseek(fp_suricata_yaml, temp_fp_location, SEEK_SET);
	fseek(fp_temp, 0, SEEK_SET);


	policy_num = cdb_num_instances(rsock, "cfg-network-security-control/policy");
	printf("Policy Num: %d\n", policy_num);
	for(i = 0; i < policy_num; i++) {
		cdb_pushd(rsock, "cfg-network-security-control/policy[%d]", i);
		cdb_get_str(rsock, &policy_name[0], BUFSIZ, "policy-name");
		strncpy(temp_policy_name," - ", sizeof(temp_policy_name));
		strncat(temp_policy_name, policy_name, sizeof(temp_policy_name));
		strncat(temp_policy_name,".rules\n", sizeof(temp_policy_name));
		fputs(temp_policy_name, fp_suricata_yaml);


		strncpy(temp_policy_file_location,"/etc/suricata/rules/", sizeof(temp_policy_file_location));
		strncat(temp_policy_file_location, policy_name, sizeof(temp_policy_file_location));
		strncat(temp_policy_file_location,".rules\n", sizeof(temp_policy_file_location));		
		printf("policy-name: %s\n",temp_policy_file_location);



	    if ((fp = fopen("test.tmp", "w")) == NULL) {
		    cdb_close(rsock);
			return CONFD_ERR;
	    }


		rule_num = cdb_num_instances(rsock, "rules");
		printf("Rule Num: %d\n", rule_num);

		for (j = 0; j < rule_num; j++) {
			cdb_pushd(rsock, "rules[%d]", j);
			do_rule(rsock, fp);
			cdb_popd(rsock);
		}
		cdb_popd(rsock);


	    fclose(fp);

		strncpy(temp_cp, "sudo cp test.tmp ", sizeof(temp_cp));
		strncat(temp_cp, temp_policy_file_location, sizeof(temp_cp));
		system(temp_cp);
	}

	while(!feof(fp_temp)) {
		fgets(temp_yaml_content, sizeof(temp_yaml_content), fp_temp);
		fputs(temp_yaml_content, fp_suricata_yaml);
	}

	fclose(fp_suricata_yaml);
	fclose(fp_temp);

	system("sudo /usr/bin/suricatasc -c reload-rules /var/run/suricata/web.socket");

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

    if ((status = cdb_subscribe(subsock, 3, nsf_facing_interface__ns, &spoint, "/cfg-network-security-control"))
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
