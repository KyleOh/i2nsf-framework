/*********************************************************************
 * ConfD Subscriber intro example
 * Implements a configuration data provider
 *
 * (C) 2005-2007 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/
#include "nsf-secu-controller-interface.h"
#include "../../Interfaces/mysql-interface.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <confd_lib.h>
#include <confd_dp.h>
#include "hst.h"

#define bool short
#define true 1
#define false 0

#define PASS 0
#define DROP 1
#define REJECT 2
#define ALERT 3
#define MIRROR 4
#define ADVANCED 5
#define REDIRECTION 6

#define INVOKE_SIGNALING 10
#define TUNNEL_ENCAPSULATION 11
#define FORWARDING 12

#define ANTIVIRUS 20
#define IPS 21
#define IDS 22
#define URL_FILTERING 23
#define DATA_FILTERING 24
#define MAIL_FILTERING 25
#define FILE_BLOCKING 26
#define FILE_ISOLATE 27
#define PKT_CAPTURE 28
#define APPLICATION_CONTROL 29
#define VOIP_VOLTE 30

#define SYN_FLOOD_ATTACK 40
#define UDP_FLOOD_ATTACK 41
#define ICMP_FLOOD_ATTACK 42
#define IP_FRAG_FLOOD_ATTACK 43
#define IPV6_RELATED_ATTACK 44

#define HTTP_FLOOD_ATTACK 50
#define HTTPS_FLOOD_ATTACK 51
#define DNS_FLOOD_ATTACK 52
#define DNS_AMP_FLOOD_ATTACK 53
#define SSL_DDOS_ATTACK 54

#define IP_SWEEP_ATTACK 60
#define PORT_SCANNING_ATTACK 61
#define PING_OF_DEATH_ATTACK 62
#define TEARDROP_ATTACK 63
#define OVERSIZED_ICMP_ATTACK 64
#define TRACERT_ATTACK 65

/********************************************************************/

struct policy {
	//container policy
	char *policy_name;
	char *policy_id;

	//list rule
	char *rule_name;
	int rule_id;
	char *rule_msg;
	int rule_rev;
	int rule_gid;
	char *rule_class_type;
	char *rule_reference;
	int rule_priority;

	//container event begin
	//member of user-security-event
	int usr_sec_event_id;
	char *usr_sec_event_content;
	int usr_sec_event_format;
	int usr_sec_event_type;
	
	//member of device-security-event
	int dev_sec_event_id;
	char *dev_sec_event_content;
	int dev_sec_event_format;
	int dev_sec_event_type;
	int dev_sec_event_type_severity;
	
	//member of system-security-event
	int sys_sec_event_id;
	char *sys_sec_event_content;
	int sys_sec_event_format;
	int sys_sec_event_type;

	//member of time-security-event
	int time_sec_event_id;
	int time_sec_event_period_begin;
	int time_sec_event_period_end;
	char *time_sec_event_time_zone;
	//container event end

	//container condition begin
	//container packet-security-condition begin
	//member of packet-security-mac-condition
	int pkt_sec_cond_mac_dest[50];
	int mac_dest_num;
	int pkt_sec_cond_mac_src[50];
	int mac_src_num;
	char *pkt_sec_cond_mac_8021q[50];
	int mac_8021q_num;
	char *pkt_sec_cond_mac_ether_type[50];
	int mac_ether_type_num;
	char *pkt_sec_cond_mac_tci[50];
	int mac_tci_num;

	//member of packet-security-ipv4-condition
	int pkt_sec_cond_ipv4_header_length[50];
	int ipv4_header_length_num;	
	int pkt_sec_cond_ipv4_tos[50];
	int ipv4_tos_num;	
	int pkt_sec_cond_ipv4_total_length[50];
	int ipv4_total_length_num;	
	int pkt_sec_cond_ipv4_id[50];
	int ipv4_id_num;
	int pkt_sec_cond_ipv4_fragment[50];
	int ipv4_fragment_num;
	int pkt_sec_cond_ipv4_fragment_offset[50];
	int ipv4_fragment_offset_num;
	int pkt_sec_cond_ipv4_ttl[50];
	int ipv4_ttl_num;
	char *pkt_sec_cond_ipv4_protocol[50];
	int ipv4_protocol_num;	
	struct in_addr ipv4_src_list[50];
	int ipv4_src_num;
	struct in_addr ipv4_dest_list[50];
	int ipv4_dest_num;
	char *pkt_sec_cond_ipv4_ipopts;
	bool pkt_sec_cond_ipv4_sameip;
	char *pkt_sec_cond_ipv4_geoip[50];
	int ipv4_geoip_num;

	//member of packet-security-ipv6-condition
	char *pkt_sec_cond_ipv6_dscp[50];
	int ipv6_dscp_num;
	char *pkt_sec_cond_ipv6_ecn[50];
	int ipv6_ecn_num;
	int pkt_sec_cond_ipv6_traffic_class[50];
	int ipv6_traffic_class_num;
	int pkt_sec_cond_ipv6_flow_label[50];
	int ipv6_flow_label_num;
	int pkt_sec_cond_ipv6_payload_length[50];
	int ipv6_payload_length_num;
	int pkt_sec_cond_ipv6_next_header[50];
	int ipv6_next_header_num;
	int pkt_sec_cond_ipv6_hop_limit[50];
	int ipv6_hop_limit_num;
	struct in6_addr ipv6_src_list[50];
	int ipv6_src_num;
	struct in6_addr ipv6_dest_list[50];
	int ipv6_dest_num;

	//memberer of packet-security-tcp-condition
	int pkt_sec_cond_tcp_seq_num[50];
	int tcp_seq_num;
	int pkt_sec_cond_tcp_ack_num[50];
	int tcp_ack_num;
	int pkt_sec_cond_tcp_window_size[50];
	int tcp_window_size_num;
	int pkt_sec_cond_tcp_flags[50];
	int tcp_flags_num;

	//member of packet-security-udp-condition
	char *pkt_sec_cond_udp_length[50];
	int udp_length_num;
	
	//member of packet-security-icmp-condition
	int pkt_sec_cond_icmp_type[50];
	int icmp_type_num;
	int pkt_sec_cond_icmp_code[50];
	int icmp_code_num;
	int pkt_sec_cond_icmp_seg_num[50];
	int icmp_seg_num;
	//container packet-security-condition end
	
	//member of packet-payload-security-condition
	int pkt_payload_id;
	char *pkt_payload_content;
	bool pkt_payload_nocase;
	int pkt_payload_depth;
	int pkt_payload_offset;
	int pkt_payload_distance;
	int pkt_payload_within;
	int pkt_payload_isdataat;
	int pkt_payload_dsize;
	char *pkt_payload_replace;
	char *pkt_payload_pcre;
	int pkt_payload_rpc_app_num;
	int pkt_payload_rpc_version_num;
	int pkt_payload_rpc_procedure_num;
	//target-security-condition begin
	int target_sec_cond_id;
	//container service-sec-context-cond begin
	char *service_sec_context_cond_name;
	int service_sec_context_cond_id;
	//container protocol begin
	bool service_sec_context_cond_protocol_tcp;
	bool service_sec_context_cond_protocol_udp;
	bool service_sec_context_cond_protocol_icmp;
	bool service_sec_context_cond_protocol_icmpv6;
	bool service_sec_context_cond_protocol_ip;
	//container protocol end
	int service_sec_context_cond_src_port;
	int service_sec_context_cond_dest_port;
	//container service-sec-context-cond end

	//container application-sec-context-cond begin
	char *app_sec_context_cond_name;
	int app_sec_context_cond_id;
	
	//container category begin
	bool business_system;
	bool entertainment;
	bool interest;
	bool network;
	bool general;
	//container category end
	
	//container subcategory begin
	bool finance;
	bool email;
	bool game;
	bool media_sharing;
	bool social_network;
	bool web_posting;
	//container subcategory end

	//container data-transmission-model begin
	bool client_server;
	bool browser_based;
	bool networking;
	bool peer_to_peer;
	bool unassigned;
	//container data-transmission-model end

	//risk-level begin
	bool expolitable;
	bool productivity_loss;
	bool evasive;
	bool data_loss;
	bool malware_vehicle;
	bool bandwidth_consuming;
	bool tunneling;
	//risk-level end
	//container application-sec-context-cond end
	
	//device-sec-context-cond begin
	bool pc;
	bool mobile_phone;
	bool tablet;
	bool voip_volte_phone;
	//device-sec-context-cond end
	//target-security-condition end
	
	//user-security-cond begin
	int usr_sec_cond_id;	
	//container user begin
	int user_tenant;
	int user_vn_id;
	//container user end

	//container group begin
	int group_tenant;
	int group_vn_id;
	//container group end
	//user-security-cond end
	
	//generic-context-condition begin
	int gen_context_cond_id;
	int start_time;
	int end_time;
	int geographic_location[50];
	int geo_location_num;
	//generic-context-condition end
	//container condition end
	int action;
	//policy end
	
	//cfg-content-security-conrol begin
	int antivirus_rule_id;
	int ips_rule_id;
	int ids_rule_id;
	int url_filter_rule_id;
	int data_filter_rule_id;
	int mail_filter_rule_id;
	int file_blocking_rule_id;
	int file_isolate_ruld_id;
	int pkt_capture_ruld_id;
	int app_control_rule_id;
	int voip_volte_rule_id;
	bool called_voip;
	bool called_volte;
	char *sip_header_uri;
	char *sip_header_method;
	int sip_header_expire_time;
	int sip_header_user_agent;
	int cell_id_region;
	//cfg-content-security-conrol end

	//cfg-attack-mitigation-conrol begin
	int syn_flood_attack_rule_id;
	int udp_flood_attack_rule_id;
	int icmp_flood_attack_rule_id;
	int ip_frag_flood_attack_rule_id;
	int ipv6_related_attacks_rule_id;

	int http_flood_attack_rule_id;
	int https_flood_attack_rule_id;
	int dns_flood_attack_rule_id;
	int dns_amp_flood_attack_rule_id;
	int ssl_ddos_attack_rule_id;
	int ip_sweep_attack_rule_id;
	int port_scanning_attack_rule_id;

	int ping_of_death_attack_rule_id;
	int teardrop_attack_rule_id;
	int oversized_icmp_attack_rule_id;
	int tracert_attack_rule_id;
	//cfg-attack-mitigation-conrol end

};

/********************************************************************/

/* Our daemon context as a global variable */
static struct confd_daemon_ctx *dctx;
static struct confd_trans_cbs trans;
static struct confd_data_cbs policy_cbks;

/* My user data, we got to install opaque data into */
/* the confd_daemon_ctx, this data is then accesible from the */
/* trans callbacks and must thus not necessarily vae to  */
/* be global data. */

struct mydata {
	int ctlsock;
	int workersock;
	int locked;
};

/* Help function which allocates a new host struct */
static struct policy *new_policy(int id)
{
	struct policy *pp;

	if ((pp = (struct policy*) calloc(1, sizeof(struct policy))) == NULL) {
		return NULL;
	}
	pp->rule_id = id;
	return pp;
}

/* Help function which insert policy to mysql */
static bool add_policy(struct policy *policy_container) {
	FILE *fp_rule, *fp_temp, *fp_suricata_yaml;
	char *temp_action;
	char temp_rule_file_location[100];
	char temp_rule_name[100];
	char temp_rule[300];
	char temp_yaml_content[100];
	char temp_addr[50];
	char temp_itoa[10];
	int temp_fp_location;
	int i;

	strncpy(temp_rule_name," - ", sizeof(temp_rule_name));
	strncat(temp_rule_name, policy_container->rule_name, sizeof(temp_rule_name));
	strncat(temp_rule_name,".rules\n", sizeof(temp_rule_name));

	strncpy(temp_rule_file_location,"/etc/suricata/rules/", sizeof(temp_rule_file_location));
	strncat(temp_rule_file_location, policy_container->rule_name, sizeof(temp_rule_file_location));
	strncat(temp_rule_file_location,".rules", sizeof(temp_rule_file_location));
	printf("%s\n",temp_rule_file_location);

	fp_suricata_yaml = fopen("/etc/suricata/suricata.yaml","r+");
	fp_temp = fopen("/etc/suricata/suricata.yaml.temp","w+");
	fp_rule = fopen(temp_rule_file_location,"w+");


	if(policy_container->action == PASS)
		temp_action = "pass";
	else if (policy_container->action == REJECT)
		temp_action = "reject";


///////////////////////////// Rule setting ///////////////////////////////////
	sprintf(temp_rule,"%s ip [",temp_action);
	for(i = 0; i < (policy_container->ipv4_src_num-1); i++) {
		inet_ntop(AF_INET, &policy_container->ipv4_src_list[i].s_addr, temp_addr, sizeof(temp_addr));
		strncat(temp_rule, temp_addr, sizeof(temp_rule));
		strncat(temp_rule, ",", sizeof(temp_rule));
	}
	inet_ntop(AF_INET, &policy_container->ipv4_src_list[i].s_addr, temp_addr, sizeof(temp_addr));
	strncat(temp_rule, temp_addr, sizeof(temp_rule));
	strncat(temp_rule, "] any -> ", sizeof(temp_rule));

	for(i = 0; i < policy_container->ipv4_dest_num; i++) {
		inet_ntop(AF_INET, &policy_container->ipv4_dest_list[i].s_addr, temp_addr, sizeof(temp_addr));
		strncat(temp_rule, temp_addr, sizeof(temp_rule));
		//strncat(temp_ddrule, ",", sizeof(temp_rule));
	}
	strncat(temp_rule, " any (msg:\"Website Reject\"; sid:", sizeof(temp_rule));
	sprintf(temp_itoa, "%d",policy_container->rule_id);
	strncat(temp_rule, temp_itoa, sizeof(temp_rule));
	strncat(temp_rule, "; rev:1;)", sizeof(temp_rule));
	fputs(temp_rule,fp_rule);	


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
	fputs(temp_rule_name, fp_suricata_yaml);

	while(!feof(fp_temp)) {
		fgets(temp_yaml_content, sizeof(temp_yaml_content), fp_temp);
		fputs(temp_yaml_content, fp_suricata_yaml);
	}

		
	fclose(fp_suricata_yaml);
	fclose(fp_temp);
	fclose(fp_rule);

	system("sudo /usr/bin/suricatasc -c reload-rules");

	return true;
}

static bool is_policy_exists(char *policy_name) {
	char where[100];
	MYSQL_RES *sqlResult;
	bool res = false;

	int n = sprintf(where, "`policy_name`=\"%s\"", policy_name);
	where[n] = '\0';

	sqlResult = MysqlSelectQuery("`firewall_policy`", "`policy_name`", where, true);
	if(MysqlGetNumRows(sqlResult) > 0) res = true;
	mysql_free_result(sqlResult);

	return res;
}


/********************************************************************/
/* transaction callbacks  */

/* The installed init() function gets called everytime Confd */
/* wants to establish a new transaction, Each NETCONF */
/* command will be a transaction */

/* We can choose to create threads here or whatever, we */
/* can choose to allocate this transaction to an already existing */
/* thread. We must tell Confd which filedescriptor should be */
/* used for all future communication in this transaction */
/* this has to be done through the call confd_trans_set_fd(); */

static int tr_init(struct confd_trans_ctx *tctx)
{
	char buf[INET6_ADDRSTRLEN];
	inet_ntop(tctx->uinfo->af, &tctx->uinfo->ip, buf, sizeof(buf));
	printf ("s_init() for %s from %s ", tctx->uinfo->username, buf);
	struct mydata *md = (struct mydata*) tctx->dx->d_opaque;
	confd_trans_set_fd(tctx, md->workersock);
	return CONFD_OK;
}

/* This callback gets invoked at the end of the transaction */
/* when ConfD has accumulated all write operations */
/* we're guaranteed that */
/* a) no more read ops will occur */
/* b) no other transactions will run between here and tr_finish() */
/*    for this transaction, i.e ConfD will serialize all transactions */

/* since we need to be prepared for abort(), we may not write */
/* our data to the actual database, we can choose to either */
/* copy the entire database here and write to the copy in the */
/* following write operatons _or_ let the write operations */
/* accumulate operations create(), set(), delete() instead of actually */
/* writing */

/* If our db supports transactions (which it doesn't in this */
/* silly example, this is the place to do START TRANSACTION */

static int tr_writestart(struct confd_trans_ctx *tctx)
{
	return CONFD_OK;
}

static int tr_prepare(struct confd_trans_ctx *tctx)
{
	return CONFD_OK;
}


static int tr_commit(struct confd_trans_ctx *tctx) // use the xml files.
{
	struct confd_tr_item *item = tctx->accumulated; // item is dats about xml files.
	struct policy *policy_container;
	confd_value_t *mac_src_list, *mac_dest_list, *mac_8021q_list, *mac_ether_type_list, *mac_tci_list;
	confd_value_t *ipv4_header_length_list, *ipv4_tos_list, *ipv4_total_length_list, *ipv4_id_list, *ipv4_fragment_list;
	confd_value_t *ipv4_fragment_offset_list, *ipv4_ttl_list, *ipv4_protocol_list, *ipv4_src_list, *ipv4_dest_list, *ipv4_geoip_list;
	confd_value_t *ipv6_dscp_list, *ipv6_ecn_list, *ipv6_traffic_class_list, *ipv6_flow_label_list, *ipv6_payload_length_list;
	confd_value_t *ipv6_next_header_list, *ipv6_hop_limit_list, *ipv6_src_list, *ipv6_dest_list;
	confd_value_t *tcp_seq_num_list, *tcp_ack_num_list, *tcp_window_size_list, *tcp_flags_list;
	confd_value_t *udp_length_list;
	confd_value_t *icmp_type_list, *icmp_code_list, *icmp_seg_num_list;
	confd_value_t *geo_location_list;
	char where[100] = {0};
	int i;

	while (item) {
		confd_hkeypath_t *keypath = item->hkp;
		confd_value_t *leaf = &(keypath->v[0][0]);

		if (strcmp(item->callpoint, "hcp") == 0) {
			switch (item->op) {
			case C_SET_ELEM:
				switch(CONFD_GET_XMLTAG(leaf)) {
					//policy
					case nsf_facing_interface_policy_name:
						policy_container->policy_name=(char *) CONFD_GET_BUFPTR(item->val);
						printf("Policy_name\n");
						break;
					case nsf_facing_interface_policy_id:
						policy_container->policy_id=(char *) CONFD_GET_BUFPTR(item->val);
						printf("Policy_ID\n");
						break;

					//rule
					case nsf_facing_interface_rule_name:
						policy_container->rule_name=(char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_rule_id:
						policy_container->rule_id = (int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_rule_msg:
						policy_container->rule_msg = (char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_rule_rev:
						policy_container->rule_rev = (int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_rule_gid:
						policy_container->rule_gid = (int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_rule_class_type:
						policy_container->rule_class_type = (char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_rule_reference:
						policy_container->rule_reference = (char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_rule_priority:
						policy_container->rule_priority = (int) CONFD_GET_UINT32(item->val);
						break;
					
					//event begin
					//user-security-event
					case nsf_facing_interface_usr_sec_event_id:
						policy_container->usr_sec_event_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_usr_sec_event_content:
						policy_container->usr_sec_event_content=(char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_usr_sec_event_format:
						policy_container->usr_sec_event_format=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_usr_sec_event_type:
						policy_container->usr_sec_event_type=(int) CONFD_GET_UINT32(item->val);
						break;

					//device-security-event
					case nsf_facing_interface_dev_sec_event_id:
						policy_container->dev_sec_event_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_dev_sec_event_content:
						policy_container->dev_sec_event_content=(char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_dev_sec_event_format:
						policy_container->dev_sec_event_format=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_dev_sec_event_type:
						policy_container->dev_sec_event_type=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_dev_sec_event_type_severity:
						policy_container->dev_sec_event_type_severity=(int) CONFD_GET_UINT32(item->val);
						break;

					//system-security-event
					case nsf_facing_interface_sys_sec_event_id:
						policy_container->sys_sec_event_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_sys_sec_event_content:
						policy_container->sys_sec_event_content=(char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_sys_sec_event_format:
						policy_container->sys_sec_event_format=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_sys_sec_event_type:
						policy_container->sys_sec_event_type=(int) CONFD_GET_UINT32(item->val);
						break;

					//time-security-event
					case nsf_facing_interface_time_sec_event_id:
						policy_container->time_sec_event_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_time_sec_event_period_begin:
						policy_container->time_sec_event_period_begin=atoi((char *)CONFD_GET_BUFPTR(item->val));
						break;
					case nsf_facing_interface_time_sec_event_period_end:
						policy_container->time_sec_event_period_end=atoi((char *)CONFD_GET_BUFPTR(item->val));
						break;
					case nsf_facing_interface_time_sec_event_time_zone:
						policy_container->time_sec_event_time_zone=(char *) CONFD_GET_BUFPTR(item->val);
						break;
					//event end

					//condition begin
					
					
					//packet-security-mac-condition
					case nsf_facing_interface_pkt_sec_cond_mac_dest:
						mac_dest_list = CONFD_GET_LIST(item->val);
						policy_container->mac_dest_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->mac_dest_num; i++) {
							policy_container->pkt_sec_cond_mac_dest[i] = (int)CONFD_GET_UINT32(&mac_dest_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_mac_src:
						mac_src_list = CONFD_GET_LIST(item->val);
						policy_container->mac_src_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->mac_src_num; i++) {
							policy_container->pkt_sec_cond_mac_src[i] = (int)CONFD_GET_UINT32(&mac_src_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_mac_8021q:
						mac_8021q_list = CONFD_GET_LIST(item->val);
						policy_container->mac_8021q_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->mac_8021q_num; i++) {
							policy_container->pkt_sec_cond_mac_8021q[i] = (char *)CONFD_GET_BUFPTR(&mac_8021q_list[i]);
						}						
						break;
					case nsf_facing_interface_pkt_sec_cond_mac_ether_type:
						mac_ether_type_list= CONFD_GET_LIST(item->val);
						policy_container->mac_ether_type_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->mac_ether_type_num; i++) {
							policy_container->pkt_sec_cond_mac_ether_type[i] = (char *)CONFD_GET_BUFPTR(&mac_ether_type_list[i]);
						}	
						break;
					case nsf_facing_interface_pkt_sec_cond_mac_tci:
						mac_tci_list = CONFD_GET_LIST(item->val);
						policy_container->mac_tci_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->mac_tci_num; i++) {
							policy_container->pkt_sec_cond_mac_tci[i] = (char *)CONFD_GET_BUFPTR(&mac_tci_list[i]);
						}
						break;

					//packet-security-ipv4-condition
					case nsf_facing_interface_pkt_sec_cond_ipv4_header_length:
						ipv4_header_length_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_header_length_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_header_length_num; i++) {
							policy_container->pkt_sec_cond_ipv4_header_length[i] = (int)CONFD_GET_UINT32(&ipv4_header_length_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_tos:
						ipv4_tos_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_tos_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_tos_num; i++) {
							policy_container->pkt_sec_cond_ipv4_tos[i] = (int)CONFD_GET_UINT32(&ipv4_tos_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_total_length:
						ipv4_total_length_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_total_length_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_total_length_num; i++) {
							policy_container->pkt_sec_cond_ipv4_total_length[i] = (int)CONFD_GET_UINT32(&ipv4_total_length_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_id:
						ipv4_id_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_id_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_id_num; i++) {
							policy_container->pkt_sec_cond_ipv4_id[i] = (int)CONFD_GET_UINT32(&ipv4_id_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_fragment:
						ipv4_fragment_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_fragment_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_fragment_num; i++) {
							policy_container->pkt_sec_cond_ipv4_fragment[i] = (int)CONFD_GET_UINT32(&ipv4_fragment_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_fragment_offset:
						ipv4_fragment_offset_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_fragment_offset_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_fragment_offset_num; i++) {
							policy_container->pkt_sec_cond_ipv4_fragment_offset[i] = (int)CONFD_GET_UINT32(&ipv4_fragment_offset_list[i]);
						}
						break;
					
					case nsf_facing_interface_pkt_sec_cond_ipv4_ttl:
						ipv4_ttl_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_ttl_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_ttl_num; i++) {
							policy_container->pkt_sec_cond_ipv4_ttl[i] = (int)CONFD_GET_UINT32(&ipv4_ttl_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_protocol:
						ipv4_protocol_list=CONFD_GET_LIST(item->val);
						policy_container->ipv4_protocol_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_protocol_num; i++) {
							policy_container->pkt_sec_cond_ipv4_protocol[i] = (char *) CONFD_GET_BUFPTR(&ipv4_protocol_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_src:
						ipv4_src_list = CONFD_GET_LIST(item->val);
						policy_container->ipv4_src_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_src_num; i++) {
							policy_container->ipv4_src_list[i] = CONFD_GET_IPV4(&ipv4_src_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_dest:
						ipv4_dest_list = CONFD_GET_LIST(item->val);
						policy_container->ipv4_dest_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_dest_num; i++) {
							policy_container->ipv4_dest_list[i] = CONFD_GET_IPV4(&ipv4_dest_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_ipopts:
						policy_container->pkt_sec_cond_ipv4_ipopts=(char *) CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_sameip:
						policy_container->pkt_sec_cond_ipv4_sameip=(bool)CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv4_geoip:
						ipv4_geoip_list = CONFD_GET_LIST(item->val);
						policy_container->ipv4_geoip_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv4_geoip_num; i++) {
							policy_container->pkt_sec_cond_ipv4_geoip[i] = (char *)CONFD_GET_BUFPTR(&ipv4_geoip_list[i]);
						}
						break;
					//packet-security-ipv6-condition
					case nsf_facing_interface_pkt_sec_cond_ipv6_dscp:
						ipv6_dscp_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_dscp_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv6_dscp_num; i++) {
							policy_container->pkt_sec_cond_ipv6_dscp[i] = (char *)CONFD_GET_BUFPTR(&ipv6_dscp_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv6_ecn:
						ipv6_ecn_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_ecn_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv6_ecn_num; i++) {
							policy_container->pkt_sec_cond_ipv6_ecn[i] = (char *)CONFD_GET_BUFPTR(&ipv6_ecn_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv6_traffic_class:
						ipv6_traffic_class_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_traffic_class_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv6_traffic_class_num; i++) {
							policy_container->pkt_sec_cond_ipv6_traffic_class[i] = (int)CONFD_GET_UINT32(&ipv6_traffic_class_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv6_flow_label:
						ipv6_flow_label_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_flow_label_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv6_flow_label_num; i++) {
							policy_container->pkt_sec_cond_ipv6_flow_label[i] = (int)CONFD_GET_UINT32(&ipv6_flow_label_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv6_payload_length:
						ipv6_payload_length_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_payload_length_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv6_payload_length_num; i++) {
							policy_container->pkt_sec_cond_ipv6_payload_length[i] = (int)CONFD_GET_UINT32(&ipv6_payload_length_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv6_next_header:
						ipv6_next_header_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_next_header_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv6_next_header_num; i++) {
							policy_container->pkt_sec_cond_ipv6_next_header[i] = (int)CONFD_GET_UINT32(&ipv6_next_header_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv6_hop_limit:
						ipv6_hop_limit_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_hop_limit_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->ipv6_hop_limit_num; i++) {
							policy_container->pkt_sec_cond_ipv6_hop_limit[i] = (int)CONFD_GET_UINT32(&ipv6_hop_limit_list[i]);
						}
						break;
						
					case nsf_facing_interface_pkt_sec_cond_ipv6_src:
						ipv6_src_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_src_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->ipv6_src_num; i++) {
							policy_container->ipv6_src_list[i]=CONFD_GET_IPV6(&ipv6_src_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_ipv6_dest:
						ipv6_dest_list=CONFD_GET_LIST(item->val);
						policy_container->ipv6_dest_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->ipv6_dest_num; i++) {
							policy_container->ipv6_dest_list[i]=CONFD_GET_IPV6(&ipv6_dest_list[i]);
						}
						break;


					//packet-security-tcp-condition
					case nsf_facing_interface_pkt_sec_cond_tcp_seq_num:
						tcp_seq_num_list=CONFD_GET_LIST(item->val);
						policy_container->tcp_seq_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->tcp_seq_num; i++) {
							policy_container->pkt_sec_cond_tcp_seq_num[i]=(int)CONFD_GET_UINT32(&tcp_seq_num_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_tcp_ack_num:
						tcp_ack_num_list=CONFD_GET_LIST(item->val);
						policy_container->tcp_ack_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->tcp_ack_num; i++) {
							policy_container->pkt_sec_cond_tcp_ack_num[i]=(int)CONFD_GET_UINT32(&tcp_ack_num_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_tcp_window_size:
						tcp_window_size_list=CONFD_GET_LIST(item->val);
						policy_container->tcp_window_size_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->tcp_window_size_num; i++) {
							policy_container->pkt_sec_cond_tcp_window_size[i]=(int)CONFD_GET_UINT32(&tcp_window_size_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_tcp_flags:
						tcp_flags_list=CONFD_GET_LIST(item->val);
						policy_container->tcp_flags_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->tcp_flags_num; i++) {
							policy_container->pkt_sec_cond_tcp_flags[i]=(int)CONFD_GET_UINT32(&tcp_flags_list[i]);
						}
						break;

					//packet-security-udp-condition
					case nsf_facing_interface_pkt_sec_cond_udp_length:
						udp_length_list = CONFD_GET_LIST(item->val);
						policy_container->udp_length_num = CONFD_GET_LISTSIZE(item->val);
						for(i = 0; i < policy_container->udp_length_num; i++) {
							policy_container->pkt_sec_cond_udp_length[i] = (char *)CONFD_GET_BUFPTR(&udp_length_list[i]);
						}
						break;
					
					//packet-security-icmp-condition
					case nsf_facing_interface_pkt_sec_cond_icmp_type:
						icmp_type_list=CONFD_GET_LIST(item->val);
						policy_container->icmp_type_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->icmp_type_num; i++) {
							policy_container->pkt_sec_cond_icmp_type[i]=(int)CONFD_GET_UINT32(&icmp_type_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_icmp_code:
						icmp_code_list=CONFD_GET_LIST(item->val);
						policy_container->icmp_code_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->icmp_code_num; i++) {
							policy_container->pkt_sec_cond_icmp_code[i]=(int)CONFD_GET_UINT32(&icmp_code_list[i]);
						}
						break;
					case nsf_facing_interface_pkt_sec_cond_icmp_seg_num:
						icmp_seg_num_list=CONFD_GET_LIST(item->val);
						policy_container->icmp_seg_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->icmp_code_num; i++) {
							policy_container->pkt_sec_cond_icmp_seg_num[i]=(int)CONFD_GET_UINT32(&icmp_seg_num_list[i]);
						}
						break;

					//packet-payload-security-condition
					case nsf_facing_interface_pkt_payload_id:
						policy_container->pkt_payload_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_content:
						policy_container->pkt_payload_content=(char *)CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_pkt_payload_nocase:
						policy_container->pkt_payload_nocase=(bool)CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_pkt_payload_depth:
						policy_container->pkt_payload_depth=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_offset:
						policy_container->pkt_payload_offset=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_distance:
						policy_container->pkt_payload_distance=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_within:
						policy_container->pkt_payload_within=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_isdataat:
						policy_container->pkt_payload_isdataat=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_dsize:
						policy_container->pkt_payload_dsize=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_replace:
						policy_container->pkt_payload_replace=(char *)CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_pkt_payload_pcre:
						policy_container->pkt_payload_pcre=(char *)CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_pkt_payload_rpc_app_num:
						policy_container->pkt_payload_rpc_app_num=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_rpc_version_num:
						policy_container->pkt_payload_rpc_version_num=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_payload_rpc_procedure_num:
						policy_container->pkt_payload_rpc_procedure_num=(int)CONFD_GET_UINT32(item->val);
						break;

					//target-security-condition begin
					case nsf_facing_interface_target_sec_cond_id:
						policy_container->target_sec_cond_id=(int)CONFD_GET_UINT32(item->val);
						break;
					//service-sec-context-cond begin
					case nsf_facing_interface_service_sec_context_cond_name:
						policy_container->service_sec_context_cond_name=(char *)CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_service_sec_context_cond_id:
						policy_container->service_sec_context_cond_id=(int)CONFD_GET_UINT32(item->val);
						break;
					//protocol 
					case nsf_facing_interface_service_sec_context_cond_protocol_tcp:
						policy_container->service_sec_context_cond_protocol_tcp=(bool)CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_service_sec_context_cond_protocol_udp:
						policy_container->service_sec_context_cond_protocol_udp=(bool)CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_service_sec_context_cond_protocol_icmp:
						policy_container->service_sec_context_cond_protocol_icmp=(bool)CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_service_sec_context_cond_protocol_icmpv6:
						policy_container->service_sec_context_cond_protocol_icmpv6=(bool)CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_service_sec_context_cond_protocol_ip:
						policy_container->service_sec_context_cond_protocol_ip=(bool)CONFD_GET_BOOL(item->val);
						break;
					//protocol end
					case nsf_facing_interface_service_sec_context_cond_src_port:
						policy_container->service_sec_context_cond_src_port=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_service_sec_context_cond_dest_port:
						policy_container->service_sec_context_cond_dest_port=(int)CONFD_GET_UINT32(item->val);
						break;
					//service-sec-context-cond end
				
					//application-sec-context-cond begin
					case nsf_facing_interface_app_sec_context_cond_name:
						policy_container->app_sec_context_cond_name=(char *)CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_app_sec_context_cond_id:
						policy_container->app_sec_context_cond_id=(int)CONFD_GET_UINT32(item->val);
						break;

					//category begin
					case nsf_facing_interface_business_system:
						policy_container->business_system=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_entertainment:
						policy_container->entertainment=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_interest:
						policy_container->interest=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_network:
						policy_container->network=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_general:
						policy_container->general=CONFD_GET_BOOL(item->val);
						break;
					//category end
					
					//subcategory begin
					case nsf_facing_interface_finance:
						policy_container->finance=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_email:
						policy_container->email=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_game:
						policy_container->game=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_media_sharing:
						policy_container->media_sharing=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_social_network:
						policy_container->social_network=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_web_posting:
						policy_container->web_posting=CONFD_GET_BOOL(item->val);
						break;
					//subcategory end
				
					//data-transmission-model begin
					case nsf_facing_interface_client_server:
						policy_container->client_server=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_browser_based:
						policy_container->browser_based=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_networking:
						policy_container->networking=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_peer_to_peer:
						policy_container->peer_to_peer=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_unassigned:
						policy_container->unassigned=CONFD_GET_BOOL(item->val);
						break;
					//data-transmission-model end
					
					//risk-level begin
					case nsf_facing_interface_exploitable:
						policy_container->expolitable=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_productivity_loss:
						policy_container->productivity_loss=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_evasive:
						policy_container->evasive=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_data_loss:
						policy_container->data_loss=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_malware_vehicle:
						policy_container->malware_vehicle=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_bandwidth_consuming:
						policy_container->bandwidth_consuming=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_tunneling:
						policy_container->tunneling=CONFD_GET_BOOL(item->val);
						break;
					//risk-level end
					//application-sec-context-cond end
				
					//device-sec-context-cond begin
					case nsf_facing_interface_pc:
						policy_container->pc=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_mobile_phone:
						policy_container->mobile_phone=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_tablet:
						policy_container->tablet=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_voip_volte_phone:
						policy_container->voip_volte_phone=CONFD_GET_BOOL(item->val);
						break;
					//device-sec-context-cond end
					//target-security-condition end
				
					//user-security-cond begin
					case nsf_facing_interface_usr_sec_cond_id:
						policy_container->usr_sec_cond_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_user_tenant:
						policy_container->user_tenant=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_user_vn_id:
						policy_container->user_vn_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_group_tenant:
						policy_container->group_tenant=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_group_vn_id:
						policy_container->group_vn_id=(int)CONFD_GET_UINT32(item->val);
						break;
					//user-security-cond end

					//generic-context-condition begin
					case nsf_facing_interface_gen_context_cond_id:
						policy_container->gen_context_cond_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_start_time:
						policy_container->start_time = atoi((char *) CONFD_GET_BUFPTR(item->val)); // (int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_end_time:
						policy_container->end_time = atoi((char *) CONFD_GET_BUFPTR(item->val)); //(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_geographic_location:
						geo_location_list=CONFD_GET_LIST(item->val);
						policy_container->geo_location_num=CONFD_GET_LISTSIZE(item->val);
						for (i = 0; i < policy_container->geo_location_num; i++) {
							policy_container->geographic_location[i]=CONFD_GET_UINT32(&geo_location_list[i]);
						}
						break;
					//condition end

					//action begin
					//ingress-action
					case nsf_facing_interface_pass:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = PASS;
						break;
					case nsf_facing_interface_drop:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = DROP;
						break;
					case nsf_facing_interface_reject:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = REJECT;
						break;
					case nsf_facing_interface_alert:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = ALERT;
						break;
					case nsf_facing_interface_mirror:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = MIRROR;
						break;

					//egress-action
					case nsf_facing_interface_invoke_signaling:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = INVOKE_SIGNALING;
						break;
					case nsf_facing_interface_tunnel_encapsulation:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = TUNNEL_ENCAPSULATION;
						break;
					case nsf_facing_interface_forwarding:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = FORWARDING;
						break;


					//apply-profile-action
					case nsf_facing_interface_antivirus_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = ANTIVIRUS;
						break;
					case nsf_facing_interface_ips_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = IPS;
						break;
					case nsf_facing_interface_ids_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = IDS;
						break;
					case nsf_facing_interface_url_filtering_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = URL_FILTERING;
						break;
					case nsf_facing_interface_data_filtering_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = DATA_FILTERING;
						break;
					case nsf_facing_interface_mail_filtering_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = MAIL_FILTERING;
						break;
					case nsf_facing_interface_file_blocking_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = FILE_BLOCKING;
						break;
					case nsf_facing_interface_file_isolate_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = FILE_ISOLATE;
						break;
					case nsf_facing_interface_pkt_capture_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = PKT_CAPTURE;
						break;
					case nsf_facing_interface_voip_volte_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = VOIP_VOLTE;
						break;

					//attack-mitigation-control
					case nsf_facing_interface_syn_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = SYN_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_udp_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = UDP_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_icmp_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = ICMP_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_ip_frag_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = IP_FRAG_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_ipv6_related_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = IPV6_RELATED_ATTACK;
						break;
					case nsf_facing_interface_http_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = HTTP_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_https_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = HTTPS_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_dns_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = DNS_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_dns_amp_flood_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = DNS_AMP_FLOOD_ATTACK;
						break;
					case nsf_facing_interface_ssl_ddos_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = SSL_DDOS_ATTACK;
						break;
					case nsf_facing_interface_ip_sweep_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = IP_SWEEP_ATTACK;
						break;
					case nsf_facing_interface_port_scanning_attack:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = PORT_SCANNING_ATTACK;
						break;
					case nsf_facing_interface_ping_of_death_attack:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = PING_OF_DEATH_ATTACK;
						break;
					case nsf_facing_interface_teardrop_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = TEARDROP_ATTACK;
						break;
					case nsf_facing_interface_oversized_icmp_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = OVERSIZED_ICMP_ATTACK;
						break;
					case nsf_facing_interface_tracert_insp:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = TRACERT_ATTACK;
						break;



					case nsf_facing_interface_antivirus_rule_id:
						policy_container->antivirus_rule_id = (int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_ips_rule_id:
						policy_container->ips_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_ids_rule_id:
						policy_container->ids_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_url_filter_rule_id:
						policy_container->url_filter_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_data_filter_rule_id:
						policy_container->data_filter_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_mail_filter_rule_id:
						policy_container->mail_filter_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_file_blocking_rule_id:
						policy_container->file_blocking_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_file_isolate_rule_id:
						policy_container->file_isolate_ruld_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_pkt_capture_rule_id:
						policy_container->pkt_capture_ruld_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_app_control_rule_id:
						policy_container->app_control_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_voip_volte_rule_id:
						policy_container->voip_volte_rule_id=(int)CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_called_voip:
						policy_container->called_voip=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_called_volte:
						policy_container->called_volte=CONFD_GET_BOOL(item->val);
						break;
					case nsf_facing_interface_sip_header_uri:
						policy_container->sip_header_uri=(char *)CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_sip_header_method:
						policy_container->sip_header_method=(char *)CONFD_GET_BUFPTR(item->val);
						break;
					case nsf_facing_interface_sip_header_expire_time:
						policy_container->sip_header_expire_time=atoi((char *)CONFD_GET_BUFPTR(item->val));
						break;
					case nsf_facing_interface_sip_header_user_agent:
						policy_container->sip_header_user_agent=(int)CONFD_GET_UINT32(item->val);
						break;
					





					case nsf_facing_interface_voip_volte_pass:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = PASS;
						break;
					case nsf_facing_interface_voip_volte_drop:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = DROP;
						break;
					case nsf_facing_interface_voip_volte_reject:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = REJECT;
						break;
					case nsf_facing_interface_voip_volte_alert:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = ALERT;
						break;
					case nsf_facing_interface_voip_volte_mirror:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = MIRROR;
						break;
					case nsf_facing_interface_voip_volte_redirection:
						if(CONFD_GET_BOOL(item->val))
							policy_container->action = REDIRECTION;
						break;


					case nsf_facing_interface_syn_flood_attack_rule_id:
						policy_container->syn_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_udp_flood_attack_rule_id:
						policy_container->udp_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_icmp_flood_attack_rule_id:
						policy_container->icmp_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_ip_frag_flood_attack_rule_id:
						policy_container->ip_frag_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_ipv6_related_attacks_rule_id:
						policy_container->ipv6_related_attacks_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;

					case nsf_facing_interface_http_flood_attack_rule_id:
						policy_container->http_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_https_flood_attack_rule_id:
						policy_container->https_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_dns_flood_attack_rule_id:
						policy_container->dns_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_dns_amp_flood_attack_rule_id:
						policy_container->dns_amp_flood_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_ssl_ddos_attack_rule_id:
						policy_container->ssl_ddos_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;

					case nsf_facing_interface_ip_sweep_attack_rule_id:
						policy_container->ip_sweep_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_port_scanning_attack_rule_id:
						policy_container->port_scanning_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					
					case nsf_facing_interface_ping_of_death_attack_rule_id:
						policy_container->ping_of_death_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_teardrop_attack_rule_id:
						policy_container->teardrop_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_oversized_icmp_attack_rule_id:
						policy_container->oversized_icmp_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;
					case nsf_facing_interface_tracert_attack_rule_id:
						policy_container->tracert_attack_rule_id=(int) CONFD_GET_UINT32(item->val);
						break;

				}
				break;
			case C_CREATE:
				// Create container
				printf("!!!!!!!!!!!\n");
				policy_container = new_policy((int) CONFD_GET_UINT32(leaf));
				
				break;
			case C_REMOVE:
				// Find policy and remove
				strcpy(where, "`policy_name`=");
				strcpy(where + 12, (char *)CONFD_GET_BUFPTR(leaf));
				if(!MysqlDeleteQuery("`firewall_policy`", where)) {
					fprintf(stderr, "policy remove failed\n");
					return CONFD_ERR;
				}
				break;
			default:
				return CONFD_ERR;
			}
		}
		item = item->next;
	}

	if(!is_policy_exists(policy_container->rule_name))
		add_policy(policy_container);
	else {
		fprintf(stderr, "\nsame policy name exists..\n");
		return CONFD_ERR;
	}

	return CONFD_OK;
}

static int tr_abort(struct confd_trans_ctx *tctx)
{
	return CONFD_OK;
}

static int tr_finish(struct confd_trans_ctx *tctx)
{
	return CONFD_OK;
}

static int policy_set_elem(struct confd_trans_ctx *tctx, confd_hkeypath_t *keypath, confd_value_t *newval) {
	return CONFD_ACCUMULATE;
}

/* Data Exists Check */
static int policy_get_elem (struct confd_trans_ctx *tctx, confd_hkeypath_t *keypath) {
/*
	int n = 0;
	char where[100] = {0};
	MYSQL_RES *sqlResult;
	switch(CONFD_GET_XMLTAG(&(keypath->v[0][0]))){
		case nsc_rule_name:
		// Check whether same rule name exists or not
		n = sprintf(where, "`policy-name`=\"%s\"", (char *) &(keypath->v[1][0]);)
		where[n] = '\0';
		printf("%s\n", (&(keypath->v[0][0])));
		printf("%s\n", (&(keypath->v[1][0])));
		printf("%s\n", (&(keypath->v[2][0])));

		sqlResult = MysqlSelectQuery("`firewall-policy`", "`policy-name`", where, true);
		printf("query success\n", &(keypath->v[3][0]));

		if(MysqlGetNumRows(sqlResult) > 0) {
			confd_value_t v;
			MYSQL_ROW row = MysqlGetRow(sqlResult);
			CONFD_SET_STR(&v, row[0]);
			confd_data_reply_value(tctx, &v);
		}
		mysql_free_result(sqlResult);

		break;

		case nsc_rule_id:
		// Check same rule id exists
		strcpy(where, "`policy-id`=");
		strcpy(where + 12, (char *) &(keypath->v[1][0]));
		sqlResult = MysqlSelectQuery("`firewall-policy`", "`policy-id`", where, true);

		if(MysqlGetNumRows(sqlResult) > 0) {
			confd_value_t v;
			MYSQL_ROW row = MysqlGetRow(sqlResult);
			CONFD_SET_INT32(&v, (int) *(row[0]));
			confd_data_reply_value(tctx, &v);
		}
		mysql_free_result(sqlResult);

		break;

		case nsc_pkt_sec_cond_ipv4_src_addr:
		case nsc_pkt_sec_cond_ipv4_dest_addr:
		case nsc_start_time:
		case nsc_end_time:
		case nsc_permit:
		case nsc_deny:
		// These tags are not unique property.
		break;

		default:
			fprintf(stderr, "HERE %d\n", CONFD_GET_XMLTAG(&(keypath->v[0][0])));
			return CONFD_ERR;
	}
*/
	confd_data_reply_not_found(tctx);
	return CONFD_OK;
}

static int policy_delete(struct confd_trans_ctx *tctx, confd_hkeypath_t *keypath) {
	return CONFD_ACCUMULATE;
}
static int policy_get_next(struct confd_trans_ctx *tctx, confd_hkeypath_t *keypath, long next) {
	return CONFD_OK;
}

static int policy_num_instances(struct confd_trans_ctx *tctx, confd_hkeypath_t *keypath) {
	//return num of policies
	MYSQL_RES *sqlResult = MysqlSelectQuery("`firewall_policy`", "COUNT(*)", "1=1", false);
	MYSQL_ROW row = MysqlGetRow(sqlResult);

	confd_value_t v;
	CONFD_SET_INT32(&v, *(row[0]));
	confd_data_reply_value(tctx, &v);

	mysql_free_result(sqlResult);
	return CONFD_OK;
}

static int policy_create(struct confd_trans_ctx *tctx, confd_hkeypath_t *keypath) {
	return CONFD_ACCUMULATE;
}


void start_confd() {
	int ctlsock;
	int workersock;
	struct sockaddr_in addr;
	struct mydata *md;
	int debuglevel = CONFD_TRACE;

	//MysqlInitialize();

	/* These are our transaction callbacks */
	trans.init = tr_init;
	trans.write_start = tr_writestart;
	trans.prepare = tr_prepare;
	trans.commit = tr_commit;
	trans.abort = tr_abort;
	trans.finish = tr_finish;


	policy_cbks.get_elem = policy_get_elem;
	policy_cbks.get_next = policy_get_next;
	policy_cbks.num_instances = policy_num_instances;
	policy_cbks.set_elem = policy_set_elem;
	policy_cbks.create = policy_create;
	policy_cbks.remove = policy_delete;
	strcpy(policy_cbks.callpoint, "hcp");

	/* Init library  */
	confd_init("firewall_daemon", stderr, debuglevel);
	/* Initialize daemon context */
	if ((dctx = confd_init_daemon("firewall_daemon")) == NULL)
		confd_fatal("Failed to initialize confd\n");

	if ((ctlsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
		confd_fatal("Failed to open ctlsocket\n");

	
	//addr.sin_addr.s_addr = inet_addr("10.0.0.200");    //IMTL
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_family = AF_INET;
	addr.sin_port = htons(CONFD_PORT);

	if (confd_load_schemas((struct sockaddr*)&addr,
						   sizeof (struct sockaddr_in)) != CONFD_OK)
		confd_fatal("Failed to load schemas from confd\n");

	/* Create the first control socket, all requests to */
	/* create new transactions arrive here */
	if (confd_connect(dctx, ctlsock, CONTROL_SOCKET, (struct sockaddr*)&addr,
					  sizeof (struct sockaddr_in)) < 0)
		confd_fatal("Failed to confd_connect() to confd \n");


	/* Also establish a workersocket, this is the most simple */
	/* case where we have just one ctlsock and one workersock */
	if ((workersock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
		confd_fatal("Failed to open workersocket\n");
	if (confd_connect(dctx, workersock, WORKER_SOCKET,(struct sockaddr*)&addr,
					  sizeof (struct sockaddr_in)) < 0)
		confd_fatal("Failed to confd_connect() to confd \n");


	/* Create a user datastructure and connect it to the */
	/* daemon struct so that we can always get to it */
	if ((md = dctx->d_opaque = (struct mydata*)
		 calloc(1, sizeof(struct mydata))) == NULL)
		confd_fatal("Failed to malloc");
	md->ctlsock = ctlsock;
	md->workersock = workersock;

	confd_register_trans_cb(dctx, &trans);

	if (confd_register_data_cb(dctx, &policy_cbks) == CONFD_ERR)
		confd_fatal("Failed to register host cb \n");
	if (confd_register_done(dctx) != CONFD_OK)
		confd_fatal("Failed to complete registration \n");

	struct pollfd set[2];
	int ret;

	set[0].fd = ctlsock;
	set[0].events = POLLIN;
	set[0].revents = 0;

	set[1].fd = workersock;
	set[1].events = POLLIN;
	set[1].revents = 0;

	while (1) {
		if (poll(&set[0], 2, -1) < 0) {
			perror("Poll failed:");
			continue;
		}

		printf("Test\n\n");

		/* Check for I/O */
		if (set[0].revents & POLLIN) {
			if ((ret = confd_fd_ready(dctx, ctlsock)) == CONFD_EOF) {
				confd_fatal("Control socket closed\n");
			} else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
				confd_fatal("Error on control socket request: %s (%d): %s\n",
					 confd_strerror(confd_errno), confd_errno, confd_lasterr());
			}
		}
		if (set[1].revents & POLLIN) {
			if ((ret = confd_fd_ready(dctx, workersock)) == CONFD_EOF) {
				confd_fatal("Worker socket closed\n");
			} else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
				confd_fatal("Error on worker socket request: %s (%d): %s\n",
					 confd_strerror(confd_errno), confd_errno, confd_lasterr());
			}
		}
	}
}

/********************************************************************/
