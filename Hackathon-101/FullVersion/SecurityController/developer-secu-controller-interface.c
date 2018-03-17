/*********************************************************************
 * ConfD Subscriber intro example
 * Implements a configuration data provider
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
#include <time.h>


#include <confd_lib.h>
#include <confd_dp.h>
#include "i2nsf-capability.h"
#include "dlist.h"
#include "developer-secu-controller-interface.h"

/********************************************************************/

/* This _is_ our database */

struct capability {
	char name[64];
	struct in_addr ipv4_addr;
	char type[64];
};



/********************************************************************/

/* A structure to keep tabs on how many times */
/* we access the different cb functions */
/* to show in the CLI */

struct access_stat {
	int get_elem;
	int get_next;
	int num_instances;
	int set_elem;
	int create;
	int remove;
};

static struct access_stat ccp_calls;

static Dlist *running_db = NULL;

/* Our daemon context as a global variable */
static struct confd_daemon_ctx *dctx;

static struct confd_trans_cbs trans;
static struct confd_data_cbs capa_cbks;


/* My user data, we got to install opaque data into */
/* the confd_daemon_ctx, this data is then accesible from the */
/* trans callbacks and must thus not necessarily vae to  */
/* be global data. */

struct mydata {
	int ctlsock;
	int workersock;
	int locked;
};

/********************************************************************/

/* free a db */
static void clear_db(Dlist *list){
	free_dlist(list);
}

static void show_capability(Dlist *hptr){
	struct capability* capa = (struct capability*) hptr->val;
	printf ("capability %10s %10s \n",
			capa->name, inet_ntoa(capa->ipv4_addr));
}

/* Help function which allocates a new capability struct */
static struct capability *new_capability(char *name, char *ipv4_addr) {
	struct capability *capa;
	if ((capa = (struct capability*) calloc(1, sizeof(struct capability))) == NULL)
		return NULL;
	strcpy(capa->name, name);
	capa->ipv4_addr.s_addr = inet_addr(ipv4_addr);
	return capa;
}

/* Help function which adds a new capability, keeping the list ordered */
static void add_capability(Dlist *list, struct capability *new){
	Dlist *ptr;
	struct capability *capa;

	dl_traverse(ptr, list) {
		capa = (struct capability *) ptr->val;
		if (strcmp(new->name, capa->name) < 0) {
			break;
		}
	}
	dl_insert_b(ptr, new);
}


static void show_db(Dlist *list){
	Dlist *hptr;
	for (hptr = list->flink; hptr != list; hptr = hptr->flink) {
		show_capability(hptr);
	}
}

static int dump_db(Dlist *list, char *filename){
	Dlist *hptr;
	FILE *fp;
	if ((fp = fopen(filename, "w+")) == NULL)
		return -1;
	for (hptr = list->flink; hptr != list; hptr = hptr->flink) {
		struct capability *capa = (struct capability*) hptr->val;
		fprintf(fp, "%s %s { ",capa->name, inet_ntoa(capa->ipv4_addr));
		fprintf(fp, " }\n");
	}
	fclose(fp);
	return 1;
}



/* Find a specific capability in a specific DB */
static Dlist *find_capability(Dlist *list, confd_value_t *v){
	Dlist *hptr;
	for (hptr = list->flink; hptr != list; hptr = hptr->flink) {
		struct capability *s = (struct capability*) hptr->val;
		if (confd_svcmp(s->name, v) == 0)
			return hptr;
	}
	return NULL;
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

static int tr_init(struct confd_trans_ctx *tctx){
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

static int tr_writestart(struct confd_trans_ctx *tctx){
	// printf("\ntr_writestart\n");
	return CONFD_OK;
}

static int tr_prepare(struct confd_trans_ctx *tctx){
	// printf("\ntr prepare\n");
	return CONFD_OK;
}

static int tr_commit(struct confd_trans_ctx *tctx){
	// printf("\n tr commit\n");
	struct confd_tr_item *item = tctx->accumulated;
	struct capability *capa;
	Dlist *dlist;
	while (item) {
		confd_hkeypath_t *keypath = item->hkp;
		confd_value_t *leaf = &(keypath->v[0][0]);
		if (strcmp(item->callpoint, "ccp") == 0) {
			switch (item->op) {
			case C_SET_ELEM:
				/* we're setting the elem of an already existing */
				/* capability entry */
				/* keypath example: /capabilitys/capability{hname}/ipv4_addr */
				if ((dlist = find_capability(running_db,
									   &(keypath->v[1][0]))) != NULL){
					capa = (struct capability*) dlist->val;
					switch (CONFD_GET_XMLTAG(leaf)) {
					case i2nsf_capability_ipv4_address:
						capa->ipv4_addr = CONFD_GET_IPV4(item->val);
						break;
					default:
						break;
					}
				}
			break;
			case C_CREATE:
				/* we're creating a brand new capability entry */
				/* it will soon be populated with values */
				/* keypath example: /capabilitys/capability{hname}   */

				capa = (struct capability*) calloc(1, sizeof(struct capability));
				strcpy(capa->name, (char *)CONFD_GET_BUFPTR(leaf));
				add_capability(running_db, capa);
				break;
			case C_REMOVE:
				if ((dlist = find_capability(running_db, leaf)) != NULL) {
					capa = (struct capability*) dlist->val;
					free(capa);
					dl_delete_node(dlist);
				}
				break;
			default:
				return CONFD_ERR;
			}
		}
		item = item->next;
	}
	return CONFD_OK;
}

static int tr_abort(struct confd_trans_ctx *tctx){
	return CONFD_OK;
}

static int tr_finish(struct confd_trans_ctx *tctx){
	return CONFD_OK;
}

/********************************************************************/




/********************************************************************/
/* data callbacks that manipulate the db */

/* keypath tells us the path choosen down the XML tree */
/* We need to return a list of all server keys here */

static int reteof(struct confd_trans_ctx *tctx){
	confd_data_reply_next_key(tctx, NULL, -1, -1);
	return CONFD_OK;
}

static int capability_get_next(struct confd_trans_ctx *tctx,
						 confd_hkeypath_t *keypath,
						 long next){
	printf("\ncapability get next\n");
	confd_value_t v;
	Dlist *list;
	struct capability *capa;
	ccp_calls.get_next++;
	if (next == -1 && !dl_empty(running_db)) {  /* Get first key */
		Dlist *first = dl_first(running_db);
		capa = (struct capability*) first->val;
		CONFD_SET_STR(&v, capa->name);
		/* Use  real ptr as next  */
		confd_data_reply_next_key(tctx, &v, 1, (long) dl_next(first));
		return CONFD_OK;
	}
	if (next == -1) {  /* First key from empty DB, */
		return reteof(tctx);
	}
	else {
		if ((list = (Dlist*) next) == running_db) {
			/* we went all the way around */
			return reteof(tctx);
		}
		capa = (struct capability*) list->val;
		CONFD_SET_STR(&v, capa->name);
		/* Use  real ptr as next  */
		confd_data_reply_next_key(tctx, &v, 1, (long) dl_next(list));
		return CONFD_OK;
	}
}

static int capability_num_instances(struct confd_trans_ctx *tctx,
							  confd_hkeypath_t *keypath){
	confd_value_t v;
	int cnt;
	Dlist *item;
	ccp_calls.num_instances++;

	cnt = 0;
	dl_traverse(item, running_db) {
		cnt++;
	}

	CONFD_SET_INT32(&v, cnt);
	confd_data_reply_value(tctx, &v);
	return CONFD_OK;
}

/* keypath here will look like */
/* /capabilitys/capability{mycapabilityname}/interfaces/interface */



static int capability_get_elem(struct confd_trans_ctx *tctx,
						 confd_hkeypath_t *keypath){
	printf("\ncapability get elem call\n");
	confd_value_t v;
	struct capability *capa;
	Dlist *list = find_capability(running_db, &(keypath->v[1][0]));
	//Dlist *list = find_min_usage(running_db);
	// Dlist *list;
	ccp_calls.get_elem++;

	if (list ==  NULL) {
		confd_data_reply_not_found(tctx);
		return CONFD_OK;
	}
	capa = (struct capability*) list->val;
	/* switch on xml elem tag */
	
	switch (CONFD_GET_XMLTAG(&(keypath->v[0][0]))) {	// keypath->v[0][0] capa_name
		case i2nsf_capability_nsf_name:
			CONFD_SET_STR(&v, capa->name);
			printf("get name");
			break;
		case i2nsf_capability_ipv4_address:
			CONFD_SET_IPV4(&v, capa->ipv4_addr);
			printf("get ipv4_addr");
			break;
		default:
			fprintf(stderr,"HERE %d\n", CONFD_GET_XMLTAG(&(keypath->v[0][0])));
			return CONFD_ERR;
	}
	
	confd_data_reply_value(tctx, &v);
	return CONFD_OK;
}

/* assuming the name of the capability being configured is "earth"     */
/* the keypaths we get here will be like :                       */
/* /capabilitys/capability{earth}/interfaces/interface{eth0}/ip              */
/*   [6]  [5]   [4]     [3]        [2]     [1]   [0]             */
/* thus keypath->v[4][0] will refer to the name of the           */
/* capability being configured                                         */
/* and  keypath->v[1][0] will refer to the name of the interface */
/* being configured                                              */




static int capability_set_elem(struct confd_trans_ctx *tctx,
						 confd_hkeypath_t *keypath,
						 confd_value_t *newval){
	ccp_calls.set_elem++;
	return CONFD_ACCUMULATE;
}
static int capability_create(struct confd_trans_ctx *tctx,
					   confd_hkeypath_t *keypath){
	ccp_calls.create++;
	return CONFD_ACCUMULATE;
}

static int capability_delete(struct confd_trans_ctx *tctx,
					   confd_hkeypath_t *keypath){
	ccp_calls.remove++;
	return CONFD_ACCUMULATE;
}



/* Initialize db to 2 capabilitys */
static Dlist *default_db(){
	struct capability *head;
	// struct capability *firewall3;
	Dlist *list;
	list = new_dlist();
	head = new_capability("head", "0.0.0.0");
	// firewall2 = new_capability("firewall2", "10.0.0.130");
	dl_append(list, head);
	// dl_append(list, firewall2);
	return list;
}


/********************************************************************/

void start_confd(){
	int ctlsock;
	int workersock;
	struct sockaddr_in addr;
	struct mydata *md;
	int debuglevel = CONFD_TRACE;



	/* These are our transaction callbacks */
	trans.init = tr_init;
	trans.write_start = tr_writestart;
	trans.prepare = tr_prepare;
	trans.commit = tr_commit;
	trans.abort = tr_abort;
	trans.finish = tr_finish;


	/* And finallly these are our read/write callbacks for  */
	/* the database */
	capa_cbks.get_elem = capability_get_elem;
	capa_cbks.get_next = capability_get_next;
	capa_cbks.num_instances = capability_num_instances;
	capa_cbks.set_elem = capability_set_elem;
	capa_cbks.create   = capability_create;
	capa_cbks.remove   = capability_delete;
	strcpy(capa_cbks.callpoint, "ccp");


	/* Init library  */
	confd_init("capability_daemon", stderr, debuglevel);
	/* Init simple DB*/
	running_db = default_db();
	show_db(running_db);


	

	/* Initialize daemon context */
	if ((dctx = confd_init_daemon("capability_daemon")) == NULL)
		confd_fatal("Failed to initialize confd\n");

	if ((ctlsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
		confd_fatal("Failed to open ctlsocket\n");
	
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_family = AF_INET;
	addr.sin_port = htons(CONFD_PORT);
	printf("%10d %10d",addr.sin_addr.s_addr,addr.sin_port);
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

	/* we also need to register our read/write callbacks */

	if (confd_register_data_cb(dctx, &capa_cbks) == CONFD_ERR)
		confd_fatal("Failed to register capability cb \n");

	if (confd_register_done(dctx) != CONFD_OK)
		confd_fatal("Failed to complete registration \n");


	while (1) {
		struct pollfd set[2];
		int ret;

		set[0].fd = ctlsock;
		set[0].events = POLLIN;
		set[0].revents = 0;

		set[1].fd = workersock;
		set[1].events = POLLIN;
		set[1].revents = 0;


		if (poll(&set[0], 2, -1) < 0) {
			perror("Poll failed:");
			continue;
		}
		// printf("after poll\n");
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
