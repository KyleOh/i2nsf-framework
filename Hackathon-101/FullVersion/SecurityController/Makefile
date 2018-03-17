######################################################################
# Introduction example 6-c_config
# (C) 2006 Tail-f Systems
#
# See the README file for more information
######################################################################

usage:
	@echo "See README file for more instructions"
	@echo "make all     Build all example files"
	@echo "make clean   Remove all built and intermediary files"
	@echo "make start   Start CONFD daemon and example agent"
	@echo "make stop    Stop any CONFD daemon and example agent"
	@echo "make query   Run query against CONFD"
	@echo "make cli     Start the CONFD Command Line Interface, J-style"
	@echo "make cli-c   Start the CONFD Command Line Interface, C-style"



######################################################################
# Where is ConfD installed? Make sure CONFD_DIR points it out
CONFD_DIR ?= ../../../../confd-6.2/
INTERFACE_DIR ?= ../Interfaces
BINARY_DIR ?= ../bin
# Include standard ConfD build definitions and rules
include $(CONFD_DIR)/src/confd/build/include.mk

# In case CONFD_DIR is not set (correctly), this rule will trigger
$(CONFD_DIR)/src/confd/build/include.mk:
	@echo 'Where is ConfD installed? Set $$CONFD_DIR to point it out!'
	@echo ''

######################################################################
# Example specific definitions and rules

CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd 
START_FLAGS ?=

LIBS    += -lmysqlclient
SRC	= main.c developer-secu-controller-interface.c dlist.c
OBJS	= developer-secu-controller-interface.o main.o dlist.o#$(SRC:.c=.o)

all:	i2nsf-capability.fxs i2nsf-capability.h dlist.h dlist $(CDB_DIR) ssh-keydir developer-secu-controller-interface.h developer-secu-controller-interface.c main securitycontroller 
	@echo $(OBJS)
	@echo "Build complete"

securitycontroller: $(OBJS)
	$(CC) -o ../bin/securitycontroller $(OBJS) $(LIBS)

main: 
	$(CC) -c main.c

dlist: ./dlist.h
	$(CC) -c dlist.c
	@echo "dlist Build complete"

developer-secu-controller-interface: ./developer-secu-controller-interface.h ./dlist.h
	$(CC) -c developer-secu-controller-interface.c -Wall -g -I ../../../confd-6.2/include
	@echo "developer-secu-controller-Interface Build complete"


######################################################################
clean:	iclean
	-rm -rf i2nsf-capability.h *_ns.py *.pyc 2> /dev/null || true
	-rm -rf *.o
	-rm -rf ../bin/securitycontroller

init:  stop 
	@echo $(CONFD)
	@echo $(CONFD_FLAGS)
	@echo $(KILL_ALL)
	$(CONFD)  -c confd.conf $(CONFD_FLAGS)

############################################################
start: stop init start_capa

start_capa: 
	../bin/securitycontroller $(START_FLAGS)
##################################################################
cli-c:
	$(CONFD_DIR)/bin/confd_cli -C --user==admin --groups==admin \
		--interactive || echo Exit
######################################################################
stop:
	### Killing any confd daemon and HOSTS confd agents
	$(CONFD) --stop || true
	$(KILLALL) hosts || true 
