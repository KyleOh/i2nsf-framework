if [ "$#" -lt 1 ] 
	then
		echo "Usage: ./lookUpSwitchFlowRules.sh [switch number]"
		exit 1
fi

wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/0 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/1 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/2 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/3 --password=admin --user=admin
#\wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/4 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/5 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/6 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/7 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/8 --password=admin --user=admin
#wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/9 --password=admin --user=admin
wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/10 --password=admin --user=admin
