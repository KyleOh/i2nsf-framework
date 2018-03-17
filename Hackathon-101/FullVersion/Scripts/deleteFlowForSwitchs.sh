#~/bin/sh

curl -X "DELETE" -H "Content-Type: application/xml" "http://127.0.0.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1" -v -u admin:admin

curl -X "DELETE" -H "Content-Type: application/xml" "http://127.0.0.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:2" -v -u admin:admin

curl -X "DELETE" -H "Content-Type: application/xml" "http://127.0.0.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:3" -v -u admin:admin

curl -X "DELETE" -H "Content-Type: application/xml" "http://127.0.0.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:4" -v -u admin:admin
#curl -X "DELETE" -H "Content-Type: application/xml" "http://127.0.0.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/Test2" -v -u admin:admin
#curl -X "DELETE" -H "Content-Type: application/xml" "http://127.0.0.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/Test3" -v -u admin:admin
#curl -X "DELETE" -H "Content-Type: application/xml" "http://127.0.0.1:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/Test4" -v -u admin:admin


