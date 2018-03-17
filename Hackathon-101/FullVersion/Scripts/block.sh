#~/bin/sh

if [ "$#" -lt 2 ]; then
    echo "Usage: ./sendFlowScript.sh [PUT or DELETE] [IP Address with port of controller]"
    exit 1
fi


###################### IP ##################################

# Switch_2 -> SFF
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/IP05" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>IP05</flow-name><id>IP05</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions>
<action><order>0</order><output-action><output-node-connector>openflow:2:2</output-node-connector><max-length>65535</max-length></output-action></action>
<action><order>1</order><output-action><output-node-connector>openflow:2:5</output-node-connector><max-length>65535</max-length></output-action></action>
<action><order>2</order><output-action><output-node-connector>openflow:2:6</output-node-connector><max-length>65535</max-length></output-action></action>
</apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>146</ip-protocol></ip-match><in-port>openflow:2:1</in-port></match></flow>'
