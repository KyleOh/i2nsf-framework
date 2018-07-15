#~/bin/sh




if [ "$#" -lt 2 ]; then
    echo "Usage: ./sendFlowScript.sh [PUT or DELETE] [IP Address with port of controller]"
    exit 1
fi


######################internetwork##################################

#1 VPN Path  : switch3(2->5)(1) -> switch 4(6->1)(2) -> switch 4(1->4)(3) -> switch 4(4->6)(4) -> switch 3(5->1)
#firewall->webfilter


curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/VPN01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>VPN01</flow-name><id>VPN01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:5</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type>
<ethernet-source><address>00:00:00:00:11:55</address></ethernet-source>
</ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
:<in-port>openflow:3:2</in-port></match></flow>'


###################################
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/KOKO" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>KOKO</flow-name><id>KOKO</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:6</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type>
#<ethernet-source><address>00:00:00:00:11:55</address></ethernet-source>
#</ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><ipv4-source>10.0.0.155/8</ipv4-source>
#<in-port>openflow:3:1</in-port></match></flow>'



###################################

curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/VPN02" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory">
<strict>false</strict><flow-name>VPN02</flow-name><id>VPN02</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:1</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:11:55</address></ethernet-source>
</ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:4:6</in-port></match></flow>'


curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/VPN03" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><id>VPN03</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw>
<instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:4</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><priority>200</priority>
<match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source>
<address>00:00:00:00:11:55</address></ethernet-source></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:4:1</in-port></match><flow-name>VPN03</flow-name></flow>'



curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/VPN04" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory">
<strict>false</strict><flow-name>VPN04</flow-name><id>VPN04</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:6</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:4:4</in-port></match></flow>'


#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/VPN05" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory">
#<strict>false</strict><flow-name>VPN05</flow-name><id>VPN05</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:1</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><ipv4-source>10.0.0.155/8</ipv4-source>
#<in-port>openflow:3:5</in-port></match></flow>'



#nat -> vpn
#switch 3(1->2)

#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/VPN06" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory">
#<strict>false</strict><flow-name>VPN06</flow-name><id>VPN06</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:2</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><ipv4-destination>10.0.0.155/8</ipv4-destination>
#<in-port>openflow:3:1</in-port></match></flow>'





#sudo ./ PUT 127.0.0.1:8181

#firewall2 -> mail ...hhhhhhhh ( smes )


#smes path : switch1(1->3)(1) -> switch2(1->3)(2) -> switch4(5->2)(3) -> switch4(2->3)(4) ->switch4(3->6)(5) -> switch3(5->1)(6)
#source ip : 10.0.0.2/8
#ipproto : 1 



curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/SMES01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES01</flow-name><id>SMES01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:3</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:1:1</in-port></match></flow>'

#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/SMES99" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES99</flow-name><id>SMES99</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:3</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
#<ipv4-source>10.0.0.2/8</ipv4-source>
#<in-port>openflow:1:2</in-port></match></flow>'



curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/SMES02" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES02</flow-name><id>SMES02</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>3</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:2:1</in-port></match></flow>'

curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/SMES03" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES03</flow-name>
<id>SMES03</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:2</output-node-connector><max-length>65535</max-length>
</output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:4:5</in-port></match></flow>'

curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/SMES04" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES04</flow-name><id>SMES04</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:3</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:4:2</in-port></match></flow>'


curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/SMES05" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES05</flow-name><id>SMES05</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:6</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:4:3</in-port></match></flow>'


#switch3(5->1)(6)
 curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/SMES06" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES06</flow-name><id>SMES06</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:1</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
<in-port>openflow:3:5</in-port></match></flow>'


#nat -> smes
#switch 3(1->3)(7) -> switch1(4->1)(8)
 #curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/SMES07" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES07</flow-name><id>SMES07</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:3</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-destination><address>00:00:00:00:00:22</address></ethernet-destination></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
#<ipv4-destination>10.0.0.2/8</ipv4-destination>
#<in-port>openflow:3:1</in-port></match></flow>'


# curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/SMES08" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES08</flow-name><id>SMES08</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:1</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-destination><address>00:00:00:00:00:22</address></ethernet-destination></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match>
#<ipv4-destination>10.0.0.2/8</ipv4-destination>
#<in-port>openflow:1:4</in-port></match></flow>'



###############################UDP######################################################################
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/VPN01UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>VPN01UDP</flow-name><id>VPN01UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:5</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type>
<ethernet-source><address>00:00:00:00:11:55</address></ethernet-source>
</ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
:<in-port>openflow:3:2</in-port></match></flow>'


###################################
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/KOKO" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>KOKO</flow-name><id>KOKO</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:6</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type>
#<ethernet-source><address>00:00:00:00:11:55</address></ethernet-source>
#</ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match><ipv4-source>10.0.0.155/8</ipv4-source>
#<in-port>openflow:3:1</in-port></match></flow>'



###################################

curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/VPN02UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory">
<strict>false</strict><flow-name>VPN02UDP</flow-name><id>VPN02UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:1</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:11:55</address></ethernet-source>
</ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:4:6</in-port></match></flow>'


curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/VPN03UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><id>VPN03UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw>
<instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:4</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><priority>200</priority>
<match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source>
<address>00:00:00:00:11:55</address></ethernet-source></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:4:1</in-port></match><flow-name>VPN03UDP</flow-name></flow>'



curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/VPN04UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory">
<strict>false</strict><flow-name>VPN04UDP</flow-name><id>VPN04UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:6</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:4:4</in-port></match></flow>'


#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/VPN05UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory">
#<strict>false</strict><flow-name>VPN05UDP</flow-name><id>VPN05UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:1</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match><ipv4-source>10.0.0.155/8</ipv4-source>
#<in-port>openflow:3:5</in-port></match></flow>'



#nat -> vpn
#switch 3(1->2)

#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/VPN06UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory">
#<strict>false</strict><flow-name>VPN06UDP</flow-name><id>VPN06UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:2</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match><ipv4-destination>10.0.0.155/8</ipv4-destination>
#<in-port>openflow:3:1</in-port></match></flow>'





#sudo ./ PUT 127.0.0.1:8181

#firewall2 -> mail ...hhhhhhhh ( smes )


#smes path : switch1(1->3)(1) -> switch2(1->3)(2) -> switch4(5->2)(3) -> switch4(2->3)(4) ->switch4(3->6)(5) -> switch3(5->1)(6)
#source ip : 10.0.0.2/8
#ipproto : 1 



curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/SMES01UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES01UDP</flow-name><id>SMES01UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:3</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:1:1</in-port></match></flow>'

#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/SMES99UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES99UDP</flow-name><id>SMES99UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:3</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
#<ipv4-source>10.0.0.2/8</ipv4-source>
#<in-port>openflow:1:2</in-port></match></flow>'



curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/SMES02UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES02UDP</flow-name><id>SMES02UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>3</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:2:1</in-port></match></flow>'

curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/SMES03UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES03UDP</flow-name>
<id>SMES03UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:2</output-node-connector><max-length>65535</max-length>
</output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:4:5</in-port></match></flow>'

curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/SMES04UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES04UDP</flow-name><id>SMES04UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:3</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-source><address>00:00:00:00:00:22</address></ethernet-source></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:4:2</in-port></match></flow>'


curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/SMES05UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES05UDP</flow-name><id>SMES05UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:6</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:4:3</in-port></match></flow>'


#switch3(5->1)(6)
 curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/SMES06UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES06UDP</flow-name><id>SMES06UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:1</output-node-connector><max-length>65535</max-length></output-action>
</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
<in-port>openflow:3:5</in-port></match></flow>'


#nat -> smes
#switch 3(1->3)(7) -> switch1(4->1)(8)
 #curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/SMES07UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES07UDP</flow-name><id>SMES07UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:3</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-destination><address>00:00:00:00:00:22</address></ethernet-destination></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
#<ipv4-destination>10.0.0.2/8</ipv4-destination>
#<in-port>openflow:3:1</in-port></match></flow>'


# curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/SMES08UDP" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
#<flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>SMES08UDP</flow-name><id>SMES08UDP</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id>
#<priority>200</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout>
#<installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:1</output-node-connector><max-length>65535</max-length></output-action>
#</action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type><ethernet-destination><address>00:00:00:00:00:22</address></ethernet-destination></ethernet-match><ip-match><ip-protocol>17</ip-protocol></ip-match>
#<ipv4-destination>10.0.0.2/8</ipv4-destination>
#<in-port>openflow:1:4</in-port></match></flow>'