import urllib2
import requests
import socket
import json
import MySQLdb #DB
import os
import sys
import time
import socket
import threading

# data list for extracting
extractedinfo = ['rule-name', 'start-time', 'end-time', 'rule-case', 'source', 'destination', 'action-name']
extractedlist = []
for i in range(len(extractedinfo)):
    extractedlist.append('')

# data list for NSF data
nsfrequiredinfo = ['rule-name', 'start-time', 'end-time', 'mail-filtering', 'pkt-sec-cond-ipv4-src', 'user-defined-category', 'pkt-payload-content', 'ingress-action-type']
nsfrequiredlist = []
for i in range(len(nsfrequiredinfo)):
    nsfrequiredlist.append('')

# call data of proper field
def usedata(field):
    global extractedinfo
    global extractedlist
    return extractedlist[extractedinfo.index(field)]

# call data of proper field in NSF data
def usensfdata(field):
    global nsfrequiredinfo
    global nsfrequiredlist
    return nsfrequiredlist[nsfrequiredinfo.index(field)]

# DFA node for extractor
class DFAnode:
    def __init__(self, nodetype):
        self.nodetype = nodetype
        self.taglist = []
        self.pointlist = []
        self.info = ''

    def setinfo(self, info):
        self.info = info

    def connectNode(self, lowerNode, tag):
        self.pointlist.append(lowerNode)
        self.taglist.append('<'+tag+'>')
        lowerNode.pointlist.append(self)
        lowerNode.taglist.append('</'+tag+'>')

    def sendString(self, string_in):
        for i in range(len(self.taglist)):
            if string_in.startswith(self.taglist[i]):
                return [True, string_in[len(self.taglist[i]):], self.pointlist[i]]
        return [False]

    def extract(self, string_in):  
        global extractedinfo
        global extractedlist
        i = 0
        while string_in[i] != '<' or i >= len(string_in):
            i = i+1
        if i < len(string_in):
            extractedlist[extractedinfo.index(self.info)] = string_in[0:i]
            return string_in[i:]
        else:
            return ''

# Grammar for generator
class TextfreeGrammar:
    def __init__(self, grammartype, datalist, starttag, endtag):
        self.grammartype = grammartype
        self.datalist = datalist
        self.starttag = starttag
        self.endtag = endtag

    def translate(self, level):
        string_out = ''
        if self.grammartype == 'structure':
            for i in range(level):
                string_out += '\t'
            string_out += self.starttag+'\n'
            for i in range(len(self.datalist)):
                string_out += self.datalist[i].translate(level+1)+'\n'
            for i in range(level):
                string_out += '\t'
            string_out += self.endtag
        else:
            for i in range(len(self.datalist)):
                for j in range(level):
                    string_out += '\t'
                string_out += self.starttag
                string_out += self.datalist[i]
                string_out += self.endtag
                if i!=len(self.datalist)-1:
                    string_out += '\n'
        return string_out

# NSF capabilities
host = 'localhost'
port = 8000
TCP_IP = '127.0.0.1'
TCP_PORT = 6000
BUFFER_SIZE = 1024  # Normally 1024, but we want fast response
cnt=0

nsf_namelist = []
nsf_iplist = []
nsf_capabilitylist = []

def json2xml(json_obj, line_padding=""):
	result_list = list()
	global cnt
	json_obj_type = type(json_obj)
	if cnt==0:
		result_list.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
		cnt+=1
	if json_obj_type is list:
		for sub_elem in json_obj:
			result_list.append(json2xml(sub_elem, line_padding))

		return "\n".join(result_list)

	if json_obj_type is dict:
		for tag_name in json_obj:
			sub_obj = json_obj[tag_name]
			result_list.append("%s<%s>" % (line_padding, tag_name))
			result_list.append(json2xml(sub_obj, "\t" + line_padding))
			result_list.append("%s</%s>" % (line_padding, tag_name))

		return "\n".join(result_list)

	return "%s%s" % (line_padding, json_obj)


xml_header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
xml_header += "<capabilities>\n <capability>urn:ietf:params:netconf:base:1.0</capability>\n</capabilities>\n</hello>\n"
xml_header += "]]>]]>\n"
xml_header += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rpc message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
xml_header += "<edit-config>\n<target>\n<running />\n</target>\n<config>\n<i2nsf-security-policy xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-policy-rule-for-nsf\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"

xml_tail = "\n</i2nsf-security-policy>\n</config>\n</edit-config>\n</rpc>\n]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
xml_tail += "<rpc message-id=\"2\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n<close-session />\n</rpc>\n]]>]]>>"

# extractor construction
node_accepter = DFAnode('accepter')
node_I2NSF = DFAnode('middle')
node_rule = DFAnode('middle')
node_rule_name = DFAnode('extractor')
node_event = DFAnode('middle')
node_start_time = DFAnode('extractor')
node_end_time = DFAnode('extractor')
node_condition = DFAnode('middle')
node_rule_case = DFAnode('extractor')
node_source = DFAnode('extractor')
node_destination = DFAnode('extractor')
node_action = DFAnode('middle')
node_action_name = DFAnode('extractor')
node_time_information = DFAnode('middle')

node_rule_name.setinfo('rule-name')
node_rule_case.setinfo('rule-case')
node_action_name.setinfo('action-name')
node_end_time.setinfo('end-time')
node_start_time.setinfo('start-time')
node_source.setinfo('source')
node_destination.setinfo('destination')

node_accepter.connectNode(node_I2NSF, 'i2nsf:Policy')
node_I2NSF.connectNode(node_rule, 'rule')

node_rule.connectNode(node_rule_name, 'rule-name')
node_rule.connectNode(node_action, 'action')
node_rule.connectNode(node_event, 'event')
node_rule.connectNode(node_condition, 'condition')

node_action.connectNode(node_action_name, 'action-name')
node_event.connectNode(node_time_information, 'time-information')
node_time_information.connectNode(node_end_time, 'end-time')
node_time_information.connectNode(node_start_time, 'start-time')
node_condition.connectNode(node_source, 'source')
node_condition.connectNode(node_destination, 'destination')
node_condition.connectNode(node_rule_case, 'rule-case')


# open server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(0)

def receive_capa():
    global nsf_namelist
    global nsf_iplist
    global nsf_capabilitylist
    global nsfrequiredinfo
    while True:
        s = socket.socket()
        host = socket.gethostname()
        port = 55552
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host,port))
        s.listen(5)
        conn, addr = s.accept()
        data = conn.recv(1024)
        data = list(str(data).split(','))
        #register_log = open('nsf_register_log.txt', 'a')
        print('New NSF and capabilities are registered!')
        #register_log.write('New NSF and capabilities are registered!\n')
        print('New NSF name: '+data[0])
        print('New NSF ip: '+data[1])
        #register_log.write('New NSF name: '+data[0]+'\nNew NSF ip: '+data[1]+'\n')
        nsf_namelist.append(data[0])
        nsf_iplist.append(data[1])
        print('NSF capabilities:')
        #register_log.write('NSF capabilities:\n')
        temp_nsf_capa = []
        for i in range(2, len(data)):
            print(data[i])
            #register_log.write(data[i]+'\n')
            temp_nsf_capa.append(data[i])
        nsf_capabilitylist.append(temp_nsf_capa)
        #register_log.close()
        print('\n')

threading._start_new_thread(receive_capa, ())

while True:
        client_socket, addr = server_socket.accept()
        tag = client_socket.recv(4096)
        print(tag)
        
        if tag == '1':
            response = os.popen("curl --ipv4 --http2 -k --cert-type PEM -E /works/jetconf/data/example-client.pem -X GET https://localhost:8443/restconf/data/i2nsf:Policy").read()
	    #print(response)
	    response = json.loads(response)
	    
            if response["i2nsf:Policy"]["rule"]:
                rname = response["i2nsf:Policy"]["rule"][0]["rule-name"]
                os.system("curl --ipv4 --http2 -k --cert-type PEM -E /works/jetconf/data/example-client.pem -X DELETE $POST_DATA https://127.0.0.1:8443/restconf/data/i2nsf:Policy/rule=%s"%rname)
            if response["i2nsf:Policy"]["rule"]:
                data = json2xml(response)
                cnt = 0
                print('received xml file:\n')
                print(data)

            # eliminate <?xml version="1.0" encoding="UTF-8"?>
            if data.startswith('<?xml version=\"1.0\" encoding=\"UTF-8\"?>'):
                temp_index = 0
                while data[temp_index] != '>':
                    temp_index += 1
                data = data[temp_index+1:]
            print(data)

            # eliminate all of spaces
            string_policy = ''.join(data.split())

            # extracting
            extractedlist = []
            for i in range(len(extractedinfo)):
                extractedlist.append('')
            currentState = [True, string_policy, node_accepter]
            extractingFlag = False
            while True:
                currentState = currentState[2].sendString(currentState[1])
                if currentState[0] == False:
                    print('Wrong Grammar!')
                    break
                elif currentState[2].nodetype == 'accepter':
                    print('Success to extract all!')
                    extractingFlag = True
                    break
                elif currentState[2].nodetype == 'extractor':
                    remain = currentState[2].extract(currentState[1])
                    if remain == '':
                        print('Fail to extract!')
                        break
                    else:
                        currentState[1] = remain

	    # debug extracted data
            if currentState[0] == True:
                print('Rule name: '+usedata('rule-name'))
                print('Start time: '+usedata('start-time'))
                print('End time: '+usedata('end-time'))
                print('Rule case: '+usedata('rule-case'))
                print('Source: '+usedata('source'))
                print('Destination: '+usedata('destination'))
                print('Action: '+usedata('action-name'))
                print('\n')
                
                # convert extracted data list 
                """
                empdb = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Position")
                empcur = empdb.cursor()
                empcur.execute("SELECT Employee_IP from Policies2 where Position='"+usedata('source')+"'")
                rows = empcur.fetchall()
                temp_iplist = []
                for i in range(len(rows)):
                    temp_iplist.append(rows[i][0])
                """

                nsfrequiredlist = []
                for i in range(len(nsfrequiredinfo)):
                    if nsfrequiredinfo[i] == 'pkt-sec-cond-ipv4-src' or nsfrequiredinfo[i] == 'ingress-action-type':
                        nsfrequiredlist.append([])
                    else:
                        nsfrequiredlist.append('')
                for i in range(len(extractedinfo)):
                    if extractedlist[i] != '':
                        if extractedinfo[i] == 'rule-name':
                            for j in range(len(nsfrequiredinfo)):
                                if nsfrequiredinfo[j] == 'rule-name':
                                    nsfrequiredlist[j] = extractedlist[i]
                                    break
                        elif extractedinfo[i] == 'start-time' or extractedinfo[i] == 'end-time':
                            for j in range(len(nsfrequiredinfo)):
                                if nsfrequiredinfo[j] == extractedinfo[i]:
                                    nsfrequiredlist[j] = '2018-07-14T'+extractedlist[i]+':00Z'
                                    break
                        elif extractedinfo[i] == 'rule-case':
                            for j in range(len(nsfrequiredinfo)):
                                if nsfrequiredinfo[j] == 'mail-filtering':
                                    nsfrequiredlist[j] = extractedlist[i]+'_filter'
                                    break
                        elif extractedinfo[i] == 'source':
                            for j in range(len(nsfrequiredinfo)):
                                if nsfrequiredinfo[j] == 'pkt-sec-cond-ipv4-src':
                                    nsfrequiredlist[j].append('10.0.0.155')
                                    nsfrequiredlist[j].append('10.0.0.2')
                                    break
                        elif extractedinfo[i] == 'destination':
                            for j in range(len(nsfrequiredinfo)):
                                if nsfrequiredinfo[j] == 'user-defined-category' and usedata('rule-case') == 'web':
                                    nsfrequiredlist[j] = extractedlist[i]
                                    break
                                if nsfrequiredinfo[j] == 'pkt-payload-content' and usedata('rule-case') == 'mail':
                                    nsfrequiredlist[j] = extractedlist[i]
                                    break
                        elif extractedinfo[i] == 'action-name':
                            for j in range(len(nsfrequiredinfo)):
                                if nsfrequiredinfo[j] == 'ingress-action-type':
                                    xxx = extractedlist[i].split(',')
                                    xxx.pop()
                                    for k in range(len(xxx)):
                                        if xxx[k] == 'permit':
                                            xxx[k] = 'pass'
                                        elif xxx[k] == 'deny':
                                            xxx[k] = 'reject'
                                    for k in range(len(xxx)):
                                        nsfrequiredlist[j].append(xxx[k])
                                    break



                # construct grammar for generating low-level policy
                # policy for firewall
                firewallindex = -1
                filterindex = -1
                grammar_rule_name = TextfreeGrammar('content', [usensfdata('rule-name')], '<rule-name>', '</rule-name>')
                grammar_total_structure_list = [grammar_rule_name]
                if usensfdata('pkt-sec-cond-ipv4-src'): 
                    grammar_ipv4_src = TextfreeGrammar('content', usensfdata('pkt-sec-cond-ipv4-src'), '<pkt-sec-cond-ipv4-src>', '</pkt-sec-cond-ipv4-src>')
                    grammar_ipv4_temp1 = TextfreeGrammar('structure', [grammar_ipv4_src], '<packet-security-ipv4-condition>', '</packet-security-ipv4-condition>')
                    grammar_ipv4_temp2 = TextfreeGrammar('structure', [grammar_ipv4_temp1], '<packet-security-condition>', '</packet-security-condition>')
                    grammar_condition_clause = TextfreeGrammar('structure', [grammar_ipv4_temp2], '<condition-clause-container>', '</condition-clause-container>')
                    grammar_total_structure_list.append(grammar_condition_clause)
                
                temp_grammar_list = []
                if len(usensfdata('ingress-action-type')) > 1:
                    grammar_ingress_action_type = TextfreeGrammar('content', [usensfdata('ingress-action-type')[1]], '<ingress-action-type>', '</ingress-action-type>')
                    grammar_ingress = TextfreeGrammar('structure', [grammar_ingress_action_type], '<ingress-action>', '</ingress-action>')
                    temp_grammar_list.append(grammar_ingress)
                if usensfdata('mail-filtering') != '':
                    grammar_mail_filtering = TextfreeGrammar('content', [usensfdata('mail-filtering')], '<mail-filtering>', '</mail-filtering>')
                    grammar_mail_temp1 = TextfreeGrammar('structure', [grammar_mail_filtering], '<content-security-control-types>', '</content-security-control-types>')
                    grammar_mail_temp2 = TextfreeGrammar('structure', [grammar_mail_temp1], '<content-security-control>', '</content-security-control>')
                    grammar_mail_temp3 = TextfreeGrammar('structure', [grammar_mail_temp2], '<apply-profile>', '</apply-profile>')
                    temp_grammar_list.append(grammar_mail_temp3)
                if temp_grammar_list:
                    grammar_action_clause = TextfreeGrammar('structure', temp_grammar_list, '<action-clause-container>', '</action-clause-container>')
                    grammar_total_structure_list.append(grammar_action_clause)

                if usensfdata('start-time') != '':
                    for i in range(len(nsf_namelist)):
                        for j in range(len(nsf_capabilitylist[i])):
                            if nsf_capabilitylist[i][j] == 'start-time':
                                firewallindex = i
                                break
                        if firewallindex != -1:
                            break
                    grammar_start_time = TextfreeGrammar('content', [usensfdata('start-time')], '<start-time>', '</start-time>')
                    grammar_time_templist = [grammar_start_time]
                    if usensfdata('end-time') != '':
                        grammar_end_time = TextfreeGrammar('content', [usensfdata('end-time')], '<end-time>', '</end-time>')
                        grammar_time_templist.append(grammar_end_time)
                    grammar_time_temp1 = TextfreeGrammar('structure', grammar_time_templist, '<time>', '</time>')
                    grammar_time_temp2 = TextfreeGrammar('structure', [grammar_time_temp1], '<absolute-time-zone>', '</absolute-time-zone>')
                    grammar_time_zone = TextfreeGrammar('structure', [grammar_time_temp2], '<time-zone>', '</time-zone>')
                    grammar_total_structure_list.append(grammar_time_zone)
                else:
                    for i in range(len(nsf_namelist)):
                        istimeexist = False
                        issrcexist = False
                        for j in range(len(nsf_capabilitylist[i])):
                            if nsf_capabilitylist[i][j] == 'start-time':
                                istimeexist = True
                                break
                            if nsf_capabilitylist[i][j] == 'pkt-sec-cond-ipv4-src':
                                issrcexist = True
                        if istimeexist == False and issrcexist == True:
                            firewallindex = i
                            break

                grammar_rules = TextfreeGrammar('structure', grammar_total_structure_list, '<rules nc:operation=\"create\">', '</rules>')
                print('Target IP is '+nsf_iplist[firewallindex]+'\nFirewall policy:')
                generated_firewall_policy = xml_header + grammar_rules.translate(0)+xml_tail
                print(generated_firewall_policy)

                # policy for filter
                grammar_rule_name = TextfreeGrammar('content', [usensfdata('rule-name')], '<rule-name>', '</rule-name>')
                grammar_total_structure_list = [grammar_rule_name]

                if usensfdata('pkt-sec-cond-ipv4-src'):
                    grammar_ipv4_src = TextfreeGrammar('content', usensfdata('pkt-sec-cond-ipv4-src'), '<pkt-sec-cond-ipv4-src>', '</pkt-sec-cond-ipv4-src>')
                    grammar_ipv4_temp1 = TextfreeGrammar('structure', [grammar_ipv4_src], '<packet-security-ipv4-condition>', '</packet-security-ipv4-condition>')
                    grammar_ipv4_temp2 = TextfreeGrammar('structure', [grammar_ipv4_temp1], '<packet-security-condition>', '</packet-security-condition>')
                    grammar_templist = [grammar_ipv4_temp2]
                    if usensfdata('user-defined-category') != '':
                        for i in range(len(nsf_namelist)):
                            for j in range(len(nsf_capabilitylist[i])):
                                if nsf_capabilitylist[i][j] == 'user-defined-category':
                                    filterindex = i
                                    break
                            if filterindex != -1:
                                break
                        grammar_destination = TextfreeGrammar('content', [usensfdata('user-defined-category')], '<user-defined-category>', '</user-defined-category>')
                        grammar_dest_temp = TextfreeGrammar('structure', [grammar_destination], '<url-category-condition>', '</url-category-condition>')
                        grammar_templist.append(grammar_dest_temp)
                    elif usensfdata('pkt-payload-content') != '':
                        for i in range(len(nsf_namelist)):
                            for j in range(len(nsf_capabilitylist[i])):
                                if nsf_capabilitylist[i][j] == 'pkt-payload-content':
                                    filterindex = i
                                    break
                            if filterindex != -1:
                                break
                        grammar_destination = TextfreeGrammar('content', [usensfdata('pkt-payload-content')], '<pkt-payload-content>', '</pkt-payload-content>')
                        grammar_dest_temp = TextfreeGrammar('structure', [grammar_destination], '<packet-payload-condition>', '</packet-payload-condition>')
                        grammar_templist.append(grammar_dest_temp)
                    else:
                        if usensfdata('start-time') == '':
                            for i in range(len(nsf_namelist)):
                                for j in range(len(nsf_capabilitylist[i])):
                                    if nsf_capabilitylist[i][j] == 'pkt-payload-content':
                                        filterindex = i
                                        break
                                if filterindex != -1:
                                    break
                        else:
                            for i in range(len(nsf_namelist)):
                                for j in range(len(nsf_capabilitylist[i])):
                                    if nsf_capabilitylist[i][j] == 'user-defined-category':
                                        filterindex = i
                                        break
                                if filterindex != -1:
                                    break

                    grammar_condition_clause = TextfreeGrammar('structure', grammar_templist, '<condition-clause-container>', '</condition-clause-container>')
                    grammar_total_structure_list.append(grammar_condition_clause)

                if usensfdata('ingress-action-type'):
                    grammar_ingress_action = TextfreeGrammar('content', [usensfdata('ingress-action-type')[0]], '<ingress-action-type>', '</ingress-action-type>')
                    grammar_action_temp = TextfreeGrammar('structure', [grammar_ingress_action], '<ingress-action>', '</ingress-action>')
                    grammar_action_clause = TextfreeGrammar('structure', [grammar_action_temp], '<action-clause-container>', '</action-clause-container>')
                    grammar_total_structure_list.append(grammar_action_clause)

                grammar_rules = TextfreeGrammar('structure', grammar_total_structure_list, '<rules nc:operation=\"create\">', '</rules>')
                print('Target IP is '+nsf_iplist[filterindex]+'\nFilter policy:')
                generated_filter_policy = xml_header + grammar_rules.translate(0) + xml_tail
                print(generated_filter_policy)

                # print low-level policy xml files
                fo = open('new_firewall.xml', 'w')
                fo.write(generated_firewall_policy)
                fo.close()
                fo = open('new_filter.xml', 'w')
                fo.write(generated_filter_policy)
                fo.close()

                #print("sudo ~/confd-6.2/bin/netconf-console --host " + nsf_iplist[firewallindex] + " ./new_firewall.xml")
                #print("sudo ~/confd-6.2/bin/netconf-console --host " + nsf_iplist[filterindex] + " ./new_filter.xml") 

                os.system("sudo ~/confd-6.2/bin/netconf-console --host " + nsf_iplist[firewallindex] + " ./new_firewall.xml") 
                os.system("sudo ~/confd-6.2/bin/netconf-console --host " + nsf_iplist[filterindex] + " ./new_filter.xml") 

                
            """
	    if response["i2nsf:Policy"]["rule"]:
		rid = response["i2nsf:Policy"]["rule"]["rule-name"]
		os.system("curl --ipv4 --http2 -k --cert-type PEM -E /works/jetconf/data/example-client.pem -X DELETE $POST_DATA https://127.0.0.1:8443/restconf/data/i2nsf:Policy/rule=%s" %rid)
            """

