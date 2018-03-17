#	!/usr/bin/env python
import urllib
import urllib2
import requests
import socket
import json
import MySQLdb #DB
import os
import sys
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element,SubElement, dump
from xml.etree import ElementTree
from xml.sax.saxutils import unescape
from xml.etree.ElementTree import ElementTree


 
TCP_IP = '127.0.0.1'
TCP_PORT = 6000
BUFFER_SIZE = 1024  # Normally 1024, but we want fast response
ns1='urn:ietf:params:xml:ns:netconf:base:1.0'
ns2='http://skku.edu/nsf-facing-interface'
ns1_prefix='{'+ns1+'}'
ns2_prefix='{'+ns2+'}'
ET.register_namespace('nc',ns1)
ET.register_namespace('pol',ns2)
level1_port_list=["20","21","22","23","24","25","80","109","110","143","443"]
level2_port_list=["22","109","110","143","443"]
employee_ip_list=[]
level1_port_list_len=len(level1_port_list)
level2_port_list_len=len(level2_port_list)

def indent(elem, level=0):
	i = "\n" + level*" "
	if len(elem):
		if not elem.text or not elem.text.strip():
			elem.text = i + ""
		if not elem.tail or not elem.text.strip():
			elem.tail = i
		for elem in elem:
			indent(elem, level+1)
		if not elem.tail or not elem.tail.strip():
			elem.tail = i
		for elem in elem:
			indent(elem, level+2)
		if not elem.tail or not elem.tail.strip():
			elem.tail = i
	else:
		if level and (not elem.tail or not elem.tail.strip()):
			elem.tail = i
def xml_hello_part(f_write):
	hello = Element("hello")
	hello.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0"
	to = Element("capabilities")
	capabilities = Element("capability")
	to.text = " " 
	capabilities.text = "urn:ietf:params:netconf:base:1.0"
	hello.append(to)
	to.append(capabilities)

	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	f_write.write(data)
	indent(hello)
	# dump(hello)
	ElementTree(hello).write("test.xml")
	f_read = open("test.xml", 'r')
 	while True:
		line = f_read.readline()
		if not line: break
		f_write.write(line)
	f_read.close()
	data = "]]>]]>\n"
	f_write.write(data)
def xml_close_part(f_write):
	elem_under_rpc = Element("rpc")
	elem_under_rpc.attrib["xmlns"]="urn:ietf:params:xml:ns:netconf:base:1.0" 
	elem_under_rpc.attrib["message-id"]="2"
	temp_elem_under_rpc = Element("")
	temp_elem_under_rpc.text = "<close-session/>"
	temp_elem_under_rpc = ET.fromstring(temp_elem_under_rpc.text)
	elem_under_rpc.append(temp_elem_under_rpc)

	data = "]]>]]>\n"
	f_write.write(data)
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	indent(elem_under_rpc)
	# dump(elem_under_rpc)
	f_write.write(data)
	ElementTree(elem_under_rpc).write("test.xml")
	f_read = open("test.xml", 'r')
	while True:
		line = f_read.readline()
		if not line: break
		f_write.write(line)
	f_read.close()
	data = "]]>]]>"
	f_write.write(data)
def enterprise_update_part(data):
	flag=0
	root = ET.fromstring(data)
	rule_id = root[0][0].text
	rule_name = root[0][1].text
	os.system("xsltproc ./xslt/enterprise-update.xslt ./xslt/data.xml > ./xslt/temp.xml")
	f_write = open("./policy/firewall-create.xml", "w")
	#======================XML Hello Part========================
	xml_hello_part(f_write)

	#======================XML CURD Part========================
	f_result = open("./xslt/result.xml","w")
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	f_result.write(data)
	f_temp = open("./xslt/temp.xml","r")
	while True:
		line=f_temp.readline()
		if not line: break
		f_result.write(line)
	f_temp.close()
	f_result.close()
	os.system("rm ./xslt/temp.xml")

	#=====================Handling xml after XSLT

	tree=ET.parse('./xslt/result.xml')
	root=tree.getroot()
	for src in root.iter(ns2_prefix+'service-sec-context-cond'):
		child=src.find(ns2_prefix+'dest-port')
		src.remove(child)
		if 'Level-1' in rule_name:
			flag=1
			elem_dest_port = []
			for i in range(level1_port_list_len):
				elem_dest_port.append(ET.Element("pol:dest-port"))
				elem_dest_port[i].text=level1_port_list[i]
			for i in range(level1_port_list_len):
				src.append(elem_dest_port[i])
		elif 'Level-2' in rule_name:
			flag=2
			elem_dest_port = []
			for i in range(level2_port_list_len):
				elem_dest_port.append(ET.Element("pol:dest-port"))
				elem_dest_port[i].text=level2_port_list[i]
			for i in range(level2_port_list_len):
				src.append(elem_dest_port[i])
		elif 'Level-3' in rule_name:
			flag=3
			os.system("xsltproc ./xslt/enterprise-update-level3.xslt ./xslt/data.xml > ./xslt/temp.xml")
			f_write_level3=open("./policy/firewall-create-level3.xml","w")
			xml_hello_part(f_write_level3)
			f_temp = open("./xslt/temp.xml","r")
			while True:
				line=f_temp.readline()
				if not line: break
				f_write_level3.write(line)
			f_temp.close()
			xml_close_part(f_write_level3)
			f_write_level3.close()
			os.system("rm ./xslt/temp.xml")


	indent(root)
	tree.write('./xslt/test.xml')

	#======================XML Generate========================
	f_xml=open("./xslt/test.xml","r")
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	f_write.write(data)
	while True:
		line=f_xml.readline()
		if not line: break
		f_write.write(line)
	f_xml.close()

	#======================XML Close Part========================
	xml_close_part(f_write)

	f_write.close()
	
	os.system("rm ./xslt/result.xml")
	os.system("rm ./xslt/test.xml")
	# print flag
	if flag==1 or flag==2:
		os.system("sudo ~/confd-6.2/bin/netconf-console --host 10.0.0.200 ./policy/firewall-create.xml")
	elif flag==3:
		os.system("sudo ~/confd-6.2/bin/netconf-console --host 10.0.0.200 ./policy/firewall-create-level3.xml")
def enterprise_delete_part(data):
	root = ET.fromstring(data)
	rule_id = root[0][0].text
	rule_name = root[0][1].text
	os.system("xsltproc ./xslt/enterprise-delete.xslt ./xslt/data.xml > ./xslt/temp.xml")
	f_write = open("./policy/firewall-delete.xml", "w")
	#======================XML Hello Part========================
	xml_hello_part(f_write)
	#======================XML CURD Part========================
	f_temp = open("./xslt/temp.xml","r")
	while True:
		line=f_temp.readline()
		if not line: break
		f_write.write(line)
	f_temp.close()

	#======================XML Close Part========================
	xml_close_part(f_write)
	f_write.close()
	os.system("rm ./xslt/temp.xml")
	os.system("sudo ~/confd-6.2/bin/netconf-console --host 10.0.0.200 ./policy/firewall-delete.xml")
def web_create_part(data):
	root = ET.fromstring(data)
	rule_id = root[0][0].text
	rule_name = root[0][1].text
	position = root[0][2].text
	website = root[0][3].text
	start_time =root[0][4].text
	end_time =root[0][5].text
	action=root[0][6].text
	os.system("xsltproc ./xslt/web-create.xslt ./xslt/data.xml > ./xslt/temp.xml")
	f_write = open("./policy/web-create.xml", "w")
	#======================XML Hello Part========================
	xml_hello_part(f_write)
	#======================XML CURD Part========================
	f_result = open("./xslt/result.xml","w")
	# data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	# f_result.write(data)
	f_temp = open("./xslt/temp.xml","r")
	while True:
		line=f_temp.readline()
		if not line: break
		f_result.write(line)
	f_temp.close()
	f_result.close()
	# os.system("rm ./xslt/temp.xml")
	
	#=====================DB
	del employee_ip_list[:]
	str_exe_position = "select * from Policies2 where Position like '" + position + "';"
	db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Position")
	cur = db.cursor()
	cur.execute(str_exe_position)
	for row in cur.fetchall():
		employee_ip_list.append(row[0])
	employee_ip_list_len = len(employee_ip_list)
	db.close()

	#=====================Handling xml after XSLT
	print ("before result parse")
	tree=ET.parse('./xslt/result.xml')
	root=tree.getroot()
	for src in root.iter(ns2_prefix+'packet-security-ipv4-condition'):
		child=src.find(ns2_prefix+'pkt-sec-cond-ipv4-src')
		src.remove(child)
		if 'Staff' in position:
			elem_employee=[]
			for i in range(employee_ip_list_len):
				elem_employee.append(ET.Element("pol:pkt-sec-cond-ipv4-src"))
				elem_employee[i].text=employee_ip_list[i]
			for i in range(employee_ip_list_len):
				src.append(elem_employee[i])
	for src in root.iter(ns2_prefix+'schedule'):
		src.find(ns2_prefix+'start-time').text=start_time+":00Z"
		src.find(ns2_prefix+'end-time').text=end_time+":00Z"

	indent(root)
	tree.write('./xslt/test.xml')

	#======================XML Generate========================
	f_xml=open("./xslt/test.xml","r")
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	f_write.write(data)
	while True:
		line=f_xml.readline()
		if not line: break
		f_write.write(line)
	f_xml.close()

	#======================XML Close Part========================
	xml_close_part(f_write)
	f_write.close()
	os.system("rm ./xslt/result.xml")
	os.system("rm ./xslt/test.xml")
	os.system("sudo ~/confd-6.2/bin/netconf-console --host 10.0.0.201 ./policy/web-create.xml")
def web_update_part(data):
	root = ET.fromstring(data)
	rule_id = root[0][0].text
	rule_name = root[0][1].text
	position = root[0][2].text
	website = root[0][3].text
	start_time =root[0][4].text
	end_time =root[0][5].text
	action=root[0][6].text
	os.system("xsltproc ./xslt/web-update.xslt ./xslt/data.xml > ./xslt/temp.xml")
	f_write = open("./policy/web-update.xml", "w")
	#======================XML Hello Part========================
	xml_hello_part(f_write)
	#======================XML CURD Part========================
	f_result = open("./xslt/result.xml","w")
	# data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	# f_result.write(data)
	f_temp = open("./xslt/temp.xml","r")
	while True:
		line=f_temp.readline()
		if not line: break
		f_result.write(line)
	f_temp.close()
	f_result.close()
	os.system("rm ./xslt/temp.xml")
	
	#=====================DB
	del employee_ip_list[:]
	str_exe_position = "select * from Policies2 where Position like '" + position + "';"
	db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Position")
	cur = db.cursor()
	cur.execute(str_exe_position)
	for row in cur.fetchall():
		employee_ip_list.append(row[0])
	employee_ip_list_len = len(employee_ip_list)
	db.close()

	#=====================Handling xml after XSLT
	tree=ET.parse('./xslt/result.xml')
	root=tree.getroot()
	for src in root.iter(ns2_prefix+'packet-security-ipv4-condition'):
		child=src.find(ns2_prefix+'pkt-sec-cond-ipv4-src')
		src.remove(child)
		if 'Staff' in position:
			elem_employee=[]
			for i in range(employee_ip_list_len):
				elem_employee.append(ET.Element("pol:pkt-sec-cond-ipv4-src"))
				elem_employee[i].text=employee_ip_list[i]
			for i in range(employee_ip_list_len):
				src.append(elem_employee[i])
	for src in root.iter(ns2_prefix+'schedule'):
		src.find(ns2_prefix+'start-time').text=start_time+":00Z"
		src.find(ns2_prefix+'end-time').text=end_time+":00Z"

	indent(root)
	tree.write('./xslt/test.xml')

	#======================XML Generate========================
	f_xml=open("./xslt/test.xml","r")
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	f_write.write(data)
	while True:
		line=f_xml.readline()
		if not line: break
		f_write.write(line)
	f_xml.close()

	#======================XML Close Part========================
	xml_close_part(f_write)
	f_write.close()
	os.system("rm ./xslt/result.xml")
	os.system("rm ./xslt/test.xml")
	os.system("sudo ~/confd-6.2/bin/netconf-console --host 10.0.0.201 ./policy/web-update.xml")
def web_delete_part(data):
	root = ET.fromstring(data)
	rule_id = root[0][0].text
	os.system("xsltproc ./xslt/web-delete.xslt ./xslt/data.xml > ./xslt/temp.xml")
	f_write = open("./policy/web-delete.xml", "w")
	#======================XML Hello Part========================
	xml_hello_part(f_write)
	#======================XML CURD Part========================
	f_temp = open("./xslt/temp.xml","r")
	while True:
		line=f_temp.readline()
		if not line: break
		f_write.write(line)
	f_temp.close()

	#======================XML Close Part========================
	xml_close_part(f_write)
	f_write.close()
	os.system("rm ./xslt/temp.xml")
	os.system("sudo ~/confd-6.2/bin/netconf-console --host 10.0.0.201 ./policy/web-delete.xml")



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(2)

while True:
	print("Now listening...\n")
	conn, addr = s.accept()

	print 'New connection from %s:%d' % (addr[0], addr[1])

	data = conn.recv(BUFFER_SIZE)
	index = data.split(',')[0]
	mode = data.split(',')[1]
	data = data.split(',')[2]
	
	print index
	print mode
	print data
	f_xml=open("./xslt/data.xml","w")
	f_xml.write(data)
	f_xml.close()

	if 'enterprise-mode' in index:
		if 'create' in mode:
			enterprise_update_part(data)
		elif 'update' in mode:
			enterprise_update_part(data)
		elif 'delete' in mode:
			enterprise_delete_part(data)
	elif 'web' in index:
		if 'create' in mode:
			web_create_part(data)
		elif 'update' in mode:
			web_update_part(data)
		elif 'delete' in mode:
			web_delete_part(data)
	elif data == 'killsrv':
		conn.close()
		sys.exit()

conn.close()
s.close()
