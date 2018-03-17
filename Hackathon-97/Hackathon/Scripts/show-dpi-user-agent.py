#	!/usr/bin/env	python

import MySQLdb
import os
import socket
import ipaddress

str_exe_position = "select * from dpi_rule;"
db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="hackathon")
cur = db.cursor()
cur.execute(str_exe_position)
print ""
print "				DPI Table"
print ""
print "%10s %10s %10s" % ("Rule ID", "Blocked User Agent", "Action")
for row in cur.fetchall():

	if row[3] == "eyebeam" or row[3] == "friendly-scanner" or row[3] == "sipcli":
		if row[4] == 0:
			print "%10s %13s %15s" % (row[0], row[3], "Permit") 

		elif row[4] == 1:
			print "%10s %13s %15s" % (row[0], row[3], "Block") 

		else:
			print "%10s %13s %15s" % (row[0], row[3], "Mirror") 

db.close()
