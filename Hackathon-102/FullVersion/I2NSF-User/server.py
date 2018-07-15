#!/usr/bin/env python
import urllib
import urllib2
import requests
import socket
from xml.etree import ElementTree

 
TCP_IP = '127.0.0.1'
TCP_PORT = 6000
BUFFER_SIZE = 4096  # Normally 1024, but we want fast response
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

while True:
    print("Now listening...\n")
    conn, addr = s.accept()

    print 'New connection from %s:%d' % (addr[0], addr[1])
    data = conn.recv(BUFFER_SIZE)
    print data
    if not data:
        break
    elif data == 'killsrv':
        conn.close()
        sys.exit()
        # r = requests.get('http://127.0.0.1/qfc.php/api/Policies')
        # print(r.text)


print 'Connection address:', addr

# r = requests.get('http://127.0.0.1/qfc.php/api/Policies')




conn.close()
