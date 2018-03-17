#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
from functools import partial
from time import sleep
from mininet.cli import CLI
from mininet.link import Intf
from mininet.link import Link
from mininet.log import setLogLevel, info

import os
import MySQLdb

class SingleSwitchTopo(Topo):
	"Single switch connected to n hosts."
	def build(self, n=2):
		switch_1 = self.addSwitch('switch1');
		switch_2 = self.addSwitch('switch2');
		switch_3 = self.addSwitch('switch3');
		switch_4 = self.addSwitch('switch4');



######################################### SFF ####################################
		sff1 = self.addHost('sff1', ip='10.0.0.100');
		self.addLink(sff1, switch_2);
	  
 
#################################### NSFs #########################################
		firewall = self.addHost('firewall', ip='10.0.0.200');
		self.addLink(firewall, switch_1);

		web_filter = self.addHost('web_filter', ip='10.0.0.201');
		self.addLink(web_filter, switch_1);


		admin = self.addHost('admin', ip='10.0.0.101');
		self.addLink(admin, switch_1);


############################## Eployee according to postion ########################
		staff_1 = self.addHost('staff_1', ip='10.0.0.2');
		self.addLink(staff_1, switch_4);

		staff_2 = self.addHost('staff_2', ip='10.0.0.3');
		self.addLink(staff_2, switch_4);

		manager = self.addHost('manager', ip='10.0.0.14');
		self.addLink(manager, switch_4);

		president = self.addHost('president', ip='10.0.0.24');
		self.addLink(president, switch_4);



############################ Internet #########################################
		nat = self.addNode('nat', ip = '10.0.0.150', inNamespace = False);
		self.addLink(nat, switch_3);

		
#############################Link Connection##########################
		self.addLink(switch_1, switch_2);
		self.addLink(switch_2, switch_3);
		self.addLink(switch_2, switch_4);
		self.addLink(switch_1, switch_3);

		

def fixNetworkManager( root, intf ):
	 """Prevent network-manager from messing with our interface,
		by specifying manual configuration in /etc/network/interfaces
		root: a node in the root namespace (for running commands)
		intf: interface name"""
	 cfile = '/etc/network/interfaces'
	 line = '\niface %s inet manual\n' % intf
	 config = open( cfile ).read()
	 if line not in config:
		 print '*** Adding', line.strip(), 'to', cfile
		 with open( cfile, 'a' ) as f:
			  f.write( line )
		 # Probably need to restart network-manager to be safe -
		 # hopefully this won't disconnect you
		 root.cmd( 'sudo service network-manager restart' )


def simpleTest():

	#os.system("sudo mysql -u root -p mysql < ./schema.sql")
	#"Create and test a simple network"
	topo = SingleSwitchTopo(n=4)
	net = Mininet(topo, controller=partial(RemoteController, ip='127.0.0.1', port=6633))
	net.start();
	os.system("sudo ./deleteFlowForSwitchs.sh")
	net.pingAll();
	os.system("sudo ./sendFlowRuleForBasicPacket.sh PUT 127.0.0.1:8181")
        os.system("sudo ./deleteFlowForSwitchs.sh")
        os.system("sudo rm /etc/suricata/rules/i2nsf-firewall.rules")
        os.system("sudo rm /etc/suricata/rules/i2nsf-web-filter.rules")

##


	# Inintalize components
	nat = net.get('nat');
	sff = net.get('sff1');
	firewall = net.get('firewall');
	web_filter = net.get('web_filter');
	admin = net.get('admin');
	staff_1 = net.get('staff_1');
	staff_2 = net.get('staff_2');
	manager = net.get('manager');
	president = net.get('president');


	firewall.cmd('cd ../NSF/Firewall; sudo make clean');
	firewall.cmd('secu');
	firewall.cmd('sudo make all start >> /tmp/firewall.out &');

	web_filter.cmd('cd ../NSF/Web_Filter; sudo make clean');
	web_filter.cmd('secu');
	web_filter.cmd('sudo make all start >> /tmp/web_filter.out &');


	#admin.cmd('cd ../RESTCONF');
	#admin.cmd('sudo npm start >> /tmp/webserver1.out &');
	admin.cmd('cd /works/jetconf');
	admin.cmd('sudo python3.6 run.py -c example-config.yaml >> /tmp/webserver.out &');
	admin.cmd('cd ~/Hackathon/Hackathon-Registration/FullVersion/SecurityController');
	admin.cmd('sudo service apache2 stop >> /tmp/webserver.out');
	admin.cmd('sudo service apache2 start >> /tmp/webserver.out');
	admin.cmd('sudo python server.py >> /tmp/webserver.out &');
	admin.cmd('sudo make clean')
	admin.cmd('sudo make all start >> /tmp/securitycontroller.out &')
	
	str_exe_enterprise = "truncate table Policy_enterprise;"
	db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="I2NSF")
	cur = db.cursor()
	cur.execute(str_exe_enterprise)

	str_exe_web = "truncate table Policy_web;"
	db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="I2NSF")
	cur = db.cursor()
	cur.execute(str_exe_web)
	db.close()


	staff_1.cmd( 'sudo route add default gw', '10.0.0.100')
	staff_2.cmd( 'sudo route add default gw', '10.0.0.100')
	manager.cmd( 'sudo route add default gw', '10.0.0.100')
	president.cmd( 'sudo route add default gw', '10.0.0.100')

	sff.cmd( 'sudo route add default gw', '10.0.0.200')
	sff.cmd( 'sudo sysctl net.ipv4.ip_forward=1')

	firewall.cmd( 'sudo route add default gw', '10.0.0.201')
	firewall.cmd( 'sudo sysctl net.ipv4.ip_forward=1')
	firewall.cmd( 'sudo iptables -I FORWARD -j NFQUEUE')

	firewall.cmd('sudo rm /var/run/suricata-firewall.pid >> /tmp/firewall.out');
	firewall.cmd('sudo rm /var/run/suricata/firewall.socket');
	firewall.cmd('sudo /usr/bin/suricata -D --pidfile /var/run/suricata-firewall.pid -c /etc/suricata/suricata_firewall.yaml -q 0 >> /tmp/firewall.out');
	firewall.cmd('sudo /usr/bin/suricatasc -c reload-rules & >> /tmp/firewall.out');

	web_filter.cmd( 'sudo route add default gw', '10.0.0.150')
	web_filter.cmd( 'sudo sysctl net.ipv4.ip_forward=1')
	web_filter.cmd( 'sudo iptables -I FORWARD -j NFQUEUE')

	web_filter.cmd('sudo rm /var/run/suricata-web.pid >> /tmp/web_filter.out');
	web_filter.cmd('sudo rm /var/run/suricata/web.socket');
	web_filter.cmd('sudo /usr/bin/suricata -D --pidfile /var/run/suricata-web.pid -c /etc/suricata/suricata_web.yaml -q 0 >> /tmp/web_filter.out');
	web_filter.cmd('sudo /usr/bin/suricatasc -c reload-rules & >> /tmp/web_filter.out');



	# Identify the interface connecting to the mininet network
	localIntf = nat.defaultIntf()
	fixNetworkManager(nat, 'nat-eth0')

	# Flush any currently active rules
	nat.cmd( 'sudo iptables -F' )
	nat.cmd( 'sudo iptables -t nat -F' )

	# Create default entries for unmatched traffic
	nat.cmd( 'sudo iptables -P INPUT ACCEPT' )
	nat.cmd( 'sudo iptables -P OUTPUT ACCEPT' )
	nat.cmd( 'sudo iptables -P FORWARD DROP' )

	# Configure NAT
	nat.cmd( 'sudo iptables -I FORWARD -i', localIntf, '-d', '10.0/8', '-j DROP' )
	nat.cmd( 'sudo iptables -A FORWARD -i', localIntf, '-s', '10.0/8', '-j ACCEPT' )
	nat.cmd( 'sudo iptables -A FORWARD -i', 'eth0', '-d', '10.0/8', '-j ACCEPT' )
	nat.cmd( 'sudo iptables -t nat -A POSTROUTING -o ', 'eth0', '-j MASQUERADE' )

	# Instruct the kernel to perform forwarding
	nat.cmd( 'sudo sysctl net.ipv4.ip_forward=1' )
			
	CLI(net)


	os.system("sudo killall -9 /usr/bin/suricata")

	"""Stop NAT/forwarding between Mininet and external network"""
	# Flush any currently active rules
	nat.cmd( 'sudo iptables -F' )
	nat.cmd( 'sudo iptables -t nat -F' )

	# Instruct the kernel to stop forwarding
	nat.cmd( 'sudo sysctl net.ipv4.ip_forward=0' )

	os.system("sudo ./deleteFlowForSwitchs.sh")


	net.stop()
	
if __name__ == '__main__':
	"Tell mininet to print useful information"
	setLogLevel('info')
	simpleTest()
	os.system("sudo mn -c");


