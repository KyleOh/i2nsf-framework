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
		s1 = self.addSwitch('s1');
		s2 = self.addSwitch('s2');
		s3 = self.addSwitch('s3');
		s4 = self.addSwitch('s4');



	  
 
#################################### Eployee according to postion ##########################
                smes = self.addHost('smes', ip='10.0.0.2', mac = '00:00:00:00:00:22');
		self.addLink(smes, s1);

		m_user = self.addHost('m_user', ip='10.0.0.3');
		self.addLink(m_user, s1);

#                test = self.addHost('test', ip='10.0.0.2', mac = '00:00:00:00:00:22');
#		self.addLink(test, s3);



############################## Eployee according to postion ########################

		firewall = self.addHost('firewall', ip='10.0.0.200');
		self.addLink(firewall, s4);

                firewall_2 = self.addHost('firewall_2', ip='10.0.0.201');
		self.addLink(firewall_2, s4);


		mail = self.addHost('mail', ip='10.0.0.202');
		self.addLink(mail, s4);

		web_filter = self.addHost('web_filter', ip='10.0.0.203');
		self.addLink(web_filter, s4);





############################ Internet #########################################
		nat = self.addNode('nat', ip = '10.0.0.150', inNamespace = False);
		self.addLink(nat, s3);

                vpn = self.addNode('vpn', ip = '10.0.0.155', mac='00:00:00:00:11:55');
                self.addLink(vpn, s3);




		
#############################Link Connection##########################
		self.addLink(s1, s2);
		self.addLink(s1, s3);
                self.addLink(s2, s3);
                self.addLink(s2, s4);
                self.addLink(s3, s4);
    

		service_provider = self.addHost('sp', ip='10.0.0.205');
		self.addLink(service_provider, s4);

		devel_sys = self.addHost('devel_sys', ip='10.0.0.206');
		self.addLink(devel_sys, s4);

            


		

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
#	os.system("ovs-vsctl set Bridge s1 protocols=OpenFlow13");
#        os.system("ovs-vsctl set Bridge s2 protocols=OpenFlow13");
#        os.system("ovs-vsctl set Bridge s3 protocols=OpenFlow13");
#        os.system("ovs-vsctl set Bridge s4 protocols=OpenFlow13");
        
        net.pingAll();
	os.system("sudo ./vpn.sh PUT 127.0.0.1:8181")
        os.system("sudo rm /etc/suricata/rules/i2nsf-firewall.rules")
        os.system("sudo rm /etc/suricata/rules/i2nsf-time-firewall.rules")
        os.system("sudo rm /etc/suricata/rules/i2nsf-web.rules")
        os.system("sudo rm /etc/suricata/rules/i2nsf-mail.rules")

	# Inintalize components

        smes = net.get('smes');
        m_user = net.get('m_user');
        firewall = net.get('firewall');
        firewall_2 = net.get('firewall_2');
        #test = net.get('test');
        sp = net.get('sp');

        web_filter = net.get('web_filter');
        mail = net.get('mail');
        nat = net.get('nat');
        vpn = net.get('vpn');
        
        firewall.cmd('cd ../NSF/Firewall_based_time; sudo make clean');
        firewall.cmd('secu');
        firewall.cmd('sudo make all start >> /tmp/time_firewall.out &');

        firewall_2.cmd('cd ../NSF/Firewall; sudo make clean');
        firewall_2.cmd('secu');
        firewall_2.cmd('sudo make all start >> /tmp/firewall.out &');

        smes.cmd('sudo service sendmail restart &');


        web_filter.cmd('cd ../NSF/Web_Filter; sudo make clean');
        web_filter.cmd('secu');
        web_filter.cmd('sudo make all start >> /tmp/web_filter.out &');

        mail.cmd('cd ../NSF/Mail_Filter; sudo make clean');
        mail.cmd('secu');
        mail.cmd('sudo make all start >> /tmp/mail.out &');


        sp.cmd('cd ~/Hackathon/Hackathon-102/FullVersion/SecurityController')
        sp.cmd('sudo service apache2 stop >> /tmp/webserver.out')
        sp.cmd('sudo service apache2 start >> /tmp/webserver.out')
        sp.cmd('cd ../Developer-mgmt-system/; sudo make clean');
        sp.cmd('secu');
        sp.cmd('sudo make all start >> /tmp/webserver.out &');

        sp.cmd('cd ~/Hackathon/Hackathon-102/FullVersion/SecurityController')
        sp.cmd('sudo python server.py >> /tmp/webserver.out &');
        sp.cmd('cd /works/jetconf')
        sp.cmd('sudo python3.6 run.py -c example-config.yaml >> /tmp/webserver.out &')
        sp.cmd('sudo make clean')
        sp.cmd('sudo make all start >> /tmp/SecurityController.out &')

	smes.cmd( 'sudo route add default gw', '10.0.0.201')
        #test.cmd( 'sudo route add default gw', '10.0.0.201')
	m_user.cmd( 'sudo route add default gw', '10.0.0.201')
        m_user.cmd( 'sudo sysctl net.ipv4.ip_forward=1')
        vpn.cmd('sudo route add default gw', '10.0.0.200')
        firewall.cmd( 'sudo route add default gw', '10.0.0.203')
	web_filter.cmd( 'sudo route add default gw', '10.0.0.150')
        firewall_2.cmd( 'sudo route add default gw', '10.0.0.202')
        mail.cmd( 'sudo route add default gw', '10.0.0.150')
        
       
        smes.cmd('sudo sysctl net.ipv4.conf.all.send_redirects=0')
        smes.cmd('sudo sysctl net.ipv4.ip_forward=1')
        vpn.cmd('sudo sysctl net.ipv4.conf.all.send_redirects=0')
        vpn.cmd('sudo sysctl net.ipv4.ip_forward=1')

        firewall.cmd( 'sudo sysctl net.ipv4.ip_forward=1')
        firewall.cmd( 'sudo iptables -I FORWARD -j NFQUEUE')
        firewall.cmd('sudo rm /var/run/suricata-time-firewall.pid >> /tmp/time_firewall.out');
        firewall.cmd('sudo rm /var/run/suricata/time_firewall.socket');
        
        firewall.cmd('sudo /usr/bin/suricata -D --pidfile /var/run/suricata-time-firewall.pid -c /etc/suricata/suricata_firewall_based_time.yaml -q 0 >> /tmp/time_firewall.out');
        firewall.cmd('sudo /usr/bin/suricatasc -c reload-rules & >> /tmp/time_firewall.out');


	firewall_2.cmd( 'sudo sysctl net.ipv4.ip_forward=1')
        firewall_2.cmd( 'sudo iptables -I FORWARD -j NFQUEUE')
        firewall_2.cmd('sudo rm /var/run/suricata-firewall.pid >> /tmp/firewall.out');
        firewall_2.cmd('sudo rm /var/run/suricata/firewall.socket');
        
        firewall_2.cmd('sudo /usr/bin/suricata -D --pidfile /var/run/suricata-firewall.pid -c /etc/suricata/suricata_firewall.yaml -q 0 >> /tmp/firewall.out');
        firewall_2.cmd('sudo /usr/bin/suricatasc -c reload-rules & >> /tmp/firewall.out');





        web_filter.cmd( 'sudo sysctl net.ipv4.ip_forward=1')
        web_filter.cmd( 'sudo iptables -I FORWARD -j NFQUEUE')
        web_filter.cmd('sudo rm /var/run/suricata-web.pid >> /tmp/webfilter.out');
        web_filter.cmd('sudo rm /var/run/suricata/web.socket');
        web_filter.cmd('sudo /usr/bin/suricata -D --pidfile /var/run/suricata-web.pid -c /etc/suricata/suricata_web.yaml -q 0 >> /tmp/web_filter.out');
        web_filter.cmd('sudo /usr/bin/suricatasc -c reload-rules & >> /tmp/web_filter.out');

        mail.cmd('sudo sysctl net.ipv4.ip_forward=1')
        mail.cmd('sudo iptables -I FORWARD -j NFQUEUE')
        mail.cmd('sudo rm /var/run/suricata-mail.pid >> /tmp/mail.out');
        mail.cmd('sudo rm /var/run/suricata/mail.socket');
        mail.cmd('sudo /usr/bin/suricata -D --pidfile /var/run/suricata-mail.pid -c /etc/suricata/suricata_mail.yaml -q 0 >> /tmp/mail.out');
        mail.cmd('sudo /usr/bin/suricatasc -c reload-rules & >> /tmp/mail.out');




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

        os.system("sudo ./vpn.sh DELETE 127.0.0.1:8181")


	net.stop()
	
if __name__ == '__main__':
	"Tell mininet to print useful information"
	setLogLevel('info')
	simpleTest()
	os.system("sudo mn -c");


