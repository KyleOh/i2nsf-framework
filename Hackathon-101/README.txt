README for IETF-98 I2NSF Hackathon

This explains the source code and manual to remotely participate in IETF-98 I2NSF Hackathon.
 
The following link contains the source code for our I2NSF Hackathon:
https://github.com/kimjinyong/i2nsf-framework

If you follow this link, you will find a "Hackathon-98" folder which 
consists of 7 subfolders. 
The information about each folder is as follows:

1. Doc
   This folder contains the document files related to I2NSF Hackathon. 
   The document files are "Hackathon Program Manual.pdf", "Hackathon Scenario.pdf", 
   "All about Hackathon.pdf", and "Hackathon-Poster.pdf".

2. I2NSF_User
   This folder contains the php files for the Web User Interface for I2NSF User 
   in I2NSF Framework.

3. Interfaces
   This folder contains the source code for the inter-process-communication interfaces 
   (i.e., NSF-NSFF-Interface and MySQL-Interface) in I2NSF framework where NSF stands for
   Network Security Function and NSFF stands for NSF Forwarder.

4. NSF
   This folder contains the source code for Network Security Functions (NSFs), such as
   Firewall and Deep Packet Inspection (DPI).

5. Scripts
   This folder contains the mysql database schema (i.e., database table for each I2NSF component),
   a Python script for mininet in a testbed network, a shell script (i.e., OpenDaylight restconf API) 
   for traffic steering, a shell script to look at the rules in a flow table in an SDN switch,
   a Python script to display all firewall policies in a Firewall in the mininet.

6. Security Controller
   This folder contains the source code for Security Controller.

7. bin
   Execution binary files for (i) NSFs (e.g., Firewall).

Enjoy and Thanks.

Best Regards,
Jinyong Tim Kim
Date: 24/03/2017
-- 
===========================
Jinyong Tim Kim, Ph.D. Student
Department of Computer Science and Engineering
Sungkyunkwan University
Email: timkim@skku.edu
Lab Homepage: http://iotlab.skku.edu
