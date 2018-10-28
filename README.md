# oscp

# cheatsheet

## recon

## password hash cracking
Cloud:
- https://crackstation.net/
- https://www.md5online.org/

Local tools:
- john
- hashcat

Wordlist:
- rockyou
- seclist

For CTF / OSCP, should not take you more than 30 mins to crak


## generate reverse shell payload
- msfvnon

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
- https://www.securitysift.com/offsec-pwb-oscp/
- https://github.com/xapax/oscp
- https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-2-workflow-and-documentation-tips-9dd335204a48
- 
- [OSCP Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md)
