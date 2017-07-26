# arp-spoofer

Best of the Best 6th    
Security Consulting Track    
Jung Hangil

## Compile enviroment
1. Debian Linuxs (Kali / Ubuntu)
2. gcc
3. pcap library

## Compile command
```
make
```

## Fetching My IP / MAC addr
```
ifconfig
```
Fetching IPv4 addr cmd
```
/bin/bash -c "ifconfig eth0" | grep "inet " | awk '{print $2}'
```
Fetching hw addr cmd
```
/bin/bash -c "ifconfig eth0" | grep '[ ][0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]' | awk '{print $2}'
```

## Fetching My Default gateway
```
route -n
```
Fetching my default gateway cmd
```
/bin/bash -c 'route -n' | grep G | grep eth0 | awk '{print $2}'
```

## Implements of net-tools

References - https://github.com/giftnuss/net-tools    
ifconfig and route command are implemented.

## References
popen example - https://stackoverflow.com/questions/646241/c-run-a-system-command-and-get-output    
Another method to fetch mac/ip addr - http://www.cnx-software.com/2011/04/05/c-code-to-get-mac-address-and-ip-address/    
arp spoof reply code - http://melwin-jose.blogspot.kr/2013/07/arp-reply-spoof-c-code.html