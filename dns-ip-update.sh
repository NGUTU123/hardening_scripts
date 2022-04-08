#!/bin/bash
#Creat set of ips
ipset -exist create dns-allowed hash:ip

# Find IP address and store it in $ip
ip=dig +short recuc.ddns.net

# Flush old IP addresses from ssh-allowed IP Set
ipset flush dns-allowed

# Add new IP address to ssh-allowed IP Set
ipset add dns-allowed $ip
