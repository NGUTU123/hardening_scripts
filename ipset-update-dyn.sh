#!/bin/bash
iptables -N myDDNS 2>/dev/null;iptables -I INPUT -j myDDNS;iptables -F myDDNS && iptables -I myDDNS -p tcp -s $(dig +short recuc.ddns.net) -m state --state NEW -m tcp -j ACCEPT
