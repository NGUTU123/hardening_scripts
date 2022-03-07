#!/bin/bash
HOSTNAME=recuc.ddns.net

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

new_ip=$(host $HOSTNAME | head -n1 | cut -f4 -d ' ')
old_ip=$(/usr/sbin/ufw status | grep $HOSTNAME | head -n1 | tr -s ' ' | cut -f3 -d ' ')

if [ "$new_ip" = "$old_ip" ] ; then
    echo IP address has not changed
else
    if [ -n "$old_ip" ] ; then
        /usr/sbin/ufw delete allow from $old_ip to any port 13689
	/usr/sbin/ufw delete allow from $old_ip to any port 8083
	/usr/sbin/ufw delete allow from $old_ip to any port 80
	/usr/sbin/ufw delete allow from $old_ip to any port 443
	/usr/sbin/ufw delete allow from $old_ip to any port 143
	/usr/sbin/ufw delete allow from $old_ip to any port 993
	/usr/sbin/ufw delete allow from $old_ip to any port 110
	/usr/sbin/ufw delete allow from $old_ip to any port 995
	/usr/sbin/ufw delete allow from $old_ip to any port 25
	/usr/sbin/ufw delete allow from $old_ip to any port 465
	/usr/sbin/ufw delete allow from $old_ip to any port 587
    fi
    /usr/sbin/ufw allow from $new_ip to any port 13689 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 8083 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 80 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 443 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 143 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 993 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 110 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 995 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 25 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 465 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 587 comment $HOSTNAME
fi
