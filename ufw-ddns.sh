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
    /usr/sbin/ufw delete allow from $old_ip to any port 13689 # ssh port
    /usr/sbin/ufw delete allow from $old_ip to any port 22 # ssh port
    /usr/sbin/ufw delete allow from $old_ip to any port 9000 # portainer port
    fi
    /usr/sbin/ufw allow from $new_ip to any port 13689 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 22 comment $HOSTNAME
    /usr/sbin/ufw allow from $new_ip to any port 9000 comment $HOSTNAME
fi
