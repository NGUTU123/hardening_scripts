#!/bin/bash
# Update ipset to let my dynamic IP in

set=whitelist
host=myhost.dynamic.example.com

me=$(basename "$0")

ip=$(dig +short $host)

if [ -z "$ip" ]; then
    logger -t "$me" "IP for '$host' not found"
    exit 1
fi

# make sure the set exists
ipset -exist create $set hash:ip

if ipset -q test $set $host; then
    logger -t "$me" "IP '$ip' already in set '$set'."
else 
    logger -t "$me" "Adding IP '$ip' to set '$set'."
    ipset flush $set
    ipset add $set $host
fi
