#!/bin/bash

# Set as cronjob
# *	*	*	*	*	/root/scripts/iptables-ddns.sh >> /root/logs/iptables-ddns.log 2>&1

log () {
    echo "[$(date "+%F +%T")] [$1] $2" >> "$LOGS/changes.log"
}

HOSTS="recuc.ddns.net"
LOGS="/root/logs/iptables-ddns/"
PORT=13689

if [ ! -d "$LOGS" ]; then
    install -d "$LOGS"
fi

for host in $HOSTS; do
    LOG="$LOGS/$host"
    CURRENT=$(getent hosts "$host" | awk '{print $1}')

    if [ "$CURRENT" == "" ]; then
        log "$host" "[EMPTY] Current address empty"
        continue
    fi

    if [ -f "$LOG" ]; then
        PREVIOUS=$(cat "$LOG")
    else
        PREVIOUS=""
    fi

    if [ "$CURRENT" == "$PREVIOUS" ]; then
        log "$host" "[SAME] Current and Previous are same ($CURRENT)"
        continue
    fi

    if [ "$PREVIOUS" != "" ]; then
        iptables -D INPUT -s "$PREVIOUS" -p tcp -m tcp --dport "$PORT" -j ACCEPT
    fi

    iptables -A INPUT -s "$CURRENT" -p tcp -m tcp --dport "$PORT" -j ACCEPT

    echo "$CURRENT" > $LOG

    log "$host" "[UPDATED] $PREVIOUS > $CURRENT"
done

exit 0
