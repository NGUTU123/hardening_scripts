#!/bin/bash
##Update the OS with latest updates
apt-get -y update
apt-get -y upgrade

echo -e "\e[93mUpdates Done\e[0m"

# Disable IPv6
sed -i -e 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' \
        /etc/default/grub
update-grub

echo -e "\e[93mOS services Done\e[0m"

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

#Ensure SSH protocolis set to 2 CHUA CHECK
sed -i 's/#Protocol 2/Protocol 2/g'  /etc/ssh/sshd_config
grep "^Protocol" /etc/ssh/sshd_config

#Ensure SSH LogLevel is set to INFO CHUA CHECK
sed -i 's/#LogLevel INFO/Loglevel INFO/g' /etc/ssh/sshd_config
grep "^LogLevel" /etc/ssh/sshd_config

#Ensure X11 forwading is disabled OK
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
grep "^X11Forwarding" /etc/ssh/sshd_config

#Ensure SSH MaxAuthTries is set to 6 or less OK
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/g' /etc/ssh/sshd_config
grep "^MaxAuthTries" /etc/ssh/sshd_config

#Ensure SSH IgnoreRhosts is enabled OK
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g'  /etc/ssh/sshd_config
grep  "^IgnoreRhosts" /etc/ssh/sshd_config

#Ensure SSH HostbasedAuthentication is disabled OK
sed -ri'' 's/^#*HostbasedAuthentication.*$/HostbasedAuthentication no/g' /etc/ssh/sshd_config && grep "^#*HostbasedAuthentication" /etc/ssh/sshd_config

#Ensure SSH root login is disabled OK
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config
grep "^PermitRootLogin" /etc/ssh/sshd_config

#Ensure SSH PermitEmptyPasswords is disabled OK
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g'  /etc/ssh/sshd_config
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config

#Ensure SSH PermitUserEnvironment is disabled OK
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
grep "^PermitUserEnvironment" /etc/ssh/sshd_config

#Ensure only approved ciphers are used CHUA CHECK
sed -i '/# Ciphers/ a Ciphers aes128-ctr,aes192-ctr,aes256-ctr' /etc/ssh/sshd_config
grep "Ciphers" /etc/ssh/sshd_config

#Ensure only approved MAC algorithms  are used CHUA CHECK
sudo sed -i '/# Ciphers and keying/ a MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' /etc/ssh/sshd_config
grep "MACs" /etc/ssh/sshd_config

#Ensure SSH Idle Timeout Interval is configured OK
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
grep "^ClientAliveInterval" /etc/ssh/sshd_config
grep "^ClientAliveCountMax" /etc/ssh/sshd_config

#Ensure SSH LoginGraceTime is set to one minute or less OK
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config
grep "^LoginGraceTime" /etc/ssh/sshd_config

#Ensure SSH warning banner is configured CHUA CHECK
sed -i 's/#Banner \/etc\/issue\.net/Banner \/etc\/issue\.net/g'  /etc/ssh/sshd_config
grep "^Banner" /etc/ssh/sshd_config

echo -e "\e[32mAll Done\e[0m"
##Reboot of server
echo -e "\e[31mHere comes the reboot. Brace for Alert\e[0m"
#reboot

########################
## Hardening Ubuntu ##
########################

#bash <(wget -qO- https://raw.githubusercontent.com/ertugrulturan/Kernel-DOS-Self-Protection/main/install)
#wget -O updater.sh 'https://raw.githubusercontent.com/XaviFortes/IPTables-DDOS-Protection/master/updater.sh' && chmod +x updater.sh && sed -i '1s/^.*#//;s/\r$//' updater.sh && ./updater.sh
#bash <(wget -qO- https://raw.githubusercontent.com/onesez/iptables/master/iptables.sh)
#bash <(wget -qO- https://raw.githubusercontent.com/deep-318/DDOSScripts/master/DDOSStop.sh)
#bash <(wget -qO- https://gist.githubusercontent.com/ozeias/1051365/raw/dad19aea109abbb2a112c219a6ca46358734dc01/Firewall-DDoS.sh)
#bash <(wget -qO- https://codeberg.org/KasperIreland/ddos-protection-script/raw/branch/main/script-ubuntu-debian.sh)
