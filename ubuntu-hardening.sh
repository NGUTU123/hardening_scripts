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


#Script for Password Creation Hardening for secure  system authentication

##Install libpam-pwquality
apt-get -y install libpam-pwquality

pwqual='/etc/security/pwquality.conf'
#Allow 3  Password tries before sending back a failure-  try_first_pass retry=3
grep pam_pwquality.so /etc/pam.d/password-auth
grep pam_pwquality.so /etc/pam.d/system-auth

#Ensure minimum number of characters in password is 14 - minlen=14
sudo sed -i 's/^# minlen =.*$/minlen = 14/' ${pwqual} /etc/security/pwquality.conf
grep ^minlen /etc/security/pwquality.conf

#Ensure users provide at least one digit - dcredit=1
sed -i 's/^# dcredit =.*$/dcredit = -1/' ${pwqual} /etc/security/pwquality.conf
grep ^dcredit /etc/security/pwquality.conf

#Ensure users provide at leaset one lowercase character - lcredit-1
sed -i 's/^# lcredit =.*$/lcredit = -1/' ${pwqual} /etc/security/pwquality.conf
grep ^lcredit /etc/security/pwquality.conf

#Ensure users provide at leaset one special character  - ocredit=-1
sed -i 's/^# ocredit =.*$/ocredit = -1/' ${pwqual} /etc/security/pwquality.conf
grep ^ocredit /etc/security/pwquality.conf

#Ensure  users provide at least one uppercase character - ucredit=-1
sed -i 's/^# ucredit =.*$/ucredit = -1/' ${pwqual} /etc/security/pwquality.conf
grep ^ucredit /etc/security/pwquality.conf

#Ensure lockout for failed password attempts is configured
sed -i '/# end of pam-auth-update config/ a auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' /etc/pam.d/common-auth

#Verify password re-use is limited - ensure the "remember option is 5 or more
sed -i '/# end of pam-auth-update config/ a password sufficient pam_unix.so remember=5' /etc/pam.d/common-password
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/common-password

#Verify password hashing algorithm is SHA-512
sed -i '/password sufficient pam_unix.so remember=5/ a password [success=1 default=ignore] pam_unix.so sha512' /etc/pam.d/common-password
egrep '^password\s+\S+\s+pam_unix.so' /etc/pam.d/common-password

echo -e "\e[93mPAM Done\e[0m"

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

#Add the banner CHUA CHECK
sudo cat > /etc/issue.net <<- EOF
********************************************************************
*                                                                  *
* This system is for the use of authorized users only.  Usage of   *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
EOF

echo -e "\e[93mSSH Done\e[0m"

login_defs=/etc/login.defs

#Ensure Password expiration is 90 days or less CHUA CHECK
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}
grep PASS_MAX_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 # Verify Users password expiration is 90 days or less

#Ensure minimum days between password changes is 1 or more CHUA CHECK
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}
grep PASS_MIN_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 # Verify users minimum days between password changes is 1 or more

#Ensure password expiration warning days is 7 or more CHUA CHECK
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}
grep PASS_WARN_AGE /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1  #Verify users password expiration warning days is 7

#Ensure inactive password lock is 90 days or less CHUA CHECK
useradd -D -f 30
useradd -D | grep INACTIVE
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1  #Verify Users have password inactivity set for 90 days

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
