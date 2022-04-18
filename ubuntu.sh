#!/bin/bash
##Update the OS with latest updates
apt-get -y update
apt-get -y upgrade

echo -e "\e[93mUpdates Done\e[0m"
systemctl enable crond              #Enable cron

#Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
stat /etc/crontab

#Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
stat /etc/cron.hourly

#Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
stat /etc/cron.daily

#Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
stat /etc/cron.weekly

#Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
stat /etc/cron.monthly

#Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
stat /etc/cron.d

#Ensure at/cron is restricted to authorized users
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

echo -e "\e[93mCron Done\e[0m"

#Ensure chargen services are not enabled CHUA CHECK
systemctl disable chargen-dgram
systemctl disable chargen-stream

#Ensure daytime services are not enabled CHUA CHECK
systemctl disable daytime-dgram
systemctl disable daytime-stream

#Ensure discard services are not enabled CHUA CHECK
systemctl disable discard-dgram
systemctl disable discard-stream

#Ensure echo services are not enabled CHUA CHECK
systemctl disable echo-dgram
systemctl disable echo-stream

#Ensure time services are not enabled CHUA CHECK
systemctl disable time-dgram
systemctl disable time-stream

#Ensure talk server is not enabled CHUA CHECK
systemctl disable talk

#Ensure telnet server is not enabled CHUA CHECK
systemctl disable telnet

#Ensure tftp server is not enabled CHUA CHECK
systemctl disable tftp

#Ensure rsync service is not enabled BAT LAI KHI CAN
systemctl disable rsync

#Ensure Avahi Server is not enabled #multicast DNS/DNS-SD service discovery CHUA CHECK
systemctl disable avahi-daemon

#Ensure CUPS is not enabled # will prevent printing from system CHUA CHECK
systemctl disable cups

#Ensure DHCP Server is not enabled CHUA CHECK
systemctl disable dhcpd

#Ensure LDAP server is not enabled CHUA CHECK
systemctl disable slapd

#Ensure NFS and RPC are not enabled CHUA CHECK
systemctl disable nfs
systemctl disable rpcbind

#Ensure DNS Server is not enabled OK
systemctl disable named

#Ensure FTP Server is not enabled BAT LAI KHI CAN
systemctl disable vsftpd

#Ensure HTTP server is not enabled #check for apache, apache2 BAT LAI KHI CAN
systemctl disable httpd

#Ensure IMAP and POP3 server is not enabled BAT LAI KHI CAN
systemctl disable dovecot

#Ensure Samba is not enabled CHUA CHECK
systemctl disable smb

# Ensure HTTP Proxy Server is not enabled BAT LAI KHI CAN
systemctl disable squid

#Ensure SNMP Server is not enabled CHUA CHECK
systemctl disable snmpd

#Ensure mail transfer agent is configured for local-only mode

#Ensure NIS Server is not enabled CHUA CHECK
systemctl disable ypserv

# Ensure mail transfer agent is configured for local-only mode CHUA CHECK
netstat -an | grep LIST | grep ":25[[:space:]]"

#Ensure NIS Client is not installed CHUA CHECK
apt-get -y remove ypbind

#Ensure talk client is not installed CHUA CHECK
apt-get -y remove talk

#Ensure rsh client is not installed CHUA CHECK
apt-get -y remove rsh

# Ensure telnet client is not installed CHUA CHECK
apt-get -y remove telnet

#Ensure LDAP client is not installed CHUA CHECK
apt-get -y remove openldap-clients

# Disable IPv6
sed -i -e 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' \
        /etc/default/grub
update-grub

# Remove Unnecessary Packages
#apt-get purge --auto-remove telnetd ftp vsftpd samba nfs-kernel-server nfs-common

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

#chown root:root /etc/ssh/sshd_config
#chmod og-rwx /etc/ssh/sshd_config

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
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
#echo MaxAuthTries 6 >> /etc/ssh/sshd_config
grep "^MaxAuthTries" /etc/ssh/sshd_config

#Ensure SSH IgnoreRhosts is enabled OK
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g'  /etc/ssh/sshd_config
grep  "^IgnoreRhosts" /etc/ssh/sshd_config

#Ensure SSH HostbasedAuthentication is disabled OK
sed -ri'' 's/^#*HostbasedAuthentication.*$/HostbasedAuthentication no/g' /etc/ssh/sshd_config && grep "^#*HostbasedAuthentication" /etc/ssh/sshd_config

#Ensure SSH root login is disabled OK
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config
grep "^PermitRootLogin" /etc/ssh/sshd_config

#Change SSH port OK
#sed -i 's/#Port 22/Port 13689/g' /etc/ssh/sshd_config
#service ssh restart

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

#Ensure SSH access is limited CHUA CHECK
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config

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
systemctl restart sshd
echo -e "\e[93mSSH Done\e[0m"

# Enable ufw
#ufw --force enable

# Keep UFW active after system restart
#sudo sed -i '6 i After=netfilter-persistent.service' /lib/systemd/system/ufw.service

# Download ufw-ddns.sh script
#curl -O https://raw.githubusercontent.com/NGUTU123/hardening_scripts/master/ufw-ddns.sh

# Run ufw-ddns.sh script every 2 minute
#chmod +x ufw-ddns.sh
#sudo crontab -l > cron.bak
#sudo echo "*/2 * * * * /home/ubuntu/ufw-ddns.sh" >> cron.bak
#sudo crontab cron.bak
#sudo rm cron.bak

#echo -e "\e[93mufw Done\e[0m"

# Ensure permissions on /etc/gshadow- are configured CHUA CHECK
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-
stat /etc/gshadow-

#Ensure permissions on /etc/group- are configured CHUA CHECK
chown root:root /etc/group-
chmod 600 /etc/group-
stat /etc/group-

#Ensure permissions on /etc/passwd- are configured CHUA CHECK
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
stat /etc/passwd-

#Ensure permissions on /etc/gshadow are configured CHUA CHECK
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
stat /etc/gshadow

#Ensure permissions on /etc/group are configured CHUA CHECK
chown root:root /etc/group
chmod 644 /etc/group
stat /etc/group

#Ensure permissions on /etc/passwd are configured CHUA CHECK
chown root:root /etc/passwd
chmod 644 /etc/passwd
stat /etc/passwd

#Ensure no world writable files exist CHUA CHECK
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print

#Ensure no ungrouped files or directories exist CHUA CHECK
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup

# Ensure no unowned files or directories exist CHUA CHECK
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser

for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/usr/bin/awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
for file in $dir/.[A-Za-z0-9]*; do
if [ ! -h "$file" -a -f "$file" ]; then
fileperm=`/bin/ls -ld $file | /usr/bin/cut -f1 -d" "`
if [ `echo $fileperm | /usr/bin/cut -c6 ` != "-" ]; then
echo "Group Write permission set on file $file"
fi
if [ `echo $fileperm | /usr/bin/cut -c9 ` != "-" ]; then
echo "Other Write permission set on file $file"
fi
fi
done
done

echo -e "\e[93mSystem File Permissions Done\e[0m"

login_defs=/etc/login.defs

#Ensure Password expiration is 90 days or less CHUA CHECK
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}
grep PASS_MAX_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 # Verify Users password expiration is 90 days or less

#Ensure minimum days between password changes is 1 or more CHUA CHECK
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}
grep PASS_MIN_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 # Verify users  minimum days between password changes is 1 or more

#Ensure password expiration warning days is 7 or more CHUA CHECK
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}
grep PASS_WARN_AGE /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1  #Verify users password expiration warning days is 7

#Ensure inactive password lock is 90 days or less CHUA CHECK
useradd -D -f 30
useradd -D | grep INACTIVE
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1  #Verify Users have password inactivity set for 90 days

#Ensure default user umask is 027 or more restrictive CHUA CHECK
sed -i '$ a umask 027' /etc/bash.bashrc
sed -i '$ a umask 027' /etc/profile

echo -e "\e[93mUser Account Done\e[0m"

#Ensure password fields are not empty CHUA CHECK
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'

#Ensure no legacy "+" entries exist in /etc/passwd CHUA CHECK
grep '^+:' /etc/passwd

#Ensure no legacy "+" entries exist in /etc/shadow CHUA CHECK
grep '^+:' /etc/shadow

#Ensure no legacy "+" entries exist in /etc/group CHUA CHECK
grep '^+:' /etc/group

#Ensure root is the only UID 0 account CHUA CHECK
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'

#Ensure root PATH Integrity CHUA CHECK
if [ "`echo $PATH | grep :: `" != "" ]; then
 echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | grep :$`" != "" ]; then
 echo "Trailing : in PATH"
fi
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
 if [ "$1" = "." ]; then
 echo "PATH contains ."
 shift
 continue
 fi
 if [ -d $1 ]; then
 dirperm=`ls -ldH $1 | cut -f1 -d" "`
 if [ `echo $dirperm | cut -c6 ` != "-" ]; then
 echo "Group Write permission set on directory $1"
 fi
 if [ `echo $dirperm | cut -c9 ` != "-" ]; then
 echo "Other Write permission set on directory $1"
 fi
 dirown=`ls -ldH $1 | awk '{print $3}'`
 if [ "$dirown" != "root" ] ; then
 echo $1 is not owned by root
 fi
 else
 echo $1 is not a directory
  fi
 shift
done


 #Ensure all users' home directories exist CHUA CHECK
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 fi
done

#Ensure users home directories permissions are 750 or more restrictive CHUA CHECK
for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 !="/sbin/nologin") {print $6}'`; do
 dirperm=`ls -ld $dir | cut -f1 -d" "`
 if [ `echo $dirperm | cut -c6 ` != "-" ]; then
 echo "Group Write permission set on directory $dir"
fi
if [ `echo $dirperm | cut -c8 ` != "-" ]; then
echo "Other Read permission set on directory $dir"
fi
if [ `echo $dirperm | cut -c9 ` != "-" ]; then
echo "Other Write permission set on directory $dir"
fi
if [ `echo $dirperm | cut -c10 ` != "-" ]; then
echo "Other Execute permission set on directory $dir"
fi
done


#Ensure users own their home directories CHUA CHECK
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
echo "The home directory ($dir) of user $user is owned by $owner."
fi
fi
done

#Ensure users dot files are not group or world writable CHUA CHECK

for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 !="/sbin/nologin") { print $6 }'`; do
for file in $dir/.[A-Za-z0-9]*; do
if [ ! -h "$file" -a -f "$file" ]; then
fileperm=`ls -ld $file | cut -f1 -d" "`
if [ `echo $fileperm | cut -c6 ` != "-" ]; then
echo "Group Write permission set on file $file"
fi
if [ `echo $fileperm | cut -c9 ` != "-" ]; then
echo "Other Write permission set on file $file"
fi
fi
 done
done


#Ensure no users have .forward files CHUA CHECK
for dir in `cat /etc/passwd |\
awk -F: '{ print $6 }'`; do
if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
echo ".forward file $dir/.forward exists"
fi
done

#Ensure no users have .netrc files CHUA CHECK
for dir in `cat /etc/passwd |\
awk -F: '{ print $6 }'`; do
if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
echo ".netrc file $dir/.netrc exists"
fi
done

#Ensure users .netrc Files are not group or world accessible CHUA CHECK
for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 !="/sbin/nologin") { print $6 }'`; do
for file in $dir/.netrc; do
if [ ! -h "$file" -a -f "$file" ]; then
fileperm=`ls -ld $file | cut -f1 -d" "`
if [ `echo $fileperm | cut -c5 ` != "-" ]; then
echo "Group Read set on $file"
fi
if [ `echo $fileperm | cut -c6 ` != "-" ]; then
echo "Group Write set on $file"
fi
if [ `echo $fileperm | cut -c7 ` != "-" ]; then
echo "Group Execute set on $file"
fi
if [ `echo $fileperm | cut -c8 ` != "-" ]; then
echo "Other Read set on $file"
fi
if [ `echo $fileperm | cut -c9 ` != "-" ]; then
echo "Other Write set on $file"
fi
if [ `echo $fileperm | cut -c10 ` != "-" ]; then
 echo "Other Execute set on $file"
fi
fi
done
done

#Ensure no users have .rhosts files CHUA CHECK
for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 !="/sbin/nologin") { print $6 }'`; do
for file in $dir/.rhosts; do
if [ ! -h "$file" -a -f "$file" ]; then
echo ".rhosts file in $dir"
fi
done
done


 #Ensure all groups in /etc/passwd exist in /etc/group CHUA CHECK
 for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
 grep -q -P "^.*?:[^:]*:$i:" /etc/group
 if [ $? -ne 0 ]; then
 echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
 fi
done

#Ensure no duplicate UIDs exist CHUA CHECK
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
echo "Duplicate UID ($2): ${users}"
fi
done

#Ensure no duplicate GIDs exist CHUA CHECK
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
echo "Duplicate GID ($2): ${groups}"
fi
done

#Ensure no duplicate user names exist CHUA CHECK
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
echo "Duplicate User Name ($2): ${uids}"
fi
done


 #Ensure no duplicate group names exist CHUA CHECK
 cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
echo "Duplicate Group Name ($2): ${gids}"
fi
done

echo -e "\e[93mUser and Group Done\e[0m"

##################################
## Enable Firewall and Iptables ##
##################################
# Flush IPtables rules
#iptables -F
# Ensure default deny firewall policy
#iptables -P INPUT DROP
#iptables -P OUTPUT DROP
#iptables -P FORWARD DROP
# Ensure loopback traffic is configured
#iptables -A INPUT -i lo -j ACCEPT
#iptables -A OUTPUT -o lo -j ACCEPT
#iptables -A INPUT -s 127.0.0.0/8 -j DROP
# Ensure outbound and established connections are configured
#iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 13689) connections
#iptables -A INPUT -p tcp --dport 13689 -m state --state NEW -j ACCEPT

# Run the following commands to implement a default DROP policy
#iptables -P INPUT DROP
#iptables -P OUTPUT DROP
#iptables -P FORWARD DROP
#iptables -L

# Run the following commands to implement the loopback rules
#iptables -A INPUT -i lo -j ACCEPT
#iptables -A OUTPUT -o lo -j ACCEPT
#iptables -A INPUT -s 127.0.0.0/8 -j DROP

# Configure iptables in accordance with site policy. The following commands will implement
# a policy to allow all outbound connections and all established connections:
#iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

#iptables -P INPUT ACCEPT
#iptables -P FORWARD ACCEPT
#iptables -P OUTPUT ACCEPT
#iptables -F
#netfilter-persistent save


########################
## Configure Auditing ##
########################
apt-get -y install auditd
service auditd reload
systemctl start auditd
systemctl enable auditd

cat > /etc/audit/auditd.conf <<-EOF
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 100
max_log_file_action = keep_logs
space_left = 75
space_left_action = email
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = SUSPEND
disk_error_action = SUSPEND
##tcp_listen_port =
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF


##############################################################
## Enable Auditing for Processes that Start Prior to auditd ##
##############################################################
sed -i '/GRUB_CMDLINE_LINUX=""/ a GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
update-grub
grep "^\s*linux" /boot/grub/grub.cfg

#########################################################
## Record Events that Modify Date and Time Information ##
#########################################################
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change 
-a always,exit -F arch=b32 -S clock_settime -k time-change 
-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules

######################################################
## Record Events that Modify User/Group Information ##
######################################################
echo "-w /etc/group -p wa -k identity 
-w /etc/passwd -p wa -k identity 
-w /etc/gshadow -p wa -k identity 
-w /etc/shadow -p wa -k identity 
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules

############################################################
## Record Events that Modify System's Network Environment ##
############################################################
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale 
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale 
-w /etc/issue -p wa -k system-locale 
-w /etc/issue.net -p wa -k system-locale 
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules

#########################################################
## Record Events that Modify Mandatory Access Controls ##
#########################################################
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules

#####################################
## Collect Login and Logout Events ##
#####################################
echo "-w /var/log/faillog -p wa -k logins 
-w /var/log/lastlog -p wa -k logins 
-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules

############################################
## Collect Session Initiation Information ##
############################################
echo "-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k session 
-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules

#########################################################################
## Collect Discretionary Access Control Permission Modification Events ##
#########################################################################
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules

###############################################################
## Collect Unsuccessful Unauthorised Access Attemps to Files ##
###############################################################
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules

########################################
## Collect Use of Privileged Commands ##
########################################
echo "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/audit.rules

###########################################
## Collect Successful File System Mounts ##
###########################################
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts 
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules

##########################################
## Collect File Deletion Events by User ##
##########################################
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete 
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules

####################################################
## Collect Changes to System Administration Scope ##
####################################################
echo "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/rules.d/audit.rules

##########################################
## Collect System Administrator Actions ##
##########################################
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules

#################################################
## Collect Kernel Module Loading and Unloading ##
#################################################
echo "-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules

############################################
## Make the Audit Configuration Immutable ##
############################################
echo "-e 2" >> /etc/audit/rules.d/audit.rules

pkill -HUP -P 1 auditd

# Ensure rsyslog Service is enabled
systemctl is-enabled rsyslog

######################
## Configure Syslog ##
######################
cat >> /etc/rsyslog.conf <<-EOF
*.emerg :omusrmsg:*
mail.* -/var/log/mail
mail.info -/var/log/mail.info
mail.warning -/var/log/mail.warn
mail.err /var/log/mail.err
news.crit -/var/log/news/news.crit
news.err -/var/log/news/news.err
news.notice -/var/log/news/news.notice
*.=warning;*.=err -/var/log/warn
*.crit /var/log/warn
*.*;mail.none;news.none -/var/log/messages
local0,local1.* -/var/log/localmessages
local2,local3.* -/var/log/localmessages
local4,local5.* -/var/log/localmessages
local6,local7.* -/var/log/localmessages
EOF

pkill -HUP rsyslogd
grep ^\$FileCreateMode /etc/rsyslog.conf

##  Ensure syslog-ng service is enabled
apt-get install -y syslog-ng
update-rc.d syslog-ng enable
systemctl is-enabled syslog-ng

#  ensure that log files exist and have the correct permissions to ensure that sensitive syslog-ng data is archived and protected
sed -i 's/options { chain_hostnames(off); flush_lines(0); use_dns(no); use_fqdn(no);/options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };/' /etc/syslog-ng/syslog-ng.conf

##################
## Enable Crond ##
##################
systemctl enable crond
systemctl is-enabled cron

###########################################
## Set User/Group Permissions on Anacron ##
###########################################
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab

########################################
## Set User/Group Permissions on Cron ##
########################################
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

########################
## Restrict At Daemon ##
########################
rm -f /etc/at.deny
rm -f /etc/cron.deny
touch /etc/at.allow
touch /etc/cron.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chmod og-rwx /etc/cron.allow

echo -e "\e[93mAudit and firewalld  Done\e[0m"
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
