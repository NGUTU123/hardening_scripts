#!/bin/bash
##Update the OS with latest updates
yum -y update
yum -y install wget

echo -e "\e[93mUpdates and Wget Done\e[0m"
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

#Ensure chargen services are not enabled
chkconfig chargen-dgram off
chkconfig chargen-stream off

#Ensure daytime services are not enabled
chkconfig daytime-dgram off
chkconfig daytime-stream off

#Ensure discard services are not enabled
chkconfig discard-dgram off
chkconfig discard-stream off

#Ensure echo services are not enabled
chkconfig echo-dgram off
chkconfig echo-stream off

#Ensure time services are not enabled
chkconfig time-dgram off
chkconfig time-stream off

#Ensure rsh server is not enabled
chkconfig rexec off
chkconfig rsh off
chkconfig rlogin off

#Ensure talk server is not enabled
chkconfig talk off

#Ensure telnet server is not enabled
chkconfig telnet off

#Ensure tftp server is not enabled
chkconfig tftp off

#Ensure rsync service is not enabled
chkconfig rsync off

#Ensure xinetd is not enabled
systemctl disable xinetd

#Ensure X Window System is not installed
yum remove xorg-x11*

#Ensure Avahi Server is not enabled #multicast DNS/DNS-SD service discovery
systemctl disable avahi-daemon

#Ensure CUPS is not enabled # will prevent printing from system
systemctl disable cups

#Ensure DHCP Server is not enabled
systemctl disable dhcpd

#Ensure LDAP server is not enabled
systemctl disable slapd

#Ensure NFS and RPC are not enabled
systemctl disable nfs
systemctl disable rpcbind

#Ensure DNS Server is not enabled
systemctl disable named

#Ensure FTP Server is not enabled
systemctl disable vsftpd

#Ensure HTTP server is not enabled #check for apache, apache2
systemctl disable httpd

#Ensure IMAP and POP3 server is not enabled
systemctl disable dovecot

#Ensure Samba is not enabled
systemctl disable smb

# Ensure HTTP Proxy Server is not enabled
systemctl disable squid

#Ensure SNMP Server is not enabled
systemctl disable snmpd

#Ensure mail transfer agent is configured for local-only mode

#Ensure NIS Server is not enabled
systemctl disable ypserv

# Ensure mail transfer agent is configured for local-only mode
netstat -an | grep LIST | grep ":25[[:space:]]"

#Ensure NIS Client is not installed
yum remove ypbind

#Ensure talk client is not installed
yum remove talk

#Ensure rsh client is not installed
yum remove rsh

# Ensure telnet client is not installed
yum remove telnet


#Ensure LDAP client is not installed
yum remove openldap-clients

echo -e "\e[93mOS services Done\e[0m"

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

#Ensure SSH protocolis set to 2
sed -i 's/#Protocol 2/Protocol 2/g'  /etc/ssh/sshd_config
grep "^Protocol" /etc/ssh/sshd_config

#Ensure SSH LogLevel is set to INFO
sed -i 's/#LogLevel INFO/Loglevel INFO/g' /etc/ssh/sshd_config
grep "^LogLevel" /etc/ssh/sshd_config

#Ensure X11 forwading is disabled
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
grep "^X11Forwarding" /etc/ssh/sshd_config

#Ensure SSH MaxAuthTries is set to 6 or less
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
#echo MaxAuthTries 6 >> /etc/ssh/sshd_config
grep "^MaxAuthTries" /etc/ssh/sshd_config

#Ensure SSH IgnoreRhosts is enabled
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g'  /etc/ssh/sshd_config
grep  "^IgnoreRhosts" /etc/ssh/sshd_config

#Ensure SSH HostbasedAuthentication is disabled
sed -i 's/#HostBasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
grep "^HostbasedAuthentication" /etc/ssh/sshd_config

#Ensure SSH root login is disabled
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
grep "^PermitRootLogin" /etc/ssh/sshd_config

#Ensure SSH PermitEmptyPasswords is disabled
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g'  /etc/ssh/sshd_config
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config

#Ensure SSH PermitUserEnvironment is disabled
sed -i 's/#PermitUserEnvironment yes/PermitUserEnvironment no/g' /etc/ssh/sshd_config
#echo  PermitUserEnvironment no >> /etc/ssh/sshd_config
grep "^PermitUserEnvironment" /etc/ssh/sshd_config

#Ensure only approved ciphers are used
sed -i '/# Ciphers/ a Ciphers aes128-ctr,aes192-ctr,aes256-ctr' /etc/ssh/sshd_config
grep "Ciphers" /etc/ssh/sshd_config

#Ensure only approved MAC algorithms  are used
sudo sed -i '/# Ciphers and keying/ a MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' /etc/ssh/sshd_config
grep "MACs" /etc/ssh/sshd_config

#Ensure SSH Idle Timeout Interval is configured
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/ClientCountMax 3/ClientCountMax 0/g' /etc/ssh/sshd_config
grep "^ClientAliveInterval" /etc/ssh/sshd_config
grep "^ClientAliveCountMax" /etc/ssh/sshd_config

#Ensure SSH LoginGraceTime is set to one minute or less
sed -i '/#LoginGraceTime/ a LoginGraceTime 60' /etc/ssh/sshd_config
grep "^LoginGraceTime" /etc/ssh/sshd_config

#Ensure SSH access is limited
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config

#Ensure SSH warning banner is configured
sed -i 's/#Banner none/Banner \/etc\/issue\.net/g'  /etc/ssh/sshd_config
grep "^Banner" /etc/ssh/sshd_config

#Add the banner
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

# Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-
stat /etc/gshadowAccess

#Ensure permissions on /etc/group- are configured
chown root:root /etc/group-
chmod 600 /etc/group-
stat /etc/groupAccess

#Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow-
chmod 600 /etc/shadow-
stat /etc/shadowAccess

#Ensure permissions on /etc/passwd- are configured
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
stat /etc/passwdAccess

#Ensure permissions on /etc/gshadow are configured
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
stat /etc/gshadow

#Ensure permissions on /etc/group are configured
chown root:root /etc/group
chmod 644 /etc/group
stat /etc/group

#Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chmod 000 /etc/shadow
stat /etc/shadow

#Ensure permissions on /etc/passwd are configured
chown root:root /etc/passwd
chmod 644 /etc/passwd
stat /etc/passwd


#Ensure no world writable files exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print

#Ensure no ungrouped files or directories exist
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup

# Ensure no unowned files or directories exist
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

#Ensure password fields are not empty
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'

#Ensure no legacy "+" entries exist in /etc/passwd
grep '^+:' /etc/passwd

#Ensure no legacy "+" entries exist in /etc/shadow
grep '^+:' /etc/shadow

#Ensure no legacy "+" entries exist in /etc/group
grep '^+:' /etc/group

#Ensure root is the only UID 0 account
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'

#Ensure root PATH Integrity
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


 #Ensure all users' home directories exist
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 fi
done

#Ensure users home directories permissions are 750 or more restrictive
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


#Ensure users own their home directories
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
echo "The home directory ($dir) of user $user is owned by $owner."
fi
fi
done

#Ensure users dot files are not group or world writable

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


#Ensure no users have .forward files
for dir in `cat /etc/passwd |\
awk -F: '{ print $6 }'`; do
if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
echo ".forward file $dir/.forward exists"
fi
done

#Ensure no users have .netrc files
for dir in `cat /etc/passwd |\
awk -F: '{ print $6 }'`; do
if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
echo ".netrc file $dir/.netrc exists"
fi
done

#Ensure users .netrc Files are not group or world accessible
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

#Ensure no users have .rhosts files
for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 !="/sbin/nologin") { print $6 }'`; do
for file in $dir/.rhosts; do
if [ ! -h "$file" -a -f "$file" ]; then
echo ".rhosts file in $dir"
fi
done
done


 #Ensure all groups in /etc/passwd exist in /etc/group
 for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
 grep -q -P "^.*?:[^:]*:$i:" /etc/group
 if [ $? -ne 0 ]; then
 echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
 fi
done

#Ensure no duplicate UIDs exist
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
echo "Duplicate UID ($2): ${users}"
fi
done

#Ensure no duplicate GIDs exist
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
echo "Duplicate GID ($2): ${groups}"
fi
done

#Ensure no duplicate user names exist
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
echo "Duplicate User Name ($2): ${uids}"
fi
done


 #Ensure no duplicate group names exist
 cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
echo "Duplicate Group Name ($2): ${gids}"
fi
done

echo -e "\e[93mUser and Group Done\e[0m"

##########################################################
## Enable Firewalld 
## Not in this case as it causes issues and the host is ##
## already behind 2 firewalls without internet access   ##
#########################################################
#yum install firewalld -y
#systemctl enable firewalld
#systemctl start firewalld


########################
## Configure Auditing ##
########################
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
echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

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
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules

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

#########################
## Configure Logrotate ##
#########################

####################
## Enable Anacron ##
####################
yum install cronie-anacron -y

##################
## Enable Crond ##
##################
systemctl enable crond

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

echo -e "\e[32mAll Done\e[0m"

##Reboot of server
echo -e "\e[31mHere comes the reboot. Brace for Alerts\e[0m"
reboot
