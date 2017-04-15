#!/bin/sh

NaughtyIPTempFile="/tmp/naughty.$$"
NaughtyIPSaveFile="/tmp/naughty.save"
MemSyslog="/tmp/syslog.log"
GREP="/opt/bin/grep"
AttackCSV="/tmp/mnt/NAS/rt-ac66r/logs/attacks/Attacks-$(date "+%b-%Y").csv" # Change this line to an appropriate location available on your router

SymLog="$(readlink $MemSyslog)"
LogFile=${SymLog:-$MemSyslog}

[ ! -t 1 ] && sleep 57 # Hack to have cru run the script just before minute end
JunkPattern01="invalid password or cipher"
JunkPattern02="rehashing of set"
JunkPattern03="Transport endpoint is not connected"
JunkPattern04="Connection reset by peer"
JunkPattern05="Connection timed out"
JunkPattern06="No route to host"
JunkPattern07="Sending HTTP 501"
JunkPattern08="Couldn't set SO_PRIORITY"
JunkPattern09="ACCEPT IN=br0 "
JunkPattern10="DROP IN=eth0 OUT= MAC=xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx <1>SRC=" # Change this line to copy your routers MAC
sed -i "/PROTO=ICMP/d \
        /SPT=5353 DPT=5353/d \
        /SPT=67 DPT=68/d \
        /DROP IN=eth0 OUT=br0/d \
        /${JunkPattern02}/d \
        /${JunkPattern03}/d \
        /${JunkPattern04}/d \
        /${JunkPattern05}/d \
        /${JunkPattern06}/d \
        /${JunkPattern07}/d \
        /${JunkPattern08}/d \
        /${JunkPattern09}/d \
        /${JunkPattern10}/d" ${LogFile}

ShadowHandshake="failed to handshake with "
ShadowAuth="authentication error from "
SSHNonExistent="Login attempt for nonexistent user from "
SSHMultipleUser="Client trying multiple usernames from "
SSHBadPassword="Bad password attempt for 'admin' from "

$GREP -oP "(?<=${SSHNonExistent})[^:]+" ${LogFile} >> ${NaughtyIPTempFile} && CauseList="${CauseList} SSHNonExistent"
$GREP -oP "(?<=${SSHMultipleUser})[^:]+" ${LogFile} >> ${NaughtyIPTempFile} && CauseList="${CauseList} SSHMultipleUser"
$GREP -oP "(?<=${SSHBadPassword})[^:]+" ${LogFile} >> ${NaughtyIPTempFile} && CauseList="${CauseList} SSHBadPassword"
$GREP -oP "(?<=${ShadowHandshake})[^ ]+" ${LogFile} >> ${NaughtyIPTempFile} && CauseList="${CauseList} ShadowHandshake"
$GREP -oP "(?<=${ShadowAuth})[^ ]+" ${LogFile} >> ${NaughtyIPTempFile} && CauseList="${CauseList} ShadowAuth"

AcceptMatchPattern="ACCEPT IN=eth0 OUT= MAC=xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx <1>SRC=" # Change this line to copy your routers MAC
#LivePorts="20 21 22 25 110"
LivePorts="22"
for port in $LivePorts; do
  grepPorts="$grepPorts-e DPT=$port "
done
$GREP "${AcceptMatchPattern}" ${LogFile} | $GREP $grepPorts | $GREP -oP "(?<=${AcceptMatchPattern})[^ ]+" >> ${NaughtyIPTempFile} && CauseList="${CauseList} LivePortMatch"

sort ${NaughtyIPTempFile} -nuo ${NaughtyIPTempFile}
ipCount=0
for ip in $(cat ${NaughtyIPTempFile}); do
  ipset --add CustomBlock $ip
  if [ $? -eq 0 ]; then
    ipCount=$((ipCount+1))
    if [ -d "$(dirname $AttackCSV)" ]; then
      [ ! -s "$AttackCSV" ] && echo "Date-Time,IP,Hostname,City,Region,Country,Postal,Latitute,Longitude,Organization,Attack Type" >$AttackCSV
      ipinfo=$(wget -qO - http://ipinfo.io/$ip)
      host=$(echo $ipinfo | cut -d '"' -f 8)
      city=$(echo $ipinfo | cut -d '"' -f 12)
      region=$(echo $ipinfo | cut -d '"' -f 16)
      country=$(echo $ipinfo | cut -d '"' -f 20)
      latlong=$(echo $ipinfo | cut -d '"' -f 24)
      org=$(echo $ipinfo | cut -d '"' -f 28)
      zip=$(echo $ipinfo | cut -d '"' -f 32)
      echo "$(date "+%x %X"),$ip,$host,$city,$region,$country,$zip,$latlong,\"$org\",$CauseList" >>$AttackCSV
    fi
  fi
done
[ $ipCount -gt 0 ] && logger -t Firewall "$0: Added $ipCount IPs to CustomBlock list:$CauseList"
cat ${NaughtyIPTempFile} >> ${NaughtyIPSaveFile}
rm -f ${NaughtyIPTempFile}
sed -i "/${AcceptMatchPattern}.*DPT=22 SEQ=/d \
        /${ShadowHandshake}/d \
        /${ShadowAuth}/d \
        /${SSHNonExistent}/d \
        /${SSHMultipleUser}/d \
        /${SSHBadPassword}/d" ${LogFile}
