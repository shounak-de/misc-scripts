#!/bin/sh
DEFAULT_LOG="/tmp/syslog.log"
[ -L "$DEFAULT_LOG" ] && LogFile=$(readlink $DEFAULT_LOG) || LogFile="$DEFAULT_LOG"
if [ -L "/www/user" ]; then
  sed -i '1s/^/<pre>/' $LogFile
  ln -s $LogFile /www/user/log.html
  grep -q "router.asus.com" /etc/hosts && router="router.asus.com" || router=$(nvram get lan_ipaddr)
  echo "You can now access syslog from http://${router}/user/log.html"
else
  echo "This script is not for you, sorry :("
fi
