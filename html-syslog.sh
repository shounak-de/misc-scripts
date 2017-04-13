#!/bin/sh
DEFAULT_LOG="/tmp/syslog.log"
[ -L "$DEFAULT_LOG" ] && LogFile=$(readlink $DEFAULT_LOG) || LogFile="$DEFAULT_LOG"
if [ -L "/www/user" ]; then
  sed -i '1s/^/<pre>/' $LogFile
  [ -L "/www/user/log.html" ] || ln -s $LogFile /www/user/log.html
  grep -q "router.asus.com" /etc/hosts && router="router.asus.com" || router=$(nvram get lan_ipaddr)
  httpd_ps=$(ps | grep "[h]ttpd ")
  if [ -n "$httpd_ps" ]; then
    httpd_port=$(ps | grep "[h]ttpd " | sed -n "s/^.*-p //p" | awk '{print $1}')
    [ -z "$httpd_port" -o "$httpd_port" = "80" ] || append=":$httpd_port"
  else
    httpds_port=$(ps | grep "[h]ttpds " | sed -n "s/^.*-p //p" | awk '{print $1}')
    [ -z "$httpds_port" -o "$httpds_port" = "443" ] || append=":$httpds_port"
    s=s
  fi
  echo "You can now access $(basename $DEFAULT_LOG) from http${s}://${router}${append}/user/log.html"
else
  echo "This script is not for you, sorry :("
fi
