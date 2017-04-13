#!/bin/sh
# Author: redhat27
# snbforums thread: https://www.snbforums.com/threads/fun-with-www-user.38546/

[ -z "$1" ] && echo "$0: Specify a directory on the router you want to expose!" && exit 1
[ ! -d "$1" ] && echo "$0: Cannot find the directory $1 on this router!" && exit 2
ps_line=$(ps | grep [l]ighttpd)
if [ -n "$ps_line" ]; then
  root=$(cat ${ps_line##* } | sed -n 's/"//g;/document-root/s/^.*= //p')
  port=$(cat ${ps_line##* } | sed -n 's/"//g;/port/s/^.*= //p') 
  base=${1#/} base=${base%%/*}
  [ ! -L "$root/$base" ] && ln -s /$base $root/$base
  echo -e "Created symlink $root/$base and $root/$(basename $1).html\nPlease remove [rm -f $root/$base $root/$(basename $1).html] to undo the changes!"
  append=":$port"
else
  Complain="<br>This page would work so much better if you had lighttpd installed and running. If you have entware, you can install it with <b>opkg install lighttpd</b><br>Right now, you can only see the file listings inside of $1, but will not be able to see the contents or download any of the files. Sad :(<br>"
  root="/www/user"
  append="/user"
fi

OUT="$root/$(basename $1).html" 
echo -e "<!DOCTYPE html>\n<head>\n\t<title>Listing of ${1}</title>\n</head>\n<body style=\"background-color:rgba(240,248,255,0.7); font-family:'Lucida Console', Monaco, monospace;\">\n${Complain}<br><h1>Listing of $1 on router</h1><br>\n<ul>" > $OUT
find "$1" -type d | sort | while read dir; do
  echo -e "  <li><b>$dir</b></li>\n  <ul>" >> $OUT
    find "$dir" -maxdepth 1 -type f | sort | while read filepath; do
    [ -z "$Complain" ] && echo "    <li><a href=\"${filepath:1}\">$(basename "$filepath")</a></li>" >> $OUT || echo "    <li>$(basename "$filepath")</li>" >> $OUT
  done
  echo "  </ul>" >> $OUT
done
echo -en "</ul>\n</body>" >> $OUT
grep -q "router.asus.com" /etc/hosts && router="router.asus.com" || router=$(nvram get lan_ipaddr)
echo "You can now see the listing of $1 from http://${router}${append}/$(basename $1).html"
