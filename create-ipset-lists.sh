    ip6tables -L | grep -q BlockedCountries6 || ip6tables -I INPUT -m set $MATCH_SET BlockedCountries6 src -j $IPTABLES_RULE_TARGET
  elif [ $USE_IP6TABLES_IF_IPSETV6_UNAVAILABLE = "enabled" -a ! -e "/tmp/ipv6_country_blocks_loaded" ]; then
    logger -t Firewall "$0: Creating [/tmp/ipv6_country_blocks_loaded] to prevent accidental reloading of country blocklists in ip6table rules."
    touch /tmp/ipv6_country_blocks_loaded
  fi
fi

# Block Microsoft telemetry spying servers [IPv4 only]
if $(ipset $SWAP MicrosoftSpyServers MicrosoftSpyServers 2>&1 | grep -q "$SETNOTFOUND"); then
  ipset $CREATE MicrosoftSpyServers $IPHASH
  [ $? -eq 0 ] && entryCount=0
  for IP in 23.99.10.11 63.85.36.35 63.85.36.50 64.4.6.100 64.4.54.22 64.4.54.32 64.4.54.254 \
        65.52.100.7 65.52.100.9 65.52.100.11 65.52.100.91 65.52.100.92 65.52.100.93 65.52.100.94 \
        65.55.29.238 65.55.39.10 65.55.44.108 65.55.163.222 65.55.252.43 65.55.252.63 65.55.252.71 \
        65.55.252.92 65.55.252.93 66.119.144.157 93.184.215.200 104.76.146.123 111.221.29.177 \
        131.107.113.238 131.253.40.37 134.170.52.151 134.170.58.190 134.170.115.60 134.170.115.62 \
        134.170.188.248 157.55.129.21 157.55.133.204 157.56.91.77 168.62.187.13 191.234.72.183 \
        191.234.72.186 191.234.72.188 191.234.72.190 204.79.197.200 207.46.223.94 207.68.166.254; do
    ipset $ADD MicrosoftSpyServers $IP
    [ $? -eq 0 ] && entryCount=$((entryCount+1))
  done
  logger -t Firewall "$0: Added MicrosoftSpyServers list ($entryCount entries)"
fi
iptables-save | grep -q MicrosoftSpyServers || iptables -I FORWARD -m set $MATCH_SET MicrosoftSpyServers dst -j $IPTABLES_RULE_TARGET

# Block traffic from custom block list [IPv4 only]
if [ -e $IPSET_LISTS_DIR/custom.lst ]; then
  if $(ipset $SWAP CustomBlock CustomBlock 2>&1 | grep -q "$SETNOTFOUND"); then
    ipset $CREATE CustomBlock $IPHASH
    [ $? -eq 0 ] && entryCount=0
    for IP in $(cat $IPSET_LISTS_DIR/custom.lst); do
      ipset $ADD CustomBlock $IP
      [ $? -eq 0 ] && entryCount=$((entryCount+1))
    done
    logger -t Firewall "$0: Added CustomBlock list ($entryCount entries)"
  fi
  iptables-save | grep -q CustomBlock || iptables -I INPUT -m set $MATCH_SET CustomBlock src -j $IPTABLES_RULE_TARGET
fi

# Allow traffic from AllowList [IPv4 only] [$IPSET_LISTS_DIR/whitelist.lst can contain IPv4 IPs]
if [ -e $IPSET_LISTS_DIR/whitelist.lst ]; then
  if $(ipset $SWAP AllowList AllowList 2>&1 | grep -q "$SETNOTFOUND"); then
    ipset $CREATE AllowList $IPHASH #(was $NETHASH)
    [ $? -eq 0 ] && entryCount=0
    for IP in $(cat $IPSET_LISTS_DIR/whitelist.lst); do
      #[ "${IP##*/}" == "$IP" ] && ipset $ADD AllowList $IP/31 || ipset $ADD AllowList $IP
      ipset $ADD AllowList $IP
      [ $? -eq 0 ] && entryCount=$((entryCount+1))
    done
    logger -t Firewall "$0: Added AllowList ($entryCount entries)"
  fi
  iptables-save | grep -q AllowList || iptables -I INPUT -m set $MATCH_SET AllowList src -j ACCEPT
fi
