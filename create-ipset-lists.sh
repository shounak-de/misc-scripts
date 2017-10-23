#!/bin/sh 
# snbforums thread:
# https://www.snbforums.com/threads/country-blocking-script.36732/page-2#post-311407

# Re-download blocklist if locally saved blocklist is older than this many days
BLOCKLISTS_SAVE_DAYS=15

# For the users of mips routers (kernel 2.x): You can now block sources with IPv6 with country blocklists
# Enable if you want to add huge country IPv6 netmask lists directly into ip6tables rules.
# Also, enabling this will add a *lot* of processing time!
# Note: This has no effect *if* you have ipset v6: It will always use ipset v6 for IPv6 country blocklists regardless of whether this is enabled or not.
USE_IP6TABLES_IF_IPSETV6_UNAVAILABLE=disabled # [enabled|disabled]

# Block incoming traffic from some countries. cn and pk is for China and Pakistan. See other countries code at http://www.ipdeny.com/ipblocks/
BLOCKED_COUNTRY_LIST="ar au br cn de fr jp kp kr pk ru sa sc tr tw ua vn"

# Use DROP or REJECT for iptable rule for the ipset. Briefly, for DROP, attacker (or IP being blocked) will get no response and timeout, and REJECT will send immediate response of destination-unreachable (Attacker will know your IP is actively rejecting requests)
# See: http://www.chiark.greenend.org.uk/~peterb/network/drop-vs-reject and http://serverfault.com/questions/157375/reject-vs-drop-when-using-iptables
IPTABLES_RULE_TARGET=DROP # [DROP|REJECT]

# Preparing folder to cache downloaded files
IPSET_LISTS_DIR=/jffs/ipset_lists
[ -d "$IPSET_LISTS_DIR" ] || mkdir -p $IPSET_LISTS_DIR

# Different routers got different iptables and ipset syntax
case $(ipset -v | grep -o "v[4,6]") in
  v6)
    MATCH_SET='--match-set'; CREATE='create'; ADD='add'; SWAP='swap'; TEST='test'; DELETE='del'; FLUSH='flush'; IPHASH='hash:ip'; NETHASH='hash:net family inet'; NETHASH6='hash:net family inet6'; SETNOTFOUND='name does not exist'
    # Loading ipset modules
    lsmod | grep -q "xt_set" || \
    for module in ip_set ip_set_hash_net ip_set_hash_ip xt_set; do
      modprobe $module
    done;;
  v4)
    MATCH_SET='--set'; CREATE='--create'; ADD='--add'; SWAP='--swap'; TEST='--test'; DELETE='--del'; FLUSH='--flush'; IPHASH='iphash'; NETHASH='nethash'; SETNOTFOUND='Unknown set'
    # Loading ipset modules
    lsmod | grep -q "ipt_set" || \
    for module in ip_set ip_set_nethash ip_set_iphash ipt_set; do
      modprobe $module
    done;;
  *)
    logger -t Firewall "$0: Unknown ipset version: $(ipset -v). Exiting."
    exit 1;;
esac

# Wait if this is run early on (before the router has internet connectivity) [Needed by wget to download files]
while ! ping -q -c 1 google.com &>/dev/null; do
  sleep 1
  WaitSeconds=$((WaitSeconds+1))
  [ $WaitSeconds -gt 300 ] && logger -t Firewall "$0: Warning: Router not online! Aborting after a wait of 5 minutes..." && exit 1
done
# Block traffic from Tor nodes [IPv4 nodes only]
if [ ! -s "$IPSET_LISTS_DIR/tor.lst" -o -n "$(find $IPSET_LISTS_DIR/tor.lst -mtime +$BLOCKLISTS_SAVE_DAYS -print 2>/dev/null)" ]; then
  $(ipset -q $SWAP BlockedCountries BlockedCountries) && ipset $DELETE BlockedCountries 194.63.140.0/22 2>/dev/null
  wget -q -O $IPSET_LISTS_DIR/tor.lst "http://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv"
  touch $IPSET_LISTS_DIR/tor.lst
  Action="Add"
  $(ipset -q $SWAP TorNodes TorNodes) && ipset $FLUSH TorNodes && Action="Reload"
fi
if $(ipset $SWAP TorNodes TorNodes 2>&1 | grep -q "$SETNOTFOUND"); then
  ipset $CREATE TorNodes $IPHASH
  Action="Add"
fi
if [ -n "${Action}" ]; then
  entryCount=0
  for IP in $(cat $IPSET_LISTS_DIR/tor.lst); do
    ipset $ADD TorNodes $IP
    [ $? -eq 0 ] && entryCount=$((entryCount+1))
  done
  logger -t Firewall "$0: ${Action}ed TorNodes list ($entryCount entries)"
  unset Action
fi
iptables-save | grep -q TorNodes || iptables -I INPUT -m set $MATCH_SET TorNodes src -j $IPTABLES_RULE_TARGET

# Country blocking by nethashes [Both IPv4 and IPv6 sources]
for country in ${BLOCKED_COUNTRY_LIST}; do
  if [ ! -e "$IPSET_LISTS_DIR/$country.lst" -o -n "$(find $IPSET_LISTS_DIR/$country.lst -mtime +$BLOCKLISTS_SAVE_DAYS -print 2>/dev/null)" ]; then
    wget -q -O $IPSET_LISTS_DIR/$country.lst "http://www.ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone"
    touch $IPSET_LISTS_DIR/$country.lst
    Action="Reload"
  fi
  [ "${Action}" == "Reload" ] && $(ipset -q $SWAP BlockedCountries BlockedCountries) && ipset $FLUSH BlockedCountries
done
if $(ipset $SWAP BlockedCountries BlockedCountries 2>&1 | grep -q "$SETNOTFOUND"); then
  ipset $CREATE BlockedCountries $NETHASH
  Action="Add"
fi
for country in ${BLOCKED_COUNTRY_LIST}; do
  if [ -n "${Action}" ]; then
    entryCount=0
    for IP in $(cat $IPSET_LISTS_DIR/$country.lst); do
      ipset $ADD BlockedCountries $IP
      [ $? -eq 0 ] && entryCount=$((entryCount+1))
    done
    logger -t Firewall "$0: ${Action}ed country [$country] to BlockedCountries list ($entryCount entries)"
  fi
done
iptables-save | grep -q BlockedCountries || iptables -I INPUT -m set $MATCH_SET BlockedCountries src -j $IPTABLES_RULE_TARGET
unset Action

if [ $(nvram get ipv6_fw_enable) -eq 1 -a "$(nvram get ipv6_service)" != "disabled" ]; then
  for country in ${BLOCKED_COUNTRY_LIST}; do
    if [ -n "$NETHASH6" -o $USE_IP6TABLES_IF_IPSETV6_UNAVAILABLE = "enabled" ] && [ ! -e "$IPSET_LISTS_DIR/${country}6.lst" -o -n "$(find $IPSET_LISTS_DIR/${country}6.lst -mtime +$BLOCKLISTS_SAVE_DAYS -print 2>/dev/null)" ]; then
      wget -q -O $IPSET_LISTS_DIR/${country}6.lst "http://www.ipdeny.com/ipv6/ipaddresses/aggregated/${country}-aggregated.zone"
      touch $IPSET_LISTS_DIR/${country}6.lst
      Action="Reload"
    fi
  done
  [ "${Action}" == "Reload" ] && $(ipset -q $SWAP BlockedCountries6 BlockedCountries6) && ipset $FLUSH BlockedCountries6
  if $(ipset $SWAP BlockedCountries6 BlockedCountries6 2>&1 | grep -q "$SETNOTFOUND"); then
    [ -n "$NETHASH6" ] && ipset $CREATE BlockedCountries6 $NETHASH6 && Action="Add"
  fi
  for country in ${BLOCKED_COUNTRY_LIST}; do
    [ -e "/tmp/ipv6_country_blocks_loaded" ] && logger -t Firewall "$0: Country block rules has already been loaded into ip6tables... Skipping." && break
    entryCount=0
    if [ -n "${Action}" ]; then
      for IP6 in $(cat $IPSET_LISTS_DIR/${country}6.lst); do
        if [ -n "$NETHASH6" ]; then
          ipset $ADD BlockedCountries6 $IP6
        elif [ $USE_IP6TABLES_IF_IPSETV6_UNAVAILABLE = "enabled" ]; then
          ip6tables -I INPUT -s $IP6 -j $IPTABLES_RULE_TARGET
        fi
        [ $? -eq 0 ] && entryCount=$((entryCount+1))
      done
      if [ -n "$NETHASH6" ]; then
        logger -t Firewall "$0: ${Action}ed country [$country] to BlockedCountries6 list ($entryCount entries)"
      elif [ $USE_IP6TABLES_IF_IPSETV6_UNAVAILABLE = "enabled" ]; then
        logger -t Firewall "$0: Added country [$country] to ip6tables rules ($entryCount entries)"
      fi
    fi
  done
  if [ -n "$NETHASH6" ]; then
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

# Allow traffic from AllowList [IPv4 only] [$IPSET_LISTS_DIR/whitelist.lst can contain a combination of IPv4 IP or IPv4 netmask] (previous)
# Allow traffic from AllowList [IPv4 only] [$IPSET_LISTS_DIR/whitelist.lst can contain IPv4 IPs] (current)
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
