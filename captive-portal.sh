#!/bin/sh

########
# Refs:
# http://www.cybersecurityguy.com/Building_a_Raspberry_Pi_Captive_Portal_Wi-Fi_Hotspot.pdf
# ----> https://andrewwippler.com/2016/03/11/wifi-captive-portal/ <----
# https://www.shellvoide.com/wifi/how-to-setup-captive-portal-login-with-rogue-ap-nginx/
# www.andybev.com/index.php/Using_iptables_and_PHP_to_create_a_captive_portal
########


########
# Args check
########

HELP="WiFi Captive Portal script
Foo-Manroot
2019

Usage:
	$0 <INET_iface> <AP_iface>

Args:
	INET_iface:
		Interface connected to the internet

	AP_iface:
		Wireless interface to set up as an AP. Will be started in monitor mode.


Environment variables. To use them to configure the AP properties, you can either
\`export <VAR_NAME>=<whatever>\` and then run this script, or directly execute this
script using \`env <VAR_NAME>=<whatever> $0 ...\`

	HOLD: set it to '-hold' to keep the xterm windows up even after the process
		being executed dies. This can be used to debug the script and see why it
		isn't working

	ESSID: set it to whatever string you want. This will be the name used by your AP.
"

# Exits if there aren't 2 arguments
test $# -ne 2 && printf "%s" "$HELP" && exit 1

# Checks that the interfaces do exist
for iface in "$1" "$2"
do
	if ! ip link show "$iface" 1>/dev/null 2>&1
	then
		printf "ERROR: '%s' is not a valid interface\n" "$iface"
		exit 1
	fi
done

# Check PHP version
! test -d /etc/php/ && printf "ERROR: PHP needs to be installed\n" && exit 1
PHP_VER=""
for dir in $(find /etc/php/ -mindepth 1 -maxdepth 1 -type d | sort -r)
do
	test -d "$dir/fpm" \
		&& PHP_VER="$(printf "%s" "$dir" | awk -F/ '{ print $4}')" \
		&& break
done

if -z "$PHP_VER"
then
	printf "No PHP-fpm version detected\n"
	exit 2
else
	printf "Detected PHP-fpm version: %s\n" "$PHP_VER"
fi


# ----------------------------------
# ----------------------------------
# ----------------------------------

####
# Global variables
#

INET_iface="$1" # Internet connected interface
AP_iface="$2" # Interface to use with the Access Point


# AP settings
test -z "$ESSID" && ESSID=FreeWifi
CHANNEL=6

TMP_DIR="$(mktemp -d)"

# To get the opened XTERM to stay even after the new process dies, set HOLD="-hold"
test -z "$HOLD" && HOLD="+hold"

# ----------------------------------
# ----------------------------------
# ----------------------------------

####
# Iptables
#

# Flush all connections in the firewall
iptables -F
# Delete all chains in iptables
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -F
iptables -t mangle -X
iptables -t filter -F
iptables -t mangle -X

# wlan0 is our wireless card. Replace with your second NIC if doing it from a server.
# This will set up our structure
iptables -t mangle -N wlan0_Trusted
iptables -t mangle -N wlan0_Outgoing
iptables -t mangle -N wlan0_Incoming
iptables -t mangle -I PREROUTING 1 -i "$AP_iface" -j wlan0_Outgoing
iptables -t mangle -I PREROUTING 1 -i "$AP_iface" -j wlan0_Trusted
iptables -t mangle -I POSTROUTING 1 -o "$AP_iface" -j wlan0_Incoming
iptables -t nat -N wlan0_Outgoing
iptables -t nat -N wlan0_Router
iptables -t nat -N wlan0_Internet
iptables -t nat -N wlan0_Global
iptables -t nat -N wlan0_Unknown
iptables -t nat -N wlan0_AuthServers
iptables -t nat -N wlan0_temp
iptables -t nat -A PREROUTING -i "$AP_iface" -j wlan0_Outgoing
iptables -t nat -A wlan0_Outgoing -d 10.3.2.1 -j wlan0_Router
iptables -t nat -A wlan0_Router -j ACCEPT
iptables -t nat -A wlan0_Outgoing -j wlan0_Internet
iptables -t nat -A wlan0_Internet -m mark --mark 0x2 -j ACCEPT
iptables -t nat -A wlan0_Internet -j wlan0_Unknown
iptables -t nat -A wlan0_Unknown -j wlan0_AuthServers
iptables -t nat -A wlan0_Unknown -j wlan0_Global
iptables -t nat -A wlan0_Unknown -j wlan0_temp
# forward new requests to this destination
iptables -t nat -A wlan0_Unknown -p tcp --dport 80 -j DNAT --to-destination 10.3.2.1
iptables -t filter -N wlan0_Internet
iptables -t filter -N wlan0_AuthServers
iptables -t filter -N wlan0_Global
iptables -t filter -N wlan0_temp
iptables -t filter -N wlan0_Known
iptables -t filter -N wlan0_Unknown
iptables -t filter -I FORWARD -i "$AP_iface" -j wlan0_Internet
iptables -t filter -A wlan0_Internet -m state --state INVALID -j DROP
iptables -t filter -A wlan0_Internet -o "$INET_iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t filter -A wlan0_Internet -j wlan0_AuthServers
iptables -t filter -A wlan0_AuthServers -d 10.3.2.1 -j ACCEPT
iptables -t filter -A wlan0_Internet -j wlan0_Global
#allow unrestricted access to packets marked with 0x2
iptables -t filter -A wlan0_Internet -m mark --mark 0x2 -j wlan0_Known
iptables -t filter -A wlan0_Known -d 0.0.0.0/0 -j ACCEPT
iptables -t filter -A wlan0_Internet -j wlan0_Unknown
# allow access to DNS and DHCP
# This helps power users who have set their own DNS servers
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p udp --dport 53 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p tcp --dport 53 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p udp --dport 67 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p tcp --dport 67 -j ACCEPT
iptables -t filter -A wlan0_Unknown -j REJECT --reject-with icmp-port-unreachable
#allow forwarding of requests from anywhere to eth0/WAN
iptables -t nat -A POSTROUTING -o "$INET_iface" -j MASQUERADE

# CRUCIAL: enable IP forwarding
echo "1" > /proc/sys/net/ipv4/ip_forward

####
# Start hostapd to manage the AP
#

cat << EOF > "$TMP_DIR"/hostapd.conf
interface=$AP_iface
driver=nl80211
ssid=$ESSID
hw_mode=g
channel=$CHANNEL
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

# Starts hostapd using another terminal
printf "Starting hostapd\n"
nohup xterm "$HOLD" -e hostapd -t "$TMP_DIR"/hostapd.conf &



####
# DNSMASQ
#

cat << EOF > "$TMP_DIR"/dnsmasq.conf
interface=$AP_iface
dhcp-range=10.3.2.100,10.3.2.200,255.255.255.0,12h

# Override the default route supplied by dnsmasq, which assumes the
# router is the same machine as the one running dnsmasq.
dhcp-option=3,10.3.2.1

#DNS Server
dhcp-option=6,10.3.2.1

server=1.1.1.1
log-queries
log-dhcp
listen-address=127.0.0.1

# List extracted from
# https://www.shellvoide.com/wifi/how-to-setup-captive-portal-login-with-rogue-ap-nginx/
address=/clients3.google.com/10.3.2.1
address=/gsp1.apple.com/10.3.2.1
address=/.akamaitechnologies.com/10.3.2.1
address=/www.appleiphonecell.com/10.3.2.1
address=/www.airport.us/10.3.2.1
address=/.apple.com.edgekey.net/10.3.2.1
address=/.akamaiedge.net/10.3.2.1
address=/.akamaitechnologies.com/10.3.2.1
address=/captive.apple.com/10.3.2.1
address=/ipv6.msftncsi.com/10.3.2.1
address=/www.msftncsi.com/10.3.2.1
address=/connectivity-check.ubuntu.com/10.3.2.1
EOF

# To avoid problems regarding already assigned ports
systemctl stop systemd-resolved
nohup xterm "$HOLD" -e dnsmasq -C "$TMP_DIR"/dnsmasq.conf -d &

####
# Network routes
#
ifconfig "$AP_iface" up 10.3.2.1 netmask 255.255.255.0
route add -net 10.3.2.0 netmask 255.255.255.0 gw 10.3.2.1

####
# Lighttpd for the captive portal
#

cp -rv "$PWD/www" "$TMP_DIR/www"
cat << EOF > "$TMP_DIR"/www/hotspot.xml
<!--
<?xml version="1.0" encoding="UTF-8"?>
<WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.wballiance.net/wispr_2_0.xsd">
<Redirect>
<MessageType>100</MessageType>
<ResponseCode>0</ResponseCode>
<VersionHigh>2.0</VersionHigh>
<VersionLow>1.0</VersionLow>
<AccessProcedure>1.0</AccessProcedure>
<AccessLocation>FakeAP Captive Portal</AccessLocation>
<LocationName>$ESSID</LocationName>
<LoginURL>http://10.3.2.1/</LoginURL>
</Redirect>
</WISPAccessGatewayParam>
-->
EOF

cat << EOF > "$TMP_DIR"/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

daemon off;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	access_log /dev/stdout;
	error_log /dev/stderr;
	gzip on;

	upstream php {
		server unix:/var/run/php/php$PHP_VER-fpm.sock;
	}

	server {
		listen 80 default_server;
		root "$TMP_DIR/www";

		# For iOS
		if (\$http_user_agent ~* (CaptiveNetworkSupport) ) {
			return 302 http://10.3.2.1/hotspot.html;
		}

		location / {
			if (!-f \$request_filename){
				return 302 http://10.3.2.1/index.html;
			}
		}

		location ~ [^/]\.php(/|$) {
			fastcgi_split_path_info ^(.+?\.php)(/.*)$;
			if (!-f \$document_root\$fastcgi_script_name) {
				return 404;
			}
			# This is a robust solution for path info security issue and
			# works with "cgi.fix_pathinfo = 1" in /etc/php.ini (default)
			include /etc/nginx/fastcgi_params;
			fastcgi_index index.php;
			fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
			fastcgi_pass php;
		}

	}
}
EOF

# Starts the PHP-FPM service if needed
test -x /var/run/php/php"$PHP_VER"-fpm.sock || systemctl start php"$PHP_VER"-fpm.service
# The PHP-fpm service doesn't work with root
chown -R www-data:www-data "$TMP_DIR/www"
chmod 0755 "$TMP_DIR"

# We have to allow www-data to execute the iptables command, to give internet access
# Thus, we edit /etc/sudoers
append="www-data ALL = NOPASSWD: /sbin/iptables -t mangle -A wlan0_Outgoing  -m mac --mac-source ??\\:??\\:??\\:??\\:??\\:?? -j MARK --set-mark 2"

# Create a backup to restore later
cp -v /etc/sudoers "$TMP_DIR"
printf "%s\n" "$append" >> /etc/sudoers

# Start nginx
nohup xterm "$HOLD" -e nginx -c "$TMP_DIR/nginx.conf" &
nohup xterm "$HOLD" -e tail -f "$TMP_DIR/www/formdata.txt" &


# Doesn't continue until all the background processes are done
wait

####
# Cleanup (sort of...)
#
printf "Cleaning up...\n"
#airmon-ng stop "$monitor_iface"
systemctl restart systemd-resolved
route del -net 10.3.2.0 netmask 255.255.255.0
# Don't know why; but it gets added twice, so it has to be removed twice
route del -net 10.3.2.0 netmask 255.255.255.0
rm nohup.out

# Rstores iptables
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -F
iptables -t mangle -X
iptables -t filter -F
iptables -t mangle -X

cp -v "$TMP_DIR/sudoers" /etc/sudoers

echo "0" > /proc/sys/net/ipv4/ip_forward

# Removes the temporal directory
rm -rf "$TMP_DIR"

printf "Bye :)\n"
