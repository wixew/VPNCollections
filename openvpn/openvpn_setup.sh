#!/bin/bash
set -eu
set -o pipefail

# set -x
sed -i 's/SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
setenforce 0

yum install -y -q -e 0 epel-release
yum install -y -q -e 0 openvpn git vim firewalld wget

systemctl stop openvpn@server.service

CLIENT_NAME='client001'
SERVER_NAME="test server"

ORI_USER="$(who am i | awk '{print $1}')"
ORI_USER_HOME="$( getent passwd $ORI_USER | cut -d: -f6)"

OPENVPN_DIR='/etc/openvpn'
EASYRSA_VER='v3.0.6'
EASYRSA_DIR="$ORI_USER_HOME/easyrsa-$EASYRSA_VER"

PUB_IPv4="$(curl -4 ifconfig.co)"
PRI_IPv4="$(ip route get 8.8.8.8| awk '{print $7}')"

_echo() (
  fmt=%s end=\\n IFS=" "

  while [ $# -gt 1 ] ; do
    case "$1" in
    [!-]*|-*[!ne]*) break ;;
    *ne*|*en*) fmt=%b end= ;;
    *n*) end= ;;
    *e*) fmt=%b ;;
    esac
    shift
  done

  printf "$fmt$end" "$*"
)

wget -q -O "$ORI_USER_HOME"/easyrsa-"$EASYRSA_VER".tgz https://github.com/OpenVPN/easy-rsa/releases/download/"$EASYRSA_VER"/EasyRSA-unix-"$EASYRSA_VER".tgz
tar zxf "$ORI_USER_HOME"/easyrsa-"$EASYRSA_VER".tgz -C "$ORI_USER_HOME"
rm -rf "$EASYRSA_DIR"
mv -f "$ORI_USER_HOME/EasyRSA-$EASYRSA_VER/" "$EASYRSA_DIR"

rm -rf "$OPENVPN_DIR/server"/*
rm -rf "$OPENVPN_DIR/client"/*
rm -rf "$EASYRSA_DIR/pki"
rm -rf "$OPENVPN_DIR/server.conf"
rm -rf "$ORI_USER_HOME/$CLIENT_NAME.ovpn"

cat >"$EASYRSA_DIR/vars" <<-_EOF_
set_var EASYRSA                 '$EASYRSA_DIR'
set_var EASYRSA_PKI             '\$EASYRSA/pki'
set_var EASYRSA_ALGO            'ec'
set_var EASYRSA_CURVE           'secp521r1'
set_var EASYRSA_CA_EXPIRE       7500
set_var EASYRSA_CERT_EXPIRE     3650
set_var EASYRSA_RAND_SN         "yes"
set_var EASYRSA_DIGEST          'sha512'
set_var EASYRSA_BATCH           'y'
_EOF_

chmod +x "$EASYRSA_DIR/vars"
"$EASYRSA_DIR/easyrsa" init-pki
"$EASYRSA_DIR/easyrsa" build-ca nopass

"$EASYRSA_DIR/easyrsa" --req-cn="Test $SERVER_NAME" gen-req "$SERVER_NAME" nopass
"$EASYRSA_DIR/easyrsa" sign-req server "$SERVER_NAME"
openssl verify -CAfile "$EASYRSA_DIR/pki/ca.crt" "$EASYRSA_DIR/pki/issued/$SERVER_NAME.crt"

"$EASYRSA_DIR/easyrsa" --req-cn="Test $CLIENT_NAME" gen-req "$CLIENT_NAME" nopass
"$EASYRSA_DIR/easyrsa" sign-req client "$CLIENT_NAME"
openssl verify -CAfile "$EASYRSA_DIR/pki/ca.crt" "$EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt"

cp "$EASYRSA_DIR/pki/ca.crt" "$OPENVPN_DIR/server/"
cp "$EASYRSA_DIR/pki/issued/$SERVER_NAME.crt" "$OPENVPN_DIR/server/"
cp "$EASYRSA_DIR/pki/private/$SERVER_NAME.key" "$OPENVPN_DIR/server/"

cp "$EASYRSA_DIR/pki/ca.crt" "$OPENVPN_DIR/client/"
cp "$EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt" "$OPENVPN_DIR/client/"
cp "$EASYRSA_DIR/pki/private/$CLIENT_NAME.key" "$OPENVPN_DIR/client/"

openvpn --genkey --secret "$OPENVPN_DIR/ta.key"
cp "$OPENVPN_DIR/ta.key" "$OPENVPN_DIR/client/"
mv -f "$OPENVPN_DIR/ta.key" "$OPENVPN_DIR/server/"

cat >>/etc/sysctl.d/99-sysctl.conf <<-_EOF_
net.ipv4.ip_forward = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
_EOF_

set +e
sysctl -p
if [ "$?" -ne '0' ]; then
  _echo "The last command fail. If the error is about IPv6, might be the system is not support IPv6 for now."
  _echo "$(ip a | grep inet6 | wc -l) of IPv6 detected."
fi
set -e

cat >"$OPENVPN_DIR/server.conf" <<-_EOF_
local $PRI_IPv4
;port 443
port 1194
;proto tcp
proto udp
dev tun
ca "$OPENVPN_DIR/server/ca.crt"
cert "$OPENVPN_DIR/server/$SERVER_NAME.crt"
key "$OPENVPN_DIR/server/$SERVER_NAME.key"
dh none
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
keepalive 15 120
tls-crypt "$OPENVPN_DIR/server/ta.key"
cipher AES-256-GCM
compress lz4-v2
push "compress lz4-v2"
user nobody
group nobody
persist-key
persist-tun
status /dev/null
log /dev/null
verb 0
ncp-ciphers AES-256-GCM:AES-256-CBC 
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256
auth SHA512
auth-nocache
ecdh-curve secp521r1
remote-cert-eku "TLS Web Client Authentication"
tls-server
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
ping-timer-rem
reneg-sec 0
fast-io
_EOF_

cat >"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn" <<-_EOF_
client
dev tun
proto udp
;proto tcp
remote $PUB_IPv4 1194
;remote $PUB_IPv4 443
resolv-retry infinite
topology subnet
nobind
user nobody
group nobody
persist-key
persist-tun
mute-replay-warnings
remote-cert-tls server
cipher AES-256-GCM
verb 0
tls-client
pull
ncp-ciphers AES-256-GCM:AES-256-CBC 
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256
auth SHA512
auth-nocache
ecdh-curve secp521r1
remote-cert-eku "TLS Web Server Authentication"
redirect-gateway def1
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
ping 15
ping-restart 0
ping-timer-rem
reneg-sec 0
fast-io
_EOF_

_echo '<ca>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
cat "$OPENVPN_DIR/client/ca.crt" >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
_echo '</ca>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"

_echo '<cert>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
cat "$OPENVPN_DIR/client/$CLIENT_NAME.crt" >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
_echo '</cert>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"

_echo '<key>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
cat "$OPENVPN_DIR/client/$CLIENT_NAME.key" >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
_echo '</key>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"

_echo '<tls-crypt>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
cat "$OPENVPN_DIR/client/ta.key" >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"
_echo '</tls-crypt>' >>"$OPENVPN_DIR/client/$CLIENT_NAME.ovpn"

rm -rf "$OPENVPN_DIR/client/ca.crt" "$OPENVPN_DIR/client/$CLIENT_NAME.crt" "$OPENVPN_DIR/client/$CLIENT_NAME.key"

cp "$OPENVPN_DIR/client/$CLIENT_NAME.ovpn" "$ORI_USER_HOME/$CLIENT_NAME.ovpn"

systemctl start openvpn@server.service
systemctl enable openvpn@server.service

systemctl start firewalld
systemctl enable firewalld
firewall-cmd --zone=public --permanent --add-port=443/tcp
firewall-cmd --zone=public --permanent --add-port=1194/udp
sleep 2
firewall-cmd --zone=public --permanent --add-masquerade
sleep 2
firewall-cmd --reload

if [ "$(firewall-cmd --query-masquerade)" = "no" ]; then
  firewall-cmd --zone=public --permanent --add-masquerade
  sleep 10
  systemctl restart firewalld
  firewall-cmd --reload
fi

firewall-cmd --query-masquerade

_echo 'finish'
