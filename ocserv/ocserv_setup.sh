#!/bin/bash

OCSERV_VER='1.0.1'

ORI_USER="$(logname)"
ORI_USER_HOME="$( getent passwd "$ORI_USER" | cut -d: -f6)"
CONFIG_DIR="$ORI_USER_HOME/$(hostname)"

OCSERV_USER="$(hostname)_$ORI_USER"

ocserv_dependencies(){
  yum update -y -q -e 0
  yum install -y -q -e 0 epel-release
  yum config-manager --set-enabled PowerTools
  yum install -y -q -e 0 gnutls-devel libev-devel \
    tcp_wrappers-devel pam-devel lz4-devel libseccomp-devel \
    readline-devel libnl3-devel krb5-devel radcli-devel \
    protobuf-c-devel libtalloc-devel http-parser-devel \
    pcllib-devel protobuf-c gperf lockfile-progs nuttcp \
    lcov uid_wrapper pam_wrapper nss_wrapper socket_wrapper \
    gssntlmssp haproxy iputils freeradius gawk yajl liboath-devel \
    systemd-devel libgeoip-devel vim ruby-devel gnutls-utils
  yum groupinstall -y -q -e 0 "Development Tools"
  gem install ronn
}

ocserv_build(){
  curl -sSL "ftp://ftp.infradead.org/pub/ocserv/ocserv-$OCSERV_VER.tar.xz" -O
  tar xf "ocserv-$OCSERV_VER.tar.xz"
  (
    cd "ocserv-$OCSERV_VER" || exit
    ./configure --prefix=/usr --sysconfdir=/etc
    make -j"$(nproc)"
    make check
  )
  make install
}

oscerv_build_install(){
  ocserv_dependencies
  ocserv_install
}

oscerv_yum_install(){
  yum update -y -q -e 0
  yum install -y -q -e 0 epel-release
  yum config-manager --set-enabled PowerTools
  yum install -y -q -e 0 ocserv vim oathtool qrencode
  yum groupinstall -y -q -e 0 'Development Tools'
  systemctl enable ocserv
}

coreutils_update(){
  (
    cd /usr/local/src/ || exit
    curl -sSL http://ftp.gnu.org/gnu/coreutils/coreutils-8.31.tar.xz -O
    tar xf coreutils-8.31.tar.xz
    cd coreutils-8.31  || exit
    FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr
    make -j"$(nproc)"
    make install 
  )
}

letsencrypt_run(){
  echo 'Starting runing LetsEncrypt Certbot'
  yum install -y -q -e 0 certbot python3-certbot-dns-cloudflare
  (
    echo "dns_cloudflare_email = $CF_EMAIL"
    echo "dns_cloudflare_api_key = $CF_KEY"
  )>/etc/letsencrypt/cf.ini

  chmod 0700 /etc/letsencrypt/cf.ini

  certbot certonly --quiet --non-interactive \
    --keep-until-expiring --max-log-backups 90 \
    --agree-tos -m "$CERT_EMAIL" --no-eff-email \
    --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cf.ini \
    -d "$SITE"

#openssl ecparam -genkey -name secp384r1 -out privkey.pem
#cat <<_EOF_ > openssl.cnf
#[ req ]
#prompt = no
#encrypt_key = no
#default_md = sha512
#distinguished_name = dname
#req_extensions = reqext
#
#[ dname ]
#CN = $SITE
#emailAddress = $CERT_EMAIL
#
#[ reqext ]
#subjectAltName = DNS:$SITE
#_EOF_
#
#openssl req -new -config openssl.cnf -key privkey.pem -out csr.pem
#certbot certonly --quiet --non-interactive \
#  --keep-until-expiring --max-log-backups 90 \
#  --agree-tos -m "$CERT_EMAIL" --no-eff-email \
#  --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cf.ini \
#  -d "$SITE" -csr csr.pem

  chown -R ocserv:ocserv "/etc/letsencrypt/live/$SITE/"
# /var/log/letsencrypt
# /var/lib/letsencrypt
}

ocserv_config(){
  mv /etc/ocserv/ocserv.conf /etc/ocserv/ocserv.conf.bak
  cat >/etc/ocserv/ocserv.conf <<-_EOF_
auth = "plain[passwd=/etc/ocserv/passwd,otp=/etc/ocserv/users.oath]"
auth = "certificate"
tcp-port = 443
#udp-port = 443
run-as-user = ocserv
run-as-group = ocserv
socket-file = ocserv.sock
chroot-dir = /var/lib/ocserv
isolate-workers = true
max-clients = 5
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = false
#server-cert = /etc/ocserv/server.crt
#server-key = /etc/ocserv/server.key
server-cert = /etc/letsencrypt/live/$SITE/fullchain.pem
server-key = /etc/letsencrypt/live/$SITE/privkey.pem
ca-cert = /etc/ocserv/ca.crt
cert-user-oid = 2.5.4.3

#RSA
tls-priorities = "%SERVER_PRECEDENCE:SECURE256:%PROFILE_ULTRA:+VERS-TLS1.3:+VERS-TLS1.2:-ECDHE-ECDSA:-DHE-RSA:-RSA:-AES-256-CBC:-CAMELLIA-256-CBC:-VERS-TLS1.1:-VERS-TLS1.0:-VERS-DTLS1.0:-VERS-DTLS1.2"

#ECC
#tls-priorities = "SECURE256:%SERVER_PRECEDENCE:-ECDHE-RSA:-DHE-RSA:-RSA:-AES-256-CBC:-CAMELLIA-256-CBC:-VERS-TLS1.1:-VERS-TLS1.0:-VERS-DTLS1.0:-VERS-DTLS1.2"

auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 86400
cookie-timeout = 3600
persistent-cookies = true
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = false

default-domain = $DOMAIN
ipv4-network = 192.168.1.0/24
ipv6-network = fda9:4efe:7e3b:03ea::/64

ipv6-subnet-prefix = 128
tunnel-all-dns = true
dns=1.1.1.1
dns=208.67.222.222
dns=208.67.220.220
ping-leases = false

route = default
cisco-client-compat = true
dtls-legacy = true
_EOF_

  echo "$OCSERV_USER:*:" >>/etc/ocserv/passwd
  mkdir -p "$CONFIG_DIR"

  SECRET="$(head -c 16 /dev/urandom | xxd -c 256 -ps)"
  echo "HOTP/T30 $OCSERV_USER - $SECRET" >>/etc/ocserv/users.oath
  SECRET_BASE32="$(echo "0x$SECRET" | xxd -r -c 256 | base32 | tr -d =)"
  echo "$SECRET_BASE32"
  qrencode "otpauth://totp/$OCSERV_USER?secret=$SECRET_BASE32&issuer=Openconnect%20$SITE" \
    -o "$CONFIG_DIR/$OCSERV_USER-2d.png"
  qrencode -t UTF8 "otpauth://totp/$OCSERV_USER?secret=$SECRET_BASE32&issuer=Openconnect%20$SITE"
  echo 'First 10 HOTP code:'
  oathtool --totp -w 10 "$SECRET"

  echo 'Setting up networking and firewall rules'
  echo "net.ipv4.ip_forward = 1">> /etc/sysctl.conf
  sysctl -p 

  firewall-cmd --zone=public --add-port 443/tcp --permanent
  # firewall-cmd --zone=public --add-port 443/udp --permanent
  firewall-cmd --zone=public --add-masquerade --permanent
  firewall-cmd --reload

  chown -R ocserv:ocserv /var/lib/ocserv

  echo 'Starting certificate generation'
  certtool --generate-privkey --ecc --sec-param ultra \
    --outfile /etc/ocserv/ca.key --stdout-info 

  cat <<_EOF_ >ca.tmpl
cn = "GlobalSign"
organization = "GlobalSign"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
_EOF_

  certtool --generate-self-signed --load-privkey \
    /etc/ocserv/ca.key --template ca.tmpl \
    --outfile /etc/ocserv/ca.crt --hash=SHA512 \
    --stdout-info 

#  certtool --generate-privkey --ecc --sec-param ultra \
#    --outfile /etc/ocserv/server.key --stdout-info 
#  cat <<_EOF_ > server.tmpl
#cn = "$DOMAIN"
#organization = "$ORI_USER"
#serial = 2
#expiration_days = 3650
#signing_key
#encryption_key
#tls_www_server
#_EOF_

#  certtool --generate-certificate \
#    --load-privkey /etc/ocserv/server.key \
#    --load-ca-certificate /etc/ocserv/ca.crt \
#    --load-ca-privkey /etc/ocserv/ca.key \
#    --template server.tmpl --outfile /etc/ocserv/server.crt \
#    --hash=SHA512 --stdout-info 

  certtool --generate-privkey --ecc --sec-param ultra \
    --outfile "$CONFIG_DIR/$OCSERV_USER.key" \
    --stdout-info 

  cat > "$OCSERV_USER.tmpl" <<_EOF_ 
cn = "$OCSERV_USER"
organization = "$DOMAIN"
expiration_days = 3650
signing_key
encryption_key
tls_www_client
_EOF_

  certtool --generate-certificate \
    --load-privkey "$CONFIG_DIR/$OCSERV_USER.key" \
    --load-ca-certificate /etc/ocserv/ca.crt \
    --load-ca-privkey /etc/ocserv/ca.key \
    --template "$OCSERV_USER.tmpl" \
    --outfile "$CONFIG_DIR/$OCSERV_USER.crt" \
    --hash=SHA512 --stdout-info 

  certtool --to-p12 --load-privkey "$CONFIG_DIR/$OCSERV_USER.key" \
    --pkcs-cipher 3des-pkcs12 \
    --load-certificate "$CONFIG_DIR/$OCSERV_USER.crt" \
    --outfile "$CONFIG_DIR/$OCSERV_USER.p12" --outder \
    --password="$CLIENT_PW" --p12-name="VPN Client Cert $OCSERV_USER" \
    --stdout-info 

  chown -R "$ORI_USER":"$ORI_USER" "$ORI_USER_HOME"
  cp /etc/ocserv/ca.crt "$CONFIG_DIR/ca.crt"
  systemctl start ocserv
}

# verify configuration values
verify_config() {
  SITE="$PARAM_SITE"
  DOMAIN="$PARAM_DOMAIN"
  if [ -z "$SITE" ] && [ -z "$DOMAIN" ]; then
    _exiterr 'No Site or Somain specified. Either of those should be declared.'
  # only specified DOMAIN
  elif [ -z "$SITE" ]; then
    SITE="$(hostname).$DOMAIN"
    echo "Only Domain $DOMAIN is presented. Automatically use $(hostname).$DOMAIN as Cloudflare site."
  # only specified SITE
  elif [ -z "$DOMAIN" ]; then
    echo "Only Site is presented. Auto detect domain and use it as Cloudflare domain."
    DOMAIN="$(echo "$SITE" | awk -F. '{ print ( $(NF-1)"."$(NF) ) }')"
  fi

  CF_EMAIL="$PARAM_CF_EMAIL"
  CF_KEY="$PARAM_CF_KEY"

  if [ -z "$CF_EMAIL" ] || [ -z "$CF_KEY" ]; then
    _exiterr 'No CDN email or API Key presented. Both of those should be declared.'
  fi

  CLIENT_PW="$PARAM_CLIENT_PW"
  if [ -z "$CLIENT_PW" ]; then
    _exiterr 'No client certification password presented.'
  fi

  CERT_EMAIL="${PARAM_CERT_EMAIL:-notinuse@$DOMAIN}"
}

print_config(){
  echo "Site : $SITE"
  echo "Domain : $DOMAIN"
  echo "Cloudflare Email : $CF_EMAIL"
  echo "Cloudflare API Key : $CF_KEY"
  echo "Certificate Email : $CERT_EMAIL"
}

#update/create dns record
update_dns_record(){

  PUB_IPv4="$(curl -s -4 ifconfig.co)"
#PRI_IPv4="$(ip route get 8.8.8.8| awk '{print $7}')"

  PUB_IPv6="$(curl -s -6 ifconfig.co)"
#PRI_IPv6="$(ip route get 2001:4860:4860::8844| awk '{print $9}')"

  local JSON="$(curl -sS "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY")"
  local ZONE_ID="$(sed -ne 's/.*"id":"\(.*\)","name":"'"$DOMAIN"'".*/\1/p' <<< $JSON)"

  if [ -z "$ZONE_ID" ]
  then
    echo "Cannot get Zone ID. Will not update DNS record"
  else
    echo "Will try update DNS record by hostname";
    local JSON="$(curl -sS -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=A&name=$SITE" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY")"
    local IPv4_ID="$(sed -ne 's/.*"id":"\(.*\)","type":"A","name":".*'"$DOMAIN"'",.*/\1/p' <<< $JSON)"

    if [ -z "$IPv4_ID" ]
    then
      curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json" --data "{\"type\":\"A\",\"name\":\"$SITE\",\"content\":\"${PUB_IPv4}\",\"ttl\":1}"
    else
      curl -sS -X PUT "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${IPv4_ID}" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json" --data "{\"type\":\"A\",\"name\":\"$SITE\",\"content\":\"${PUB_IPv4}\",\"ttl\":1}"
    fi

    local JSON="$(curl -sS -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=AAAA&name=$SITE" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY")"
    local IPv6_ID="$(sed -ne 's/.*"id":"\(.*\)","type":"AAAA","name":".*'"$DOMAIN"'",.*/\1/p' <<< $JSON)"

    if [ -z "$IPv6_ID" ]
    then
      curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json" --data "{\"type\":\"AAAA\",\"name\":\"$SITE\",\"content\":\"${PUB_IPv6}\",\"ttl\":1}"
    else
      curl -sS -X PUT "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${IPv6_ID}" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_KEY" -H "Content-Type: application/json" --data "{\"type\":\"AAAA\",\"name\":\"$SITE\",\"content\":\"${PUB_IPv6}\",\"ttl\":1}"
    fi
  fi
}

run(){
  verify_config
  print_config
  update_dns_record
  oscerv_yum_install
  coreutils_update
  letsencrypt_run
  ocserv_config
}

test_env_vars(){
  local VARS=$(grep -E -e '^[[:space:]]*# PARAM_Environment:' "${0}" | \
    sed -e 's/.*# PARAM_Environment: \(.*\)/\1/g' \
      -e '/N\/A/ d' | \
    tr '\n' ' ')
  for VAR in $VARS
  do
    if [[ -n "${!VAR}" ]]; then
      return 0
    fi
  done
  return 1
}

## see following code from https://github.com/lukas2511/dehydrated dehydrated file
_exiterr() {
  echo "ERROR: ${1}" >&2
  exit 1
}

# PARAM_Usage: --help (-h)
# PARAM_Environment: N/A
# PARAM_Description: Show help text and exit 
command_help() {
  printf "Usage: %s [-h] [parameter [argument]] [parameter [argument]] ...\n" "${0}"
  printf -- "\nParameters:\n"
  grep -E -e '^[[:space:]]*# PARAM_Usage:' \
    -e '^[[:space:]]*# PARAM_Description:' \
    -e '^[[:space:]]*# PARAM_Environment:' "${0}" | \
  while read -r usage; read -r env; read -r description; do
    if [[ ! "${usage}" =~ Usage ]] || \
      [[ ! "${description}" =~ Description ]] || \
      [[ ! "${env}" =~ Environment ]]; then
      _exiterr "Error generating help text."
    fi
    printf " %-28s ENV: %-17s %s\n" \
      "${usage##"# PARAM_Usage: "}" \
      "${env##"# PARAM_Environment: "}" \
      "${description##"# PARAM_Description: "}"
  done
}

main() {
  check_parameters() {
    if [ -z "${1:-}" ]; then
      echo "The specified command requires additional parameters. See help:" >&2
      echo >&2
      command_help >&2
      exit 1
    elif [[ "${1:0:1}" = "-" ]]; then
      _exiterr "Invalid argument: ${1}"
    fi
  }

  if [ $# -eq 0 ] ; then
    test_env_vars || command_help >&2
  else
    while (( ${#} )); do
      case "${1}" in
        --help|-h)
          command_help
          exit 0
          ;;

        # PARAM_Usage: --domain (-d) domain.tld
        # PARAM_Environment: PARAM_DOMAIN
        # PARAM_Description: Use specified domain name
        --domain|-d)
          shift 1
          check_parameters "${1:-}"
          [ -n "${PARAM_DOMAIN:-}" ] && _exiterr "Domain can only be specified once!"
          PARAM_DOMAIN="${1}"
          ;;

        # PARAM_Usage: --site (-s) site.domain.tld
        # PARAM_Environment: PARAM_SITE
        # PARAM_Description: Use specified site for tls
        --site|-s)
          shift 1
          check_parameters "${1:-}"
          [ -n "${PARAM_SITE:-}" ] && _exiterr "Site can only be specified once!"
          PARAM_SITE="${1}"
          ;;

        # PARAM_Usage: --cf-email (-e) email
        # PARAM_Environment: PARAM_CF_EMAIL
        # PARAM_Description: Use specified email as Cloudflare account
        --cf-email|-e)
          shift 1
          check_parameters "${1:-}"
          [ -n "${PARAM_CF_EMAIL:-}" ] && _exiterr "Cloudflare email can only be specified once!"
          PARAM_CF_EMAIL="${1}"
          ;;

        # PARAM_Usage: --cf-key (-k) key
        # PARAM_Environment: PARAM_CF_KEY
        # PARAM_Description: Use specified key as Cloudflare API key
        --cf-key|-k)
          shift 1
          check_parameters "${1:-}"
          [ -n "${PARAM_CF_KEY:-}" ] && _exiterr "Cloudflare API key can only be specified once!"
          PARAM_CF_KEY="${1}"
          ;;

        # PARAM_Usage: --cert-email (-ce) email
        # PARAM_Environment: PARAM_CERT_EMAIL
        # PARAM_Description: Use specified email as letsencrypt account email
        --cert-email|-ce)
          shift 1
          check_parameters "${1:-}"
          [ -n "${PARAM_CERT_EMAIL:-}" ] && _exiterr "Certificate email can only be specified once!"
          PARAM_CERT_EMAIL="${1}"
          ;;

        # PARAM_Usage: --ccert-password (-ccp) pw
        # PARAM_Environment: PARAM_CLIENT_PW
        # PARAM_Description: Use specified password as client certification email
        --ccert-password|-ccp)
          shift 1
          check_parameters "${1:-}"
          [ -n "${PARAM_CLIENT_PW:-}" ] && _exiterr "Client certificate password can only be specified once!"
          PARAM_CLIENT_PW="${1}"
          ;;

        *)
          echo "Unknown parameter detected: ${1}" >&2
          echo >&2
          command_help >&2
          exit 1
          ;;
      esac

      shift 1
    done
  fi

  run
}

main "${@:-}"