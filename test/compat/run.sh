#!/usr/bin/env bash
# Client compatibility suite (`make compat`): real ACME clients against the
# broker image, backed by Pebble.
#
#   test/compat/run.sh            (make compat holds .claude/tmp/pebble.lock)
#
# What runs, all on the host network, every container named
# tlsbroker-e2e-compat-*:
#
#   Pebble + challtestsrv  test/pebble.sh (14000, 15000, 8055)
#   r53mock     127.0.0.1:18454  Route53 REST API over dns01.FakeRoute53,
#                                TXT mirrored to challtestsrv, DoH for TXT
#   mockdoh     127.0.0.1:18453  the DNS gate's view: test names -> 127.0.0.1,
#                                CAA closing wildcards, the rest -> r53mock
#   broker      127.0.0.1:18480  tls-broker:compat, data in
#                                .claude/tmp/compat-data, provider "pebble"
#   caddy       127.0.0.1:18443  TLS front (tls internal), X-Real-IP
#
# Clients: current certbot (certbot/certbot:latest), Ubuntu 20.04's
# python3-certbot, the certbot/certbot:v0.31.0 image, and acme.sh
# (neilpang/acme.sh) both as an ACME-proxy client and with the DNS-proxy hook
# from docs/dns-proxy.md talking to Pebble directly. Each obtains a
# certificate, checks the chain against Pebble's intermediate and root, and
# renews. The summary table at the end lists every check; the exit status is
# non-zero if any failed. Logs stay in .claude/tmp/compat/ for inspection.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
work="$root/.claude/tmp/compat"
data="$root/.claude/tmp/compat-data"
image="${COMPAT_IMAGE:-tls-broker:compat}"
certbot_image="${CERTBOT_IMAGE:-certbot/certbot:latest}"
certbot_old_image="${CERTBOT_OLD_IMAGE:-certbot/certbot:v0.31.0}"
acmesh_image="${ACMESH_IMAGE:-neilpang/acme.sh:latest}"
focal_image=tlsbroker-e2e-compat-certbot-focal
p=tlsbroker-e2e-compat
broker_port=18480 caddy_port=18443 mockdoh_port=18453 r53_port=18454
zone=compat.test zone_id=ZCOMPAT
# COMPAT_PLAIN_HTTP=1: clients talk to the broker directly over http (an
# experiment: does each client accept a plain-http directory?).
public="https://127.0.0.1:$caddy_port"
[ "${COMPAT_PLAIN_HTTP:-}" = 1 ] && public="http://127.0.0.1:$broker_port"
dir_url="$public/acme/directory"

results=()
failed=0
record() { # client version check result
  results+=("$(printf '%-22s %-10s %-34s %s' "$1" "$2" "$3" "$4")")
  [ "$4" = PASS ] || failed=1
  echo "compat: $1 $3: $4"
}

cleanup() {
  docker rm -f "$p-broker" "$p-caddy" "$p-mockdoh" "$p-r53mock" >/dev/null 2>&1 || true
  test/pebble.sh stop
}

die() {
  echo "compat: $*" >&2
  for c in broker r53mock mockdoh caddy; do
    docker logs "$p-$c" >"$work/$c.log" 2>&1 || true
  done
  exit 1
}

# Remove root-owned leftovers of client containers.
wipe() {
  if [ -e "$1" ]; then
    docker run --rm -v "$(dirname "$1"):/w" --entrypoint rm "$acmesh_image" -rf "/w/$(basename "$1")"
  fi
}

# ---- infrastructure ---------------------------------------------------------

test/pebble.sh start
rc=$?
if [ $rc -eq 3 ]; then echo "compat: SKIPPED (Pebble ports busy)"; exit 0; fi
[ $rc -eq 0 ] || exit $rc
trap cleanup EXIT
for port in $broker_port $caddy_port $mockdoh_port $r53_port; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "compat: 127.0.0.1:$port is already in use (SKIPPED)" >&2
    exit 0
  fi
done

wipe "$work"
wipe "$data"
mkdir -p "$work" "$data"
cp .claude/tmp/e2e/pebble.minica.pem "$work/"

make image IMAGE="$image" >"$work/image-build.log" 2>&1 || die "image build failed (see $work/image-build.log)"
CGO_ENABLED=0 scripts/dev go build -o .claude/tmp/compat/r53mock ./test/compat/r53mock || die "r53mock build failed"
docker build --network host -q -t "$focal_image" -f test/compat/certbot-focal.Dockerfile test/compat \
  >"$work/focal-build.log" 2>&1 || die "Ubuntu 20.04 certbot image build failed"

curl -sf --cacert "$work/pebble.minica.pem" https://127.0.0.1:15000/intermediates/0 -o "$work/pebble-intermediate.pem"
curl -sf --cacert "$work/pebble.minica.pem" https://127.0.0.1:15000/roots/0 -o "$work/pebble-root.pem"

docker run -d --rm --network host --name "$p-r53mock" -v "$work:/compat:ro" \
  --entrypoint /compat/r53mock "$image" \
  --listen 127.0.0.1:$r53_port --zone "$zone=$zone_id" --challtestsrv http://127.0.0.1:8055 >/dev/null

records=()
for n in current old focal acmesh dnsproxy; do records+=(--record "$n.$zone A 127.0.0.1"); done
docker run -d --rm --network host --name "$p-mockdoh" --entrypoint /usr/local/bin/mockdoh "$image" \
  --listen 127.0.0.1:$mockdoh_port "${records[@]}" \
  --record "$zone CAA 0 issuewild \";\"" \
  --upstream http://127.0.0.1:$r53_port/dns-query >/dev/null

cat >"$work/broker.yaml" <<EOF
server:
  external_url: $public
  trusted_proxies: [127.0.0.1]
  real_ip_header: X-Real-IP
zones:
  - name: $zone
    hosted_zone_id: $zone_id
route53:
  poll_interval: 500ms
providers:
  - name: pebble
    directory_url: https://127.0.0.1:14000/dir
    contact: ops@$zone
    profile: default
    caa_issuers: [pebble.letsencrypt.org]
    account_uri_honoured: false
    ari: true
    ari_exempt: true
upstream:
  poll_interval: 500ms
EOF

broker_env=(
  -e TLS_BROKER_DATA_DIR=/data -e TLS_BROKER_LISTEN=127.0.0.1:$broker_port
  -e TLS_BROKER_DOH_ENDPOINTS=http://127.0.0.1:$mockdoh_port/dns-query
  -e AWS_ENDPOINT_URL_ROUTE_53=http://127.0.0.1:$r53_port
  -e AWS_ACCESS_KEY_ID=compat -e AWS_SECRET_ACCESS_KEY=compat -e AWS_EC2_METADATA_DISABLED=true
  -e SSL_CERT_FILE=/compat/pebble.minica.pem
)
docker run --rm --network host --user "$(id -u):$(id -g)" -v "$data:/data" -v "$work:/compat:ro" \
  "${broker_env[@]}" "$image" config apply /compat/broker.yaml >"$work/config-apply.log" 2>&1 ||
  die "config apply failed: $(cat "$work/config-apply.log")"
docker run -d --rm --network host --name "$p-broker" --user "$(id -u):$(id -g)" \
  -v "$data:/data" -v "$work:/compat:ro" "${broker_env[@]}" "$image" serve >/dev/null

cat >"$work/Caddyfile" <<EOF
{
	admin off
	http_port 18481
	auto_https disable_redirects
	skip_install_trust
}
https://127.0.0.1:$caddy_port {
	tls internal
	reverse_proxy 127.0.0.1:$broker_port {
		header_up X-Real-IP {remote_host}
	}
}
EOF
docker run -d --rm --network host --name "$p-caddy" -v "$work/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:2-alpine >/dev/null

for _ in $(seq 1 150); do
  if curl -sf "http://127.0.0.1:$broker_port/healthz" >/dev/null 2>&1 &&
    docker cp "$p-caddy:/data/caddy/pki/authorities/local/root.crt" "$work/caddy-root.pem" >/dev/null 2>&1 &&
    curl -sf --cacert "$work/caddy-root.pem" "$dir_url" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -sf --cacert "$work/caddy-root.pem" "$dir_url" >/dev/null || die "broker not reachable through caddy"
# One bundle trusted by every client: the TLS front and Pebble's API.
cat "$work/caddy-root.pem" "$work/pebble.minica.pem" >"$work/bundle.pem"
echo "compat: broker up at $dir_url"

# ---- checks -----------------------------------------------------------------

# check_chain <client> <version> <label> <fullchain.pem> <name>
check_chain() {
  local f=$4 name=$5
  if [ ! -s "$f" ]; then
    record "$1" "$2" "$3: certificate" FAIL
    return 1
  fi
  awk -v d="$work/split-" '/BEGIN CERT/{n++} {print > (d n ".pem")}' "$f"
  if ! openssl x509 -in "$work/split-1.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:$name"; then
    record "$1" "$2" "$3: leaf names $name" FAIL
    return 1
  fi
  if ! cmp -s <(openssl x509 -in "$work/split-2.pem" -outform DER) <(openssl x509 -in "$work/pebble-intermediate.pem" -outform DER) ||
    [ -e "$work/split-3.pem" ] ||
    ! openssl verify -CAfile "$work/pebble-root.pem" -untrusted "$work/split-2.pem" "$work/split-1.pem" >/dev/null 2>&1; then
    record "$1" "$2" "$3: chain = Pebble's" FAIL
    rm -f "$work"/split-*.pem
    return 1
  fi
  rm -f "$work"/split-*.pem
  record "$1" "$2" "$3: cert + Pebble chain" PASS
}

serial() { openssl x509 -in "$1" -noout -serial 2>/dev/null; }

# certbot_suite <label> <image> <name> <ari:yes|no>
certbot_suite() {
  local label=$1 img=$2 name=$3 ari=$4 dir="$work/$1" ver
  mkdir -p "$dir"
  # -t: certbot renew sleeps up to 8 minutes when stdin is not a terminal.
  local run=(docker run --rm -t --network host --user "$(id -u):$(id -g)" -v "$dir:/w" -v "$work/bundle.pem:/bundle.pem:ro"
    -e REQUESTS_CA_BUNDLE=/bundle.pem -e HOME=/w "$img")
  local common=(--config-dir /w/etc --work-dir /w/lib --logs-dir /w/log --non-interactive)
  ver=$(docker run --rm "$img" --version 2>&1 | awk '/^certbot /{print $2}' | tr -d '\r' | tail -1)
  if ! "${run[@]}" certonly "${common[@]}" --server "$dir_url" --webroot -w /tmp -d "$name" \
    --agree-tos --no-eff-email -m "ops@$zone" >"$dir/issue.log" 2>&1; then
    record "certbot $label" "$ver" "issue (--webroot)" FAIL
    return
  fi
  local live="$dir/etc/live/$name"
  check_chain "certbot $label" "$ver" issue "$live/fullchain.pem" "$name" || return
  local before
  before=$(serial "$live/cert.pem")
  if [ "$ari" = yes ]; then
    # Not due: certbot asks the broker's renewalInfo and keeps the certificate.
    local mark
    mark=$(docker logs "$p-broker" 2>&1 | grep -c 'renewal-info' || true)
    "${run[@]}" renew "${common[@]}" >"$dir/renew-check.log" 2>&1
    if [ "$(docker logs "$p-broker" 2>&1 | grep -c 'renewal-info' || true)" -gt "$mark" ]; then
      record "certbot $label" "$ver" "ARI renewalInfo fetched" PASS
    else
      record "certbot $label" "$ver" "ARI renewalInfo fetched" FAIL
    fi
  fi
  if ! "${run[@]}" renew "${common[@]}" --force-renewal >"$dir/renew.log" 2>&1; then
    record "certbot $label" "$ver" "renew --force-renewal" FAIL
    return
  fi
  if [ "$(serial "$live/cert.pem")" = "$before" ]; then
    record "certbot $label" "$ver" "renew --force-renewal: new cert" FAIL
    return
  fi
  check_chain "certbot $label" "$ver" "renew --force-renewal" "$live/fullchain.pem" "$name"
}

acmesh() { # dir args...
  local dir=$1
  shift
  docker run --rm --network host -v "$dir:/acme.sh" -v "$work/bundle.pem:/bundle.pem:ro" \
    -v "$work/dns_broker.sh:/acmebin/dnsapi/dns_broker.sh:ro" \
    -e AUTO_UPGRADE=0 -e CURL_CA_BUNDLE=/bundle.pem -e DNS_BROKER_URL="https://127.0.0.1:$caddy_port" \
    "$acmesh_image" acme.sh "$@"
}

acmesh_suite() { # label name args...
  local label=$1 name=$2 dir="$work/acmesh-$1" ver
  shift 2
  mkdir -p "$dir"
  ver=$(acmesh "$dir" --version 2>&1 | tail -1 | tr -d '\r')
  if ! acmesh "$dir" --issue -d "$name" --ca-bundle /bundle.pem "$@" >"$dir/issue.log" 2>&1; then
    record "acme.sh $label" "$ver" issue FAIL
    return
  fi
  local fc="$dir/${name}_ecc/fullchain.cer"
  [ -e "$fc" ] || fc="$dir/$name/fullchain.cer"
  check_chain "acme.sh $label" "$ver" issue "$fc" "$name" || return
  local before
  before=$(serial "$fc")
  if ! acmesh "$dir" --renew -d "$name" --force --ca-bundle /bundle.pem >"$dir/renew.log" 2>&1; then
    record "acme.sh $label" "$ver" "renew --force" FAIL
    return
  fi
  if [ "$(serial "$fc")" = "$before" ]; then
    record "acme.sh $label" "$ver" "renew --force: new cert" FAIL
    return
  fi
  check_chain "acme.sh $label" "$ver" "renew --force" "$fc" "$name"
}

# The acme.sh hook exactly as documented in docs/dns-proxy.md.
awk '/^### acme.sh \(`dns_broker.sh`\)/{f=1} f&&/^```sh$/{c=1;next} c&&/^```$/{exit} c{print}' docs/dns-proxy.md >"$work/dns_broker.sh"
grep -q 'dns_broker_add()' "$work/dns_broker.sh" || die "could not extract the acme.sh hook from docs/dns-proxy.md"

certbot_suite current "$certbot_image" "current.$zone" yes
certbot_suite focal "$focal_image" "focal.$zone" no
certbot_suite old "$certbot_old_image" "old.$zone" no
acmesh_suite proxy "acmesh.$zone" --server "$dir_url" -w /tmp
acmesh_suite dnsproxy "dnsproxy.$zone" --server https://127.0.0.1:14000/dir --dns dns_broker --dnssleep 0

# Every ACME-proxy renewal went upstream with `replaces` (sent by the client
# or inferred by the broker): the order audit event names it.
for n in current focal old acmesh; do
  if jq -e -s --arg n "$n.$zone" \
    '[.[] | select(.type == "order" and .names == [$n] and (.detail | test("^renewal; replaces ")))] | length >= 1' \
    "$data"/audit/*.jsonl >/dev/null 2>&1; then
    record "broker" "-" "$n: renewal sent replaces upstream" PASS
  else
    record "broker" "-" "$n: renewal sent replaces upstream" FAIL
  fi
done

# The DNS-proxy hook must have cleaned up after itself.
left=$(curl -s --cacert "$work/caddy-root.pem" "https://127.0.0.1:$caddy_port/dns/challenges")
if printf '%s' "$left" | grep -q '"challenges":\[\]'; then
  record "acme.sh dnsproxy" "-" "hook cleanup left nothing" PASS
else
  record "acme.sh dnsproxy" "-" "hook cleanup left nothing ($left)" FAIL
fi

for c in broker r53mock mockdoh caddy; do docker logs "$p-$c" >"$work/$c.log" 2>&1 || true; done

echo
echo "compat summary (logs in $work)"
printf '%-22s %-10s %-34s %s\n' CLIENT VERSION CHECK RESULT
printf '%s\n' "${results[@]}"
exit $failed
