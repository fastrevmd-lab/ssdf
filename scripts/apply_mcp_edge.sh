#!/usr/bin/env bash
# Apply the nginx MCP edge (edge-hardening M2/L1b/L3/L6) to ct106 + ct113 via pve3.
# Per host: install nginx, push leaf cert/key + CA + site conf + shared limit
# zones, rebind the MCP service to loopback via a systemd drop-in, restart
# both, then smoke-test. Idempotent; safe to re-run.
#
# Prereq: ./scripts/gen_ssdf_tls.sh has populated infra/tls-local/.
# Usage:  ./scripts/apply_mcp_edge.sh
# Env:    PVE_HOST_SSH (default root@pve3.example.com),
#         SSDF_QUERY_CTID (default 106), SSDF_PUBLIC_CTID (default 113)
set -euo pipefail

PVE_HOST="${PVE_HOST_SSH:-root@pve3.example.com}"
QUERY_CTID="${SSDF_QUERY_CTID:-106}"
PUBLIC_CTID="${SSDF_PUBLIC_CTID:-113}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TLS_DIR="$REPO_ROOT/infra/tls-local"
NGINX_DIR="$REPO_ROOT/infra/nginx"

for f in "$TLS_DIR/ssdf-ca.crt" "$TLS_DIR/ct106.crt" "$TLS_DIR/ct106.key" \
         "$TLS_DIR/ct113.crt" "$TLS_DIR/ct113.key" \
         "$NGINX_DIR/ssdf-limits.conf" "$NGINX_DIR/ssdf-mcp-query.conf" \
         "$NGINX_DIR/ssdf-mcp-public.conf"; do
  [ -f "$f" ] || { echo "missing $f (run scripts/gen_ssdf_tls.sh first?)" >&2; exit 1; }
done

# Push a local file into a container via a pve3 scratch copy (ct102 pattern).
push_file() {
  local ctid="$1" src="$2" dst="$3"
  ssh "$PVE_HOST" "cat > /tmp/ssdf-push.tmp && pct push $ctid /tmp/ssdf-push.tmp $dst && rm -f /tmp/ssdf-push.tmp" < "$src"
}

deploy_edge() {
  local ctid="$1" host_ip="$2" lan_port="$3" loop_port="$4" leaf="$5" unit="$6" conf="$7"

  echo "=== [$unit @ ct$ctid] install nginx (if missing) ==="
  ssh "$PVE_HOST" "pct exec $ctid -- sh -c '
    command -v nginx >/dev/null 2>&1 || { apt-get update -q && apt-get install -y -q nginx; }
    command -v curl  >/dev/null 2>&1 || apt-get install -y -q curl
  '"

  echo "=== [$unit @ ct$ctid] push certs + nginx config ==="
  ssh "$PVE_HOST" "pct exec $ctid -- mkdir -p /etc/nginx/ssdf /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d"
  push_file "$ctid" "$TLS_DIR/$leaf.crt"   "/etc/nginx/ssdf/$leaf.crt"
  push_file "$ctid" "$TLS_DIR/$leaf.key"   "/etc/nginx/ssdf/$leaf.key"
  # CA cert is pushed only so in-container verification below can --cacert it.
  push_file "$ctid" "$TLS_DIR/ssdf-ca.crt" "/etc/nginx/ssdf/ssdf-ca.crt"
  ssh "$PVE_HOST" "pct exec $ctid -- chmod 600 /etc/nginx/ssdf/$leaf.key"
  push_file "$ctid" "$NGINX_DIR/ssdf-limits.conf" "/etc/nginx/conf.d/ssdf-limits.conf"
  push_file "$ctid" "$NGINX_DIR/$conf" "/etc/nginx/sites-available/$conf"
  # Enable our site; drop the distro default (it grabs port 80 + default_server).
  ssh "$PVE_HOST" "pct exec $ctid -- sh -c '
    ln -sf /etc/nginx/sites-available/$conf /etc/nginx/sites-enabled/$conf
    rm -f /etc/nginx/sites-enabled/default
  '"

  echo "=== [$unit @ ct$ctid] rebind MCP service to loopback (systemd drop-in) ==="
  # Drop-in (not unit edit): later Environment= assignments of the same var
  # override the unit's values, and the checked-in unit file stays canonical.
  ssh "$PVE_HOST" "pct exec $ctid -- sh -c '
    mkdir -p /etc/systemd/system/$unit.d
    printf \"[Service]\nEnvironment=MCP_BIND=127.0.0.1\nEnvironment=MCP_PORT=$loop_port\n\" > /etc/systemd/system/$unit.d/edge.conf
    systemctl daemon-reload
    systemctl restart $unit
  '"

  echo "=== [$unit @ ct$ctid] nginx -t && restart ==="
  ssh "$PVE_HOST" "pct exec $ctid -- sh -c 'nginx -t && systemctl enable --now nginx && systemctl restart nginx'"

  echo "=== [$unit @ ct$ctid] verify ==="
  # Give uvicorn a moment to come back before probing through nginx.
  local https_code http_code
  https_code="$(ssh "$PVE_HOST" "pct exec $ctid -- sh -c '
    for i in \$(seq 1 15); do
      code=\$(curl -s -o /dev/null -w \"%{http_code}\" --cacert /etc/nginx/ssdf/ssdf-ca.crt https://$host_ip:$lan_port/mcp || true)
      [ \"\$code\" != \"000\" ] && [ \"\$code\" != \"502\" ] && break
      sleep 1
    done
    echo \"\$code\"
  '" | tr -d '[:space:]')"
  # No bearer token -> FastMCP must refuse (401; 400/406 acceptable for
  # missing Accept/session headers). 2xx here would mean auth is broken.
  case "$https_code" in
    401|400|406) echo "PASS: https://$host_ip:$lan_port/mcp -> $https_code (auth/handshake required)" ;;
    *)           echo "FAIL: https://$host_ip:$lan_port/mcp -> $https_code (expected 401/400/406)" >&2; exit 1 ;;
  esac

  # Plain HTTP against the TLS listener must not work: nginx answers 400
  # ("plain HTTP request was sent to HTTPS port") — never an MCP response.
  http_code="$(ssh "$PVE_HOST" "pct exec $ctid -- curl -sm 5 -o /dev/null -w '%{http_code}' http://$host_ip:$lan_port/mcp || true" | tr -d '[:space:]')"
  case "$http_code" in
    2*) echo "FAIL: plain http://$host_ip:$lan_port/mcp returned $http_code" >&2; exit 1 ;;
    *)  echo "PASS: plain http://$host_ip:$lan_port/mcp -> ${http_code:-no-response} (rejected)" ;;
  esac
}

#           ctid          host_ip        lan    loop   leaf   unit                       conf
deploy_edge "$QUERY_CTID"  198.51.100.152 30032 31032 ct106 ssdf-mcp-query.service  ssdf-mcp-query.conf
deploy_edge "$PUBLIC_CTID" 198.51.100.154 30033 31033 ct113 ssdf-mcp-public.service ssdf-mcp-public.conf

echo 'done — clients now connect https://<ip>:3003x/mcp with ssdf-ca.crt trust.'
