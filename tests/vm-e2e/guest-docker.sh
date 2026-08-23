#!/usr/bin/env bash
# Runs INSIDE the Linux VM as root. Exercises the CONTAINER path documented in
# docs/docker.md: build the repo Dockerfile, run it under compose with the
# static backend, and assert the same wire chain as the systemd leg.
set -uo pipefail

PASS=0; FAIL=0
ok(){ printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step(){ printf '\n== %s\n' "$*"; }

SRC=/home/debian/kow-src
STACK=/home/debian/kow-stack
REAL_SECRET="sk-live-DOCKER-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PLACEHOLDER="sk-PLACEHOLDER-docker00001111222233334"
# Own host port: the systemd leg may still hold 14322 in the same VM.
HOST_PORT=14323

step "1. docker engine"
export DEBIAN_FRONTEND=noninteractive
command -v docker >/dev/null 2>&1 || apt-get install -y -qq docker.io >/tmp/dockerinst.log 2>&1
# Compose is a separate package on Debian; try v2 (plugin) then v1 (standalone).
docker compose version >/dev/null 2>&1 || apt-get install -y -qq docker-compose-v2 >>/tmp/dockerinst.log 2>&1
docker compose version >/dev/null 2>&1 || apt-get install -y -qq docker-compose >>/tmp/dockerinst.log 2>&1
systemctl enable --now docker >/dev/null 2>&1
sleep 3
docker info >/dev/null 2>&1 && ok "docker daemon up ($(docker --version | awk '{print $3}' | tr -d ,))" \
  || { bad "docker daemon unavailable"; tail -5 /tmp/dockerinst.log; exit 1; }

step "2. build the image from the repo Dockerfile"
if docker build -q -t kow:e2e "$SRC" >/tmp/build.log 2>&1; then
  ok "image built from Dockerfile"
else
  bad "docker build failed"; tail -18 /tmp/build.log; exit 1
fi
docker run --rm --entrypoint /opt/kow/.venv/bin/kow kow:e2e --version >/dev/null 2>&1 \
  && ok "kow runs inside the image" || bad "kow not runnable in image"
# The image must not run as root (docs/docker.md hardening claim).
IMG_USER=$(docker run --rm --entrypoint id kow:e2e -un 2>/dev/null)
[ "$IMG_USER" = "kow" ] && ok "container runs as unprivileged 'kow'" || bad "container user is '$IMG_USER'"

step "3. compose stack with the static backend"
mkdir -p "$STACK/secrets"
cat > "$STACK/static-secrets.yaml" <<YAML
secrets:
  DOCKER_KEY: "${REAL_SECRET}"
YAML
chmod 0600 "$STACK/static-secrets.yaml"
cat > "$STACK/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  DOCKER_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {DOCKER_KEY}"
    bindings:
      - host: "host.docker.internal"
backend:
  type: static
  config:
    type: static
    path: /etc/kow/static/secrets.yaml
audit:
  path: /var/log/kow/audit.jsonl
unmatched_destination_policy: deny
YAML
mkdir -p "$STACK/static" && cp "$STACK/static-secrets.yaml" "$STACK/static/secrets.yaml"
chmod 0700 "$STACK/static"; chmod 0600 "$STACK/static/secrets.yaml"
chown -R 65532:65532 "$STACK/static"
ok "stack config written"

step "4. run the container"
docker rm -f kow-e2e >/dev/null 2>&1
docker run -d --name kow-e2e \
  --add-host host.docker.internal:host-gateway \
  -p 127.0.0.1:${HOST_PORT}:14322 \
  -v "$STACK/bindings.yaml":/etc/kow/bindings.yaml:ro \
  -v "$STACK/static":/etc/kow/static:ro \
  kow:e2e >/dev/null 2>&1
sleep 8
docker ps --filter name=kow-e2e --filter status=running -q | grep -q . \
  && ok "container running" || { bad "container not running"; docker logs kow-e2e 2>&1 | tail -12; }

step "5. healthz through the containerised proxy"
HZ=$(curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:${HOST_PORT} http://healthz.kow.invalid/healthz)
[ "$HZ" = "200" ] && ok "healthz -> 200" || bad "healthz returned $HZ"

step "6. real substitution on the wire (host upstream via host-gateway)"
python3 - <<'PY' >/tmp/echo.log 2>&1 &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"auth": self.headers.get("Authorization","")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.HTTPServer(("0.0.0.0", 8098), H).serve_forever()
PY
sleep 2
SEEN=$(curl -s --max-time 15 -x http://127.0.0.1:${HOST_PORT} -H "Authorization: Bearer ${PLACEHOLDER}" \
        http://host.docker.internal:8098/ | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])' 2>/dev/null)
[ "$SEEN" = "Bearer ${REAL_SECRET}" ] && ok "upstream saw the REAL secret" || bad "upstream saw: ${SEEN:-<nothing>}"

step "7. deny an unbound destination"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:${HOST_PORT} -H "Authorization: Bearer ${PLACEHOLDER}" http://198.51.100.7/)
[ "$CODE" = "403" ] && ok "unbound destination -> 403" || bad "unbound destination -> $CODE"

step "8. no secret bytes in container logs"
if docker logs kow-e2e 2>&1 | grep -q "$REAL_SECRET"; then bad "SECRET IN CONTAINER LOGS"; else ok "no secret bytes in container logs"; fi

docker rm -f kow-e2e >/dev/null 2>&1

step "9. the REPO's docker-compose.yml, via docker compose"
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"; ok "docker compose v2 available ($(docker compose version --short 2>/dev/null))"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"; ok "docker-compose v1 available ($(docker-compose version --short 2>/dev/null))"
else
  bad "no compose implementation installable"; COMPOSE=""
fi
COMPOSE_DIR="$STACK/compose"
mkdir -p "$COMPOSE_DIR/static"
cp "$SRC/docker-compose.yml" "$COMPOSE_DIR/docker-compose.yml"
cp "$SRC/Dockerfile" "$COMPOSE_DIR/Dockerfile"
cp -r "$SRC/src" "$SRC/pyproject.toml" "$SRC/requirements.lock" "$SRC/README.md" "$SRC/LICENSE" "$COMPOSE_DIR/" 2>/dev/null
cp "$STACK/bindings.yaml" "$COMPOSE_DIR/bindings.yaml"
cp "$STACK/static/secrets.yaml" "$COMPOSE_DIR/static/secrets.yaml"
chmod 0700 "$COMPOSE_DIR/static"; chmod 0600 "$COMPOSE_DIR/static/secrets.yaml"
chown -R 65532:65532 "$COMPOSE_DIR/static"
# Override ONLY what the static backend needs; the base file stays as shipped,
# so this proves the shipped compose file actually works.
cat > "$COMPOSE_DIR/docker-compose.override.yml" <<YAML
services:
  kow:
    build:
      context: .
    image: kow:e2e
    # !override, not a plain list: compose MERGES sequences by appending, so a
    # bare `ports:` here keeps the base file's 127.0.0.1:14322:14322 as well and
    # the stack fails to bind when the systemd leg already holds that port in
    # this VM. Requires compose >= 2.24.4.
    ports: !override
      - "127.0.0.1:${HOST_PORT}:14322"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./bindings.yaml:/etc/kow/bindings.yaml:ro
      - ./static:/etc/kow/static:ro
      - kow-state:/var/lib/kow
      - kow-logs:/var/log/kow
YAML
# `!override` below is Compose >= 2.24.4. On older compose the file fails to
# parse and the error looks nothing like a version problem, so say it plainly.
if [ -n "$COMPOSE" ]; then
  CV=$($COMPOSE version --short 2>/dev/null | tr -d 'v')
  case "$CV" in
    [0-9]*.[0-9]*)
      if [ "$(printf '%s\n2.24.4\n' "$CV" | sort -V | head -1)" != "2.24.4" ]; then
        bad "compose $CV is older than 2.24.4; the ports:!override merge tag is unsupported"
        COMPOSE=""
      fi ;;
    *)
      # Unknown version: do NOT fail open silently into a cryptic YAML parse
      # error — say what we could not determine before trying anyway.
      printf '  note: could not parse compose version (%s); if `up` fails to parse the\n' "${CV:-empty}"
      printf '        override, suspect compose < 2.24.4 (ports:!override unsupported)\n' ;;
  esac
fi
[ -n "$COMPOSE" ] && ( cd "$COMPOSE_DIR" && $COMPOSE up -d >/tmp/compose.log 2>&1 )
sleep 10
if [ -n "$COMPOSE" ] && ( cd "$COMPOSE_DIR" && $COMPOSE ps -q | grep -q . ); then
  ok "docker compose up brought the service online"
else
  bad "docker compose up failed"; tail -15 /tmp/compose.log
  [ -n "$COMPOSE" ] && ( cd "$COMPOSE_DIR" && $COMPOSE logs 2>&1 | tail -10 )
fi
HZC=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:${HOST_PORT}" http://healthz.kow.invalid/healthz)
[ "$HZC" = "200" ] && ok "compose stack healthz -> 200" || bad "compose healthz returned $HZC"
SEENC=$(curl -s --max-time 15 -x "http://127.0.0.1:${HOST_PORT}" -H "Authorization: Bearer ${PLACEHOLDER}" \
        http://host.docker.internal:8098/ | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])' 2>/dev/null)
[ "$SEENC" = "Bearer ${REAL_SECRET}" ] && ok "compose stack swapped the real secret" || bad "compose upstream saw: ${SEENC:-<nothing>}"
# The shipped file declares named volumes; prove they were actually created.
docker volume ls -q | grep -q kow && ok "named volumes created by compose" || bad "no kow volumes"
[ -n "$COMPOSE" ] && ( cd "$COMPOSE_DIR" && $COMPOSE down -v >/dev/null 2>&1 )
ok "docker compose down cleaned up"

printf '\n===== docker E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
