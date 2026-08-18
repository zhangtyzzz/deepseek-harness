#!/usr/bin/env bash
# One-shot deployer for the dsh web surface.
#
#   ./dsh-deploy.sh deploy     interactive: asks for what it needs, then brings it up
#   ./dsh-deploy.sh status     containers, health, auth state, tunnel connections
#   ./dsh-deploy.sh logs       follow the harness log
#   ./dsh-deploy.sh update     pull a newer image and recreate, keeping state
#   ./dsh-deploy.sh stop       stop and remove the containers, keeping state
#   ./dsh-deploy.sh destroy    also delete the state volume (password, sessions, credentials)
#   ./dsh-deploy.sh rotate-password
#
# Deliberately uses plain `docker run` rather than compose: a docker CLI installed
# from the static tarball has no compose plugin, and this way the script has no
# dependency beyond docker itself.
#
# Every prompt can be pre-answered with an environment variable, so a second
# deployment is scriptable: DSH_MODE, DSH_HOSTNAME, DSH_TUNNEL_TOKEN,
# DSH_CF_TEAM, DSH_CF_AUD, DSH_PORT, DSH_WORKSPACE, DSH_IMAGE.
set -euo pipefail

# `ipconfig` lives in /usr/sbin, which a trimmed PATH often omits.
PATH=$PATH:/usr/sbin:/sbin

IMAGE=${DSH_IMAGE:-ghcr.io/zhangtyzzz/dsh-web:latest}
NAME=${DSH_NAME:-dsh}
TUNNEL_NAME=${DSH_TUNNEL_NAME:-dsh-cloudflared}
NETWORK=${DSH_NETWORK:-dsh-net}
VOLUME=${DSH_VOLUME:-dsh-home}
CONF_DIR=${DSH_CONF_DIR:-$HOME/.dsh-deploy}
CONF_FILE=$CONF_DIR/deployment.env

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '  \033[33m! %s\033[0m\n' "$*" >&2; }
die()  { printf '\n\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# ── docker availability ──────────────────────────────────────────────────────
require_docker() {
  command -v docker > /dev/null 2>&1 || die "docker not found in PATH."
  if docker info > /dev/null 2>&1; then return; fi
  if command -v colima > /dev/null 2>&1; then
    warn "the docker daemon is not reachable; colima is installed."
    read -r -p "  start colima now? [Y/n] " reply
    case "${reply:-Y}" in
      [Nn]*) die "start a docker daemon and re-run." ;;
      *) colima start --vm-type vz --cpu 4 --memory 4 || die "colima failed to start."
         export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
         docker info > /dev/null 2>&1 || die "daemon still unreachable." ;;
    esac
  else
    die "the docker daemon is not reachable. Start Docker (or colima) and re-run."
  fi
}

# ── input helpers ────────────────────────────────────────────────────────────
ask() {                                   # ask VAR "prompt" "default"
  local var=$1 prompt=$2 default=${3:-} current=${!1:-} reply
  if [ -n "$current" ]; then info "$prompt → $current (from the environment)"; return; fi
  if [ -n "$default" ]; then read -r -p "  $prompt [$default]: " reply; else read -r -p "  $prompt: " reply; fi
  printf -v "$var" '%s' "${reply:-$default}"
}

ask_secret() {                            # ask_secret VAR "prompt"
  local var=$1 prompt=$2 current=${!1:-} reply
  if [ -n "$current" ]; then info "$prompt → (from the environment)"; return; fi
  read -r -s -p "  $prompt: " reply; echo
  printf -v "$var" '%s' "$reply"
}

# The provider rejects anything but a bare hostname at load time; catching it here
# turns a container that exits on boot into a prompt the user can fix.
validate_team_domain() {
  case "$1" in
    http*|*/*) die "team domain must be a bare hostname like example.cloudflareaccess.com (no scheme, no path)." ;;
  esac
  [[ "$1" =~ ^[A-Za-z0-9.-]+$ ]] || die "team domain '$1' is not a hostname."
}

validate_aud() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || warn "the AUD tag is usually 64 hex characters; '$1' looks unusual — continuing anyway."
}

primary_lan_ip() {
  # Best-effort only, and it must never fail the script: `hostname -I` does not
  # exist on macOS, and `pipefail` would otherwise turn that into an exit.
  if command -v ipconfig > /dev/null 2>&1; then
    ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true
  else
    { hostname -I 2>/dev/null || true; } | awk '{print $1}' || true
  fi
  return 0
}

# ── collect the deployment shape ─────────────────────────────────────────────
collect() {
  say "How should this deployment be reachable?"
  info "1) LAN / this machine only — password sign-in"
  info "2) public hostname through a Cloudflare tunnel — Access identity, password kept as a fallback"
  info "3) public hostname through a Cloudflare tunnel — Access identity only, no password"
  ask DSH_MODE "choose 1, 2 or 3" "2"
  case "$DSH_MODE" in
    1|lan)      MODE=lan ;;
    2|cf)       MODE=cf ;;
    3|cf-only)  MODE=cf-only ;;
    *) die "unrecognized choice '$DSH_MODE'." ;;
  esac

  if [ "$MODE" = lan ]; then
    say "LAN deployment"
    local guess; guess=$(primary_lan_ip)
    ask DSH_PORT "published port" "3080"
    ask DSH_HOSTNAME "the address a browser will use (host or host:port)" "${guess:+$guess:$DSH_PORT}"
    [ -n "$DSH_HOSTNAME" ] || die "an address is required; the trust fence refuses any Host it was not told about."
    TRUSTED_HOST=$DSH_HOSTNAME
    COOKIE_SECURE=never
    PASSWORD=1
  else
    say "Cloudflare tunnel deployment"
    ask DSH_HOSTNAME "the public hostname (must match the Access application)" ""
    [ -n "$DSH_HOSTNAME" ] || die "a hostname is required."
    ask_secret DSH_TUNNEL_TOKEN "cloudflared tunnel token (input hidden)"
    [ -n "$DSH_TUNNEL_TOKEN" ] || die "a tunnel token is required."
    ask DSH_CF_TEAM "Access team domain, e.g. example.cloudflareaccess.com" ""
    validate_team_domain "$DSH_CF_TEAM"
    ask DSH_CF_AUD "Access application AUD tag" ""
    [ -n "$DSH_CF_AUD" ] || die "the AUD tag is required; without it any token from your team would be accepted."
    validate_aud "$DSH_CF_AUD"
    TRUSTED_HOST=$DSH_HOSTNAME
    COOKIE_SECURE=always
    [ "$MODE" = cf ] && PASSWORD=1 || PASSWORD=0
    DSH_PORT=${DSH_PORT:-3080}
  fi

  ask DSH_WORKSPACE "directory the agent works in" "$PWD/dsh-workspace"
  mkdir -p "$DSH_WORKSPACE"
  # uid 1000 inside the container owns nothing on the host; make the mount usable.
  chmod -R a+rwX "$DSH_WORKSPACE" 2> /dev/null || warn "could not widen permissions on $DSH_WORKSPACE; uid 1000 must be able to write it."

  say "About to deploy"
  info "image           $IMAGE"
  info "mode            $MODE"
  info "trusted host    $TRUSTED_HOST"
  info "cookie Secure   $COOKIE_SECURE"
  info "password login  $([ "$PASSWORD" = 1 ] && echo enabled || echo disabled)"
  [ "$MODE" != lan ] && info "Access team     $DSH_CF_TEAM"
  [ "$MODE" != lan ] && info "Access AUD      ${DSH_CF_AUD:0:12}…"
  info "workspace       $DSH_WORKSPACE"
  info "state volume    $VOLUME"
  [ "$MODE" = lan ] && info "published on    127.0.0.1 and the LAN, port $DSH_PORT" \
                    || info "published on    nothing — the tunnel is the only ingress"
  read -r -p "  proceed? [Y/n] " reply
  case "${reply:-Y}" in [Nn]*) die "aborted." ;; esac

  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  {
    echo "MODE=$MODE"
    echo "IMAGE=$IMAGE"
    echo "TRUSTED_HOST=$TRUSTED_HOST"
    echo "COOKIE_SECURE=$COOKIE_SECURE"
    echo "PASSWORD=$PASSWORD"
    echo "DSH_PORT=$DSH_PORT"
    echo "DSH_WORKSPACE=$DSH_WORKSPACE"
    [ "$MODE" != lan ] && echo "DSH_CF_TEAM=$DSH_CF_TEAM"
    [ "$MODE" != lan ] && echo "DSH_CF_AUD=$DSH_CF_AUD"
    [ "$MODE" != lan ] && echo "DSH_TUNNEL_TOKEN=$DSH_TUNNEL_TOKEN"
  } > "$CONF_FILE"
  chmod 600 "$CONF_FILE"
  info "settings saved to $CONF_FILE (mode 600; it holds the tunnel token)"
}

load_conf() {
  [ -f "$CONF_FILE" ] || die "no deployment found at $CONF_FILE — run '$0 deploy' first."
  # shellcheck disable=SC1090
  . "$CONF_FILE"
}

# ── image identity ───────────────────────────────────────────────────────────
# `docker run` resolves a tag against the local store, so a pull that never
# landed leaves the previous image running and nothing says so. Every claim about
# "updated" below is therefore made against a digest, not against a pull's word.
tag_digest() {                            # tag_digest <image|image-id>
  docker inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$1" 2> /dev/null || true
}

container_image_digest() {                # digest of the image a container runs
  local id
  id=$(docker inspect --format '{{.Image}}' "$1" 2> /dev/null) || return 0
  tag_digest "$id"
}

# ── bring it up ──────────────────────────────────────────────────────────────
start_containers() {
  docker network inspect "$NETWORK" > /dev/null 2>&1 || docker network create "$NETWORK" > /dev/null
  docker rm -f "$NAME" "$TUNNEL_NAME" > /dev/null 2>&1 || true

  local args=(-d --name "$NAME" --network "$NETWORK" --restart unless-stopped
    -e "DSH_TRUSTED_HOST=$TRUSTED_HOST"
    -e "DSH_COOKIE_SECURE=$COOKIE_SECURE"
    -e "DSH_WEB_AUTH_PASSWORD=$PASSWORD"
    -e DSH_PRINT_CONFIG=1
    -v "$VOLUME:/dsh-home"
    -v "$DSH_WORKSPACE:/workspace")
  if [ "$MODE" != lan ]; then
    args+=(-e "DSH_CF_ACCESS_TEAM=$DSH_CF_TEAM" -e "DSH_CF_ACCESS_AUD=$DSH_CF_AUD")
  else
    args+=(-p "$DSH_PORT:3080")
  fi

  say "Starting the harness"
  docker run "${args[@]}" "$IMAGE" > /dev/null
  info "container $NAME started"

  if [ "$MODE" != lan ]; then
    docker run -d --name "$TUNNEL_NAME" --network "$NETWORK" --restart unless-stopped \
      cloudflare/cloudflared:latest tunnel --no-autoupdate run --token "$DSH_TUNNEL_TOKEN" > /dev/null
    info "container $TUNNEL_NAME started — point the tunnel's public hostname at http://$NAME:3080"
  fi
}

wait_ready() {
  say "Waiting for the harness to bind"
  local i
  for i in $(seq 1 60); do
    if docker logs "$NAME" 2>&1 | grep -q 'dsh web: http'; then info "bound after ${i}s"; return 0; fi
    if [ "$(docker inspect --format '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ]; then
      warn "the container exited. Its last words:"
      docker logs "$NAME" 2>&1 | tail -12 | sed 's/^/      /'
      die "deployment failed."
    fi
    sleep 1
  done
  warn "no bind line after 60s; last log lines:"
  docker logs "$NAME" 2>&1 | tail -12 | sed 's/^/      /'
}

show_password() {
  [ "$PASSWORD" = 1 ] || return 0
  local pw
  # A missing match must not abort the run: an existing state volume legitimately
  # prints no password.
  pw=$(docker logs "$NAME" 2>&1 | grep -oE '[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}' | head -1 || true)
  if [ -z "$pw" ]; then
    info "no new password printed — this state volume already holds a credential."
    return 0
  fi
  say "Sign-in password — shown once, never recoverable"
  printf '\n      \033[1;32m%s\033[0m\n\n' "$pw"
  info "Only its scrypt verifier is stored. Put it in a password manager now."
  info "This script does not write it to disk; '$0 rotate-password' issues a new one."
}

is_loopback_authority() {                 # 127.0.0.1[:port], localhost[:port], [::1][:port]
  case "${1%%:*}" in
    127.*|localhost|'[::1]'|'::1') return 0 ;;
    *) return 1 ;;
  esac
}

probe() {                                 # probe HOST [extra curl args...]
  local host=$1; shift
  docker exec "$NAME" curl -s -o /dev/null -w '%{http_code}' -X POST -H "Host: $host" \
    -H 'content-type: application/json' "$@" -d '{}' \
    http://127.0.0.1:3080/api/settings.describe 2>/dev/null || echo ERR
}

FORGED_ASSERTION='Cf-Access-Jwt-Assertion: eyJhbGciOiJub25lIn0.eyJhdWQiOlsieCJdfQ.'

self_check() {
  say "Self-check"
  local undeclared forged declared status

  # An authority this deployment was never told about must be refused whatever it
  # carries — that check is meaningful for every mode.
  undeclared=$(probe undeclared.invalid)
  forged=$(probe undeclared.invalid -H "$FORGED_ASSERTION")
  [ "$undeclared" = 403 ] && info "PASS  an undeclared authority is refused (403)" \
                          || warn "FAIL  expected 403 for an undeclared authority, got $undeclared"
  [ "$forged" = 403 ] && info "PASS  a forged Access assertion buys nothing (403)" \
                      || warn "FAIL  expected 403 for a forged assertion, got $forged"

  declared=$(probe "$TRUSTED_HOST")
  if is_loopback_authority "$TRUSTED_HOST"; then
    info "NOTE  '$TRUSTED_HOST' is a loopback authority, which reaches everything without a"
    info "      credential by design (unchanged from before authentication existed); got $declared"
  else
    [ "$declared" = 403 ] && info "PASS  '$TRUSTED_HOST' without a credential is refused (403)" \
                          || warn "FAIL  expected 403 for the declared authority with no credential, got $declared"
  fi

  status=$(docker exec "$NAME" curl -s -H "Host: $TRUSTED_HOST" http://127.0.0.1:3080/auth/status 2>/dev/null || echo ERR)
  info "auth status: $status"

  if [ "$MODE" != lan ]; then
    if docker logs "$TUNNEL_NAME" 2>&1 | grep -qiE "registered tunnel connection|connection.*registered"; then
      info "PASS  the tunnel registered at least one connection"
    else
      warn "the tunnel has not registered a connection yet. Check: $0 logs tunnel"
    fi
  fi
}

next_steps() {
  say "Next"
  if [ "$MODE" = lan ]; then
    info "1. open http://$TRUSTED_HOST/auth/login and sign in with the password above"
  else
    info "1. in the tunnel's Public Hostname, point https://$DSH_HOSTNAME at http://$NAME:3080"
    info "   and leave the HTTP Host Header override empty — the original Host is what the fence checks"
    info "2. open https://$DSH_HOSTNAME, pass the Cloudflare login; you land in dsh without a password prompt"
  fi
  info "then configure a model API key in the settings pane — that plane is reachable precisely because you are authenticated"
  info ""
  info "manage: $0 status | logs | update | stop | destroy | rotate-password"
  info "state:  volume '$VOLUME' holds sessions, settings, credentials and the password verifier"
}

cmd_deploy() {
  require_docker
  collect
  say "Pulling $IMAGE"
  info "the image carries the built workspace, so expect a multi-gigabyte download the first time"
  # Progress stays on screen: on a slow link this runs for many minutes, and a
  # silent pull is indistinguishable from a stalled one. Docker does not resume a
  # partial layer, so the answer to a slow pull is to let it finish, not to cut it
  # off — which is only a decision the operator can make from the byte counter.
  docker pull "$IMAGE" || die "pull failed."
  start_containers
  wait_ready
  show_password
  self_check
  next_steps
}

cmd_status() {
  require_docker; load_conf
  say "Containers"
  docker ps -a --filter "name=^${NAME}$" --filter "name=^${TUNNEL_NAME}$" \
    --format '  {{.Names}}  {{.Status}}  {{.Image}}'
  say "Health"
  info "$(docker inspect --format '{{.State.Health.Status}}' "$NAME" 2>/dev/null || echo unknown)"
  self_check
}

cmd_logs() {
  require_docker; load_conf
  case "${1:-harness}" in
    tunnel) docker logs -f --tail 100 "$TUNNEL_NAME" ;;
    *)      docker logs -f --tail 100 "$NAME" ;;
  esac
}

cmd_update() {
  require_docker; load_conf
  local before after running
  before=$(tag_digest "$IMAGE")
  say "Pulling a newer image"
  docker pull "$IMAGE" || die "pull failed — the deployment still runs its previous image."
  after=$(tag_digest "$IMAGE")
  [ -n "$after" ] || die "$IMAGE has no digest after the pull; refusing to claim an update."
  if [ "$before" = "$after" ]; then
    info "already the newest published image: $after"
  else
    info "image ${before:-<none>} → $after"
  fi
  start_containers
  wait_ready
  running=$(container_image_digest "$NAME")
  [ "$running" = "$after" ] \
    || die "'$NAME' runs ${running:-an unidentified image} but $after was pulled — update did not take."
  info "verified: '$NAME' runs $running"
  info "state kept; every browser session was invalidated by the restart, which is by design"
  self_check
}

cmd_stop() {
  require_docker; load_conf
  docker rm -f "$NAME" "$TUNNEL_NAME" > /dev/null 2>&1 || true
  say "Stopped. State volume '$VOLUME' is untouched; '$0 deploy' or '$0 update' brings it back."
}

cmd_destroy() {
  require_docker; load_conf
  warn "this deletes the state volume: sessions, settings, model credentials and the password verifier."
  read -r -p "  type the volume name to confirm ($VOLUME): " reply
  [ "$reply" = "$VOLUME" ] || die "not confirmed."
  docker rm -f "$NAME" "$TUNNEL_NAME" > /dev/null 2>&1 || true
  docker volume rm "$VOLUME" > /dev/null
  say "Destroyed."
}

cmd_rotate_password() {
  require_docker; load_conf
  [ "$PASSWORD" = 1 ] || die "this deployment has no password provider (mode $MODE)."
  docker exec "$NAME" rm -f /dsh-home/web-auth/password.json
  say "Credential deleted; restarting to issue a new password"
  docker restart "$NAME" > /dev/null
  wait_ready
  show_password
}

case "${1:-deploy}" in
  deploy)           cmd_deploy ;;
  status)           cmd_status ;;
  logs)             shift; cmd_logs "${1:-harness}" ;;
  update)           cmd_update ;;
  stop)             cmd_stop ;;
  destroy)          cmd_destroy ;;
  rotate-password)  cmd_rotate_password ;;
  *) die "usage: $0 {deploy|status|logs [tunnel]|update|stop|destroy|rotate-password}" ;;
esac
