#!/bin/bash
# Server side of the socket-server deploy. Receives a tar of the committed tree,
# stages it, checks it, swaps it into place and rolls back if the smoke test
# fails.
#
# This is the PHP remote-deploy.sh from the backend repos, adapted for Node:
#   * `node --check` replaces `php -l`
#   * node_modules/ and .env are excluded from --delete (both are server-side
#     only; .env is where the two instances differ, node_modules is an install
#     artifact)
#   * `npm ci --omit=dev` runs only when package-lock.json actually changed
#   * `pm2 reload` replaces `systemctl reload php8.3-fpm`
#
# Expects, in the environment:
#   APP_DIR   deployment target, e.g. /var/www/ishield-socket
#   PM2_APP   pm2 process name, e.g. ishield-socket
#   TARBALL   path to the uploaded tar
#   SMOKE_URL optional public URL that must return 200 afterwards
set -euo pipefail

APP_DIR=${APP_DIR:?APP_DIR not set}
PM2_APP=${PM2_APP:?PM2_APP not set}
TARBALL=${TARBALL:?TARBALL not set}
SMOKE_URL=${SMOKE_URL:-}

NAME=$(basename "$APP_DIR")
STAGE="/srv/ifilter/.staging/$NAME"
BACKUP_DIR=/root/backups/deploy
STAMP=$(date -u +%Y%m%d-%H%M%S)
BACKUP="$BACKUP_DIR/$NAME-$STAMP.tar.gz"

# .env holds this instance's identity -- port, JWT secret, CORS origins, and the
# INSTANCE_NAME that ecosystem.config.js turns into the pm2 process name. It is
# gitignored, so it is not in the incoming tree; without this exclude --delete
# would remove it and the process would come back up on the wrong port with the
# wrong secret.
EXCLUDES=(
  --exclude '.env'
  --exclude 'node_modules/'
  --exclude '*.log'
)

log() { printf '  %s\n' "$*"; }

log "target      : $APP_DIR"
log "pm2 app     : $PM2_APP"

# ---------------------------------------------------------------- preflight
if [ ! -f "$APP_DIR/.env" ]; then
  echo "ABORT: $APP_DIR/.env does not exist." >&2
  echo "  The instance's identity lives there and is never deployed. Create it" >&2
  echo "  from .env.example before the first deploy -- otherwise this would" >&2
  echo "  start a second process on the default port 3001 with iFilter's" >&2
  echo "  secret, which on the iShield target is exactly the collision this" >&2
  echo "  whole split exists to prevent." >&2
  exit 1
fi

# ---------------------------------------------------------------- stage
rm -rf "$STAGE"
mkdir -p "$STAGE" "$BACKUP_DIR"
tar -xf "$TARBALL" -C "$STAGE"
log "staged      : $(find "$STAGE" -type f | wc -l) files"

if [ ! -f "$STAGE/server.js" ]; then
  echo "ABORT: staged tree has no server.js -- refusing to swap an empty or wrong tarball" >&2
  exit 1
fi

# CRLF matters in anything this side executes or parses. `|| true` matters:
# grep exits 1 when it finds nothing, find propagates that, and under `set -e`
# the clean case would abort the deploy.
crlf=$(find "$STAGE" \( -name '*.sh' -o -name '*.js' -o -name '*.json' -o -name '*.conf' \) -type f \
         -exec grep -lI $'\r' {} + 2>/dev/null | head -5 || true)
if [ -n "$crlf" ]; then
  echo "ABORT: CRLF in files that run on Linux:" >&2
  echo "$crlf" | sed "s|$STAGE/|    |" >&2
  exit 1
fi
log "line endings: LF in all .sh/.js/.json/.conf"

# ---------------------------------------------------------------- verify
# The Node equivalent of `php -l`. Catches a syntax error before anything is
# swapped -- without it a bad commit takes the process down and pm2 restart-loops
# it. node_modules is excluded because linting dependencies proves nothing and
# is slow.
fail=0
while IFS= read -r f; do
  node --check "$f" >/dev/null 2>&1 || { echo "    SYNTAX ERROR: ${f#$STAGE/}" >&2; fail=1; }
done < <(find "$STAGE" -name '*.js' -not -path '*/node_modules/*')
[ "$fail" -eq 0 ] || { echo "ABORT: staged tree has JS syntax errors" >&2; exit 1; }
log "node --check: $(find "$STAGE" -name '*.js' -not -path '*/node_modules/*' | wc -l) files OK"

# ---------------------------------------------------------------- back up
# -C the parent and name the directory, so the tar restores over the same path.
tar -czf "$BACKUP" -C "$(dirname "$APP_DIR")" "$NAME"
log "backup      : $BACKUP ($(du -h "$BACKUP" | cut -f1))"

# ---------------------------------------------------------------- swap
# Recorded before the swap so we can tell whether dependencies actually changed.
# Reinstalling on every deploy would add ~20s and a network dependency to a
# one-line code change.
lock_before=$(sha256sum "$APP_DIR/package-lock.json" 2>/dev/null | cut -d' ' -f1 || echo none)

rsync -a --delete "${EXCLUDES[@]}" "$STAGE/" "$APP_DIR/"

lock_after=$(sha256sum "$APP_DIR/package-lock.json" 2>/dev/null | cut -d' ' -f1 || echo none)

if [ "$lock_before" != "$lock_after" ] || [ ! -d "$APP_DIR/node_modules" ]; then
  log "npm ci      : package-lock changed (or node_modules absent) -- installing"
  ( cd "$APP_DIR" && npm ci --omit=dev --no-audit --no-fund >/dev/null 2>&1 ) || {
    echo "ABORT: npm ci failed -- restoring backup" >&2
    rm -rf "${APP_DIR:?}"/*
    tar -xzf "$BACKUP" -C "$(dirname "$APP_DIR")"
    exit 1
  }
else
  log "npm ci      : skipped (package-lock unchanged)"
fi

# Code is root-owned and world-readable; nothing here is a secret except .env,
# which is 0600 and excluded from the rsync above so these modes never touch it.
chown -R root:root "$APP_DIR"
find "$APP_DIR" -mindepth 1 -type d -not -path '*/node_modules/*' -exec chmod 755 {} +
find "$APP_DIR" -mindepth 1 -type f -not -path '*/node_modules/*' -exec chmod 644 {} +
chmod 600 "$APP_DIR/.env"
log "permissions : applied (.env 0600)"

# ---------------------------------------------------------------- restart
# `pm2 reload` if the app is already known, `pm2 start` if this is the first
# deploy to a new instance. Either way `pm2 save` afterwards, so the process is
# in the resurrect list and survives a reboot -- a started-but-unsaved app comes
# back missing, which is the kind of thing you discover months later.
if pm2 describe "$PM2_APP" >/dev/null 2>&1; then
  pm2 reload "$PM2_APP" --update-env >/dev/null
  log "pm2         : reloaded $PM2_APP"
else
  ( cd "$APP_DIR" && pm2 start ecosystem.config.js >/dev/null )
  log "pm2         : started $PM2_APP (first deploy)"
fi
pm2 save >/dev/null 2>&1 || true

# ---------------------------------------------------------------- smoke
# Local first: it proves the process itself came up, and it works before DNS or
# a certificate exists -- which is the state a brand-new instance is in. The
# public URL then proves nginx and TLS on top of that, and is skipped when not
# supplied or not yet resolvable.
PORT=$(sed -n "s/^[[:space:]]*PORT[[:space:]]*=[[:space:]]*//p" "$APP_DIR/.env" | head -1 | tr -d "\"' ")
PORT=${PORT:-3001}

sleep 2
local_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$PORT/health" || true)
if [ "$local_code" != "200" ]; then
  echo "SMOKE TEST FAILED: 127.0.0.1:$PORT/health returned $local_code -- rolling back" >&2
  rm -rf "${APP_DIR:?}"/*
  tar -xzf "$BACKUP" -C "$(dirname "$APP_DIR")"
  pm2 reload "$PM2_APP" --update-env >/dev/null 2>&1 || true
  sleep 2
  after=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$PORT/health" || true)
  echo "rolled back to $BACKUP; local /health now returns $after" >&2
  exit 1
fi
log "smoke local : 127.0.0.1:$PORT/health -> 200"

if [ -n "$SMOKE_URL" ]; then
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$SMOKE_URL" || true)
  if [ "$code" = "200" ]; then
    log "smoke public: $SMOKE_URL -> 200"
  else
    # Deliberately not a rollback. The process is up and healthy on localhost --
    # a non-200 here is nginx, DNS or the certificate, none of which this deploy
    # touched, and all of which are the expected state before an instance's
    # hostname is cut over. Rolling back working code for that would be wrong.
    log "smoke public: $SMOKE_URL -> $code (process is healthy locally; check nginx/DNS/cert)"
  fi
fi

# Keep the last 10 backups; they are the rollback path.
#
# `find`, not `ls -1t <glob>`. On a first deploy no backup exists, so the glob
# matches nothing, `ls` exits 2, and `set -o pipefail` propagates that -- which
# aborts AFTER the swap, the install, the restart and a passing smoke test have
# all succeeded. The deploy has worked; the operator is told DEPLOY FAILED.
# Observed for real on the iFilter website repo's first deploy, 2026-08-18, and
# this target is genuinely new so it would have fired here.
find "$BACKUP_DIR" -maxdepth 1 -name "$NAME-*.tar.gz" -printf '%T@ %p\n' \
  | sort -rn | tail -n +11 | cut -d' ' -f2- | xargs -r rm --
rm -rf "$STAGE" "$TARBALL"
log "DEPLOY OK"
