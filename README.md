# Socket Server

Real-time WebSocket server for live admin–client sessions: chat/command relay
over Socket.IO, and a raw binary H.264 screen relay on `/screen`.
Node.js + Express + Socket.IO.

**One codebase, two running instances.** iFilter and iShield each get their own
process, port, checkout and `.env`. Nothing in `server.js` is product-specific —
no database, in-memory `Map`s only, pure relay — so the entire difference between
the two deployments is four environment variables.

| Instance | PM2 app | Port | Hostname | Checkout |
| --- | --- | --- | --- | --- |
| iFilter | `ifilter-socket` | 3001 | `socket.ikosher.me` | `/var/www/iFilterSocketServer` |
| iShield | `ishield-socket` | 3002 | `ishield-socket.ikosher.me` | `/var/www/ishield-socket` |

*(The iFilter checkout keeps its 2026-07 directory name. The PM2 app was created
against that path, and renaming it orphans the entry `pm2 save` restores on boot.)*

## Why they cannot be one process

**One process holds one `JWT_SECRET`, and this is the decisive one.** It is used
both to verify admin/sink JWTs and as the literal device token
(`token !== JWT_SECRET`, `server.js:151`), and the two dashboards sign with
different secrets — `iFilter_Secret_Key_2025` (hardcoded in `AuthMiddleware.php`)
versus `iShield_Secret_Key_2025` (resolved by the iShield dashboard's
`auth-secret.php`). A single process cannot verify both, so sharing one would
mean unifying the secrets — which merges the two products' admin auth domains:
an iFilter admin token would open iShield sessions.

Measured on the box, both directions:

```
iShield :3002 + iShield secret   ACCEPTED
iShield :3002 + iFilter secret   REJECTED  close=1008 Invalid client token
iFilter :3001 + iFilter secret   ACCEPTED
iFilter :3001 + iShield secret   REJECTED  close=1008 Invalid client token
```

**Session-namespace collision is the second reason, and it is a risk rather than
a certainty.** `sessions` and `screenSessions` are keyed on `clientId` alone, and
the room is `session:${clientId}` (`server.js:39, 166, 320`). The screen relay is
a blind passthrough — `target.send(data, { binary: true })` at `server.js:420` —
with no check that source and sink belong to the same product, so two clients
sharing an id across products would put one product's device screen in front of
the other's admin.

How likely that is depends on how the id is generated, and it is worth being
precise because an earlier version of this file got it wrong. `client_unique_id`
is **not** an auto-increment. Both products draw a random ~9-digit integer, and
the measured overlap on 2026-08-19 was **0**, across 97 iFilter and 17 iShield
clients:

```sql
SELECT COUNT(*) FROM ifilter.clients f
  JOIN ishield.clients s ON f.client_unique_id = s.client_unique_id;  -- 0
```

So a shared process would probably not have collided any time soon. "Probably
not" is a poor property for a screen-sharing boundary between two products, but
it is not the reason the processes are split — the auth domain is.

## Setup

```bash
cp .env.example .env   # then edit: INSTANCE_NAME, PORT, JWT_SECRET, ALLOWED_ORIGINS
npm ci --omit=dev
```

`.env` is gitignored and lives only on the server — it is what makes a checkout
*this* instance rather than the other one. `deploy/remote-deploy.sh` refuses to
run against a directory that has no `.env`, because without one the process would
come up on the default port 3001 with iFilter's secret.

| Variable | Description |
| --- | --- |
| `INSTANCE_NAME` | Names the PM2 process, `${INSTANCE_NAME}-socket`. Defaults to `ifilter`. |
| `PORT` | Port behind the nginx reverse proxy. |
| `JWT_SECRET` | Verifies admin JWTs **and** is the literal device token. Baked into the APK — changing it needs an app release. |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins. `*` disables the allowlist; don't. |

## Deploying

```powershell
.\deploy\deploy.ps1 -Target ishield       # 4-5 devices — go first
.\deploy\deploy.ps1 -Target ifilter       # ~1,000 devices
.\deploy\deploy.ps1 -Target ifilter -Ref v1.1.0
```

`-Target` is mandatory. There is no default, because a default would eventually
restart the wrong instance.

**A code change reaches both products as two deploys of one commit.** That is
deliberate rather than a limitation: a shared checkout would mean every iShield
change restarts the process serving ~1,000 iFilter devices, and sessions are
in-memory, so a restart ends every live session on that instance. Deploy to
`ishield` first, verify, then `ifilter`.

It ships `git archive HEAD` — the **committed** tree, not the working copy — so
uncommitted edits are not deployed and the script stops rather than shipping
something you did not mean. Both installers in this estate were found serving a
working-tree snapshot matching no commit in their repository; this is what
prevents that here.

On the server, `remote-deploy.sh`:

1. refuses a target with no `.env`, or a tarball with no `server.js`;
2. rejects the tree if any `.sh`/`.js`/`.json`/`.conf` has CRLF;
3. runs `node --check` over every staged `.js` (the Node `php -l`), aborting
   before anything is swapped;
4. tars the current deployment into `/root/backups/deploy/` (last 10 kept);
5. `rsync --delete`, excluding `.env`, `node_modules/` and `*.log`;
6. `npm ci --omit=dev` **only if `package-lock.json` actually changed**;
7. `pm2 reload`, or `pm2 start` + `pm2 save` on a first deploy;
8. smoke-tests `127.0.0.1:$PORT/health` and **restores the backup automatically**
   if it is not 200.

The public URL is checked too but does **not** trigger a rollback: a non-200
there is nginx, DNS or the certificate, none of which the deploy touched, and all
of which are the expected state before a new instance's hostname is cut over.

nginx vhosts for both hostnames are in `deploy/nginx/`, with the first-install
procedure for a new hostname in its README.

## HTTP endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server health + active session count. The deploy smoke target. |
| GET | `/session/:clientId/status` | Whether a session exists for a client |

## Socket events

### Client → Server
| Event | Payload | Description |
|-------|---------|-------------|
| `message` | envelope (below) | Relayed to the other side |
| `session:end` | — | End the session |

### Server → Client
| Event | Payload | Description |
|-------|---------|-------------|
| `session:waiting` | — | Waiting for the other side |
| `session:active` | — | Both sides connected |
| `session:client_disconnected` | — | Client dropped, still waiting |
| `session:ended` | `{ reason }` | Session is over |
| `message` | `{ from, ...envelope }` | Relayed message |

Relayed messages are a versioned envelope — `{ v, id, type, ts, payload }`, where
`type` is one of `cmd`/`res`/`event`/`err`/`stream` — capped at 8 KB.

### Socket auth (handshake)

```json
{ "token": "<JWT from PHP login>", "clientId": "<client_unique_id>", "role": "admin" }
```

The Android client uses `"role": "client"` and sends `JWT_SECRET` itself as the
token. See the note below.

### Screen relay (`/screen`)

Raw binary WebSocket, no JSON parsing. Both sides connect with query params —
`?clientId=&token=&role=source` from the device, `role=sink` from the dashboard.
Frames are `[0]` type (`0x00` SPS/PPS config, `0x01` H.264), `[1..4]` big-endian
size, `[5..]` NAL bytes. The server never inspects the payload. It drops frames
when the sink's buffer exceeds 256 KB, so a slow viewer degrades rather than
backing up.

## Known: the device token is the JWT signing key

`server.js` authenticates a device by string-comparing its token against
`JWT_SECRET` (`:151` and `:372`) — the same secret used to *sign* dashboard admin
JWTs. Since that value is baked into every APK and extractable with `unzip` and
`grep`, any device owner can forge an admin token for that product.

Fixing it properly means a separate `DEVICE_TOKEN`, distinct from `JWT_SECRET`.
It is a small change here, but the device half only lands at an app release, so
the server would accept both during the transition.

## Firewall

Neither port should be open externally — nginx proxies to `127.0.0.1`. If `ufw`
is active, they need no rule at all.
