# nginx reference configuration

Copies of what is loaded on the VPS, so the server is no longer the only place
this configuration exists. `socket.conf` was pulled from the box on 2026-08-19;
before that it existed nowhere but `/etc/nginx/sites-available/socket`.

| File | Installs as | Proxies to |
| --- | --- | --- |
| `socket.conf` | `sites-available/socket` | `socket.ikosher.me` → `127.0.0.1:3001` (`ifilter-socket`) |
| `ishield-socket.conf` | `sites-available/ishield-socket` | `ishield-socket.ikosher.me` → `127.0.0.1:3002` (`ishield-socket`) |

Neither port is reachable from outside. nginx terminates TLS and forwards the
WebSocket upgrade; both transports ride one vhost — socket.io on `/socket.io/`
and the raw binary H.264 screen relay on `/screen`.

## Why two vhosts and not one path split

The two products cannot share a socket process, so they cannot share a vhost
either. `JWT_SECRET` is one constant per process — used both to verify admin JWTs
and as the literal device token — and the two dashboards sign with different
secrets, so one process cannot serve both without merging their admin auth
domains.

Session namespace is a second, weaker reason: `sessions` and `screenSessions` are
keyed on `clientId` alone and the relay forwards source→sink with no product
check. `client_unique_id` is a random ~9-digit int rather than a sequence though,
with measured overlap 0 on 2026-08-19, so that alone would not have forced the
split.

## Standing up the iShield hostname

`ishield-socket.conf` as committed includes the `listen 443` and certificate
lines, which are certbot's work rather than hand-written — so it cannot be
installed as-is before the certificate exists. First install:

1. **DNS first.** An `A` record for `ishield-socket.ikosher.me` → `187.127.70.80`
   in the `ikosher.me` zone (`ns1`/`ns2.dns-parking.com`). No `AAAA`: the box has
   no IPv6 for these names, and Let's Encrypt prefers IPv6 when an `AAAA` exists,
   so a stray one fails validation rather than falling back.

   Verify at the authoritative server, not a public resolver — propagation starts
   *at* the authoritative server, so absence there is absence everywhere:

   ```
   dig +short ishield-socket.ikosher.me @ns1.dns-parking.com
   dig +short ifilter-app.ikosher.me    @ns1.dns-parking.com   # known-good control
   ```

   Do not use the SOA serial as evidence. Hostinger does not reliably bump it —
   `ikosher.me` stayed on `2026081701` across the 19 Aug record additions.

2. **A port-80-only vhost**, so certbot has something to attach to:

   ```nginx
   server {
       listen 80;
       server_name ishield-socket.ikosher.me;
       location / { proxy_pass http://127.0.0.1:3002; }
   }
   ```

   `nginx -t`, then reload.

3. `certbot --nginx -d ishield-socket.ikosher.me`, which rewrites the vhost into
   roughly the committed shape.

4. Replace the result with `ishield-socket.conf` (it adds the WebSocket upgrade
   headers and the proxy timeouts certbot does not know about), `nginx -t`,
   reload, then **pull the file back here** so the two do not diverge.

5. `certbot renew --dry-run`, and check the renewal config has no manual DNS
   hook — one configured that way waits forever and fails silently in ~60 days.

## Applying a change

Reference copies; nothing deploys them. Edit on the server, `nginx -t`, reload,
pull back. `nginx -T` prints the fully-resolved config if you need to be sure
what is loaded.

When verifying a reload, check worker start times before believing a negative
result: nginx keeps old workers briefly during a graceful restart, and a `curl`
issued milliseconds after `systemctl reload` can land on one. That produced a
false 403 during the iShield ACME work on 18 Aug.
