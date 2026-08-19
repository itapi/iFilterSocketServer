// PM2 process definition.
//
// ONE codebase, TWO running instances — iFilter and iShield each get their own
// process, port, checkout and .env.
//
// The load-bearing reason is auth: JWT_SECRET is a single module-level constant
// used both to verify admin JWTs and as the literal device token, and the two
// products sign with different secrets (iFilter_Secret_Key_2025 vs
// iShield_Secret_Key_2025). One process holds one, so sharing would mean
// unifying them — which merges the two products' admin auth domains.
//
// Session namespace is the second reason. `sessions` and `screenSessions` are
// keyed on clientId alone, and the room is `session:${clientId}`. clientId is
// `client_unique_id`, which is NOT an auto-increment: both products draw a
// random ~9-digit int, and measured overlap on 2026-08-19 was 0 across 97
// iFilter and 17 iShield clients. So a collision is unlikely rather than
// impossible — but the relay forwards source→sink with no product check, so if
// two ever did collide, one product's device would stream to the other's admin.
//
// So everything that differs between instances is environment. server.js reads
// it with dotenv; this file cannot, because PM2 evaluates it and `pm2 start`
// may run before `npm ci` has created node_modules — a require() of dotenv here
// would make the process definition depend on an install step. Six lines of
// parsing instead of a dependency.

const fs = require('fs');
const path = require('path');

function envValue(key) {
  const file = path.join(__dirname, '.env');
  if (!fs.existsSync(file)) return undefined;
  const line = fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.startsWith(`${key}=`));
  return line ? line.slice(key.length + 1).trim().replace(/^["']|["']$/g, '') : undefined;
}

// Names the PM2 process. Defaults to 'ifilter' so an existing checkout with an
// INSTANCE_NAME-less .env keeps the process name it already has — renaming a
// live PM2 app orphans it from `pm2 save`, and this box has been running
// `ifilter-socket` since 2026-07-14.
const instance = process.env.INSTANCE_NAME || envValue('INSTANCE_NAME') || 'ifilter';

module.exports = {
  apps: [
    {
      name: `${instance}-socket`,
      script: 'server.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '256M',
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};
