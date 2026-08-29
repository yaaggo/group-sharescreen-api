// One Redis connection for the whole process, shared by every store that
// uses it (chat, rooms, accounts, announcement, partners, supporters, guest
// points).
//
// Each of those used to build its own client from the same eight lines of
// boilerplate, which meant seven TCP/TLS connections per process — and seven
// times per worker once the server started running on several cores (see
// clusterPrimary.ts), so a machine with eight cores opened fifty-six of
// them. Nothing here needs a connection of its own: node-redis pipelines
// commands over a single one, and none of these stores uses a blocking
// command or pub/sub, which are the only two things that would.
//
// The other reason this exists is REDIS_CA_CERT. A `rediss://` endpoint
// whose certificate is signed by a private CA fails with "self-signed
// certificate" unless that CA is handed to the TLS layer, and nothing was
// handing it over — the variable was in .env but never read, so every one of
// those seven clients kept reconnecting and logging the same failure
// forever.
import { createClient } from "redis";

// `any` isn't a shortcut — @redis/client's generic RedisClientType fails to
// structurally match itself across separate `ReturnType<typeof createClient>`
// computations (a known typings quirk around scanIterator's `this`
// parameter), so a precise alias is more trouble than it's worth for the
// plain commands the stores actually use.
export type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

// Redis stays opt-in: with REDIS_URL unset every store falls back to its own
// JSON file on disk, exactly as before. Read once here so the stores agree
// on whether it's configured.
export const REDIS_URL = process.env.REDIS_URL;
export const REDIS_ENABLED = Boolean(REDIS_URL);

// Escape hatch for a broken/rotated certificate chain in an emergency. Off by
// default and deliberately loud about what it costs: with this on, the
// connection is still encrypted but no longer authenticated, so it can be
// intercepted. REDIS_CA_CERT is the actual fix.
const REJECT_UNAUTHORIZED = process.env.REDIS_TLS_REJECT_UNAUTHORIZED !== "false";

const PEM_BLOCK_RE = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
const PEM_LINE_LENGTH = 64;

// Rebuilds a certificate into the line-wrapped form OpenSSL insists on.
//
// A PEM pasted into a .env almost never survives with its newlines intact —
// it arrives as one long line, or with the breaks escaped as a literal "\n".
// OpenSSL can't read either: it needs the BEGIN and END markers on lines of
// their own. So the base64 is pulled out of whatever shape it came in and
// re-wrapped, which also means a chain of several certificates concatenated
// together keeps working.
export function normalizeCaCert(raw: string): string | null {
  const unescaped = raw.trim().replace(/^["']|["']$/g, "").replace(/\\n/g, "\n");
  const blocks: string[] = [];
  for (const match of unescaped.matchAll(PEM_BLOCK_RE)) {
    const body = match[1].replace(/[^A-Za-z0-9+/=]/g, "");
    if (!body) continue;
    const lines: string[] = [];
    for (let i = 0; i < body.length; i += PEM_LINE_LENGTH) {
      lines.push(body.slice(i, i + PEM_LINE_LENGTH));
    }
    blocks.push(`-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`);
  }
  return blocks.length > 0 ? blocks.join("\n") : null;
}

function caCert(): string | null {
  const raw = process.env.REDIS_CA_CERT;
  if (!raw || !raw.trim()) return null;
  const normalized = normalizeCaCert(raw);
  if (!normalized) {
    console.error(
      "[redis] REDIS_CA_CERT está definida mas não contém um certificado PEM válido — ignorando."
    );
  }
  return normalized;
}

// node-redis reconnects on its own, forever, and emits "error" on every
// attempt. With a genuinely broken connection that's a line in the log every
// few hundred milliseconds — times the number of workers. The first failure
// is worth seeing immediately; after that, one line a minute saying what is
// still wrong and how many attempts it swallowed says the same thing without
// burying everything else.
const ERROR_LOG_INTERVAL_MS = 60_000;
let lastErrorLoggedAt = 0;
let suppressedErrors = 0;
let lastErrorMessage = "";

function logConnectionError(err: Error): void {
  const now = Date.now();
  if (lastErrorLoggedAt !== 0 && now - lastErrorLoggedAt < ERROR_LOG_INTERVAL_MS) {
    suppressedErrors += 1;
    lastErrorMessage = err.message;
    return;
  }
  const repeats =
    suppressedErrors > 0 ? ` (+${suppressedErrors} tentativas no último minuto)` : "";
  console.error(`[redis] Erro na conexão com o Redis: ${err.message}${repeats}`);
  if (/self.signed|unable to verify|certificate/i.test(err.message) && !process.env.REDIS_CA_CERT) {
    console.error(
      "[redis] O endpoint usa TLS com um certificado que este processo não confia. Defina REDIS_CA_CERT com o certificado da CA."
    );
  }
  lastErrorLoggedAt = now;
  suppressedErrors = 0;
  lastErrorMessage = err.message;
}

// Surfaced so a caller can mention the underlying cause without every store
// having to keep its own copy of it.
export function lastRedisError(): string {
  return lastErrorMessage;
}

let redisReady: Promise<RedisClient> | null = null;

// Lazily connects on first use and memoizes the in-flight/connected client.
// A failed connect resets the memo so the next call retries instead of
// replaying the same rejection forever.
export async function getRedis(): Promise<RedisClient> {
  if (redisReady) return redisReady;
  if (!REDIS_URL) throw new Error("REDIS_URL não configurada.");
  const ca = caCert();
  const usesTls = REDIS_URL.startsWith("rediss://");
  const client = createClient({
    url: REDIS_URL,
    // Only ever passed for a TLS endpoint: handing tls options to a plain
    // `redis://` URL would turn a working connection into a failing one.
    ...(usesTls
      ? {
          socket: {
            tls: true as const,
            ...(ca ? { ca: [ca] } : {}),
            rejectUnauthorized: REJECT_UNAUTHORIZED,
          },
        }
      : {}),
  });
  client.on("error", logConnectionError);
  const connecting = client.connect().then(() => client);
  redisReady = connecting;
  try {
    return await connecting;
  } catch (err) {
    redisReady = null;
    try {
      // The client keeps its own reconnect loop alive otherwise, which would
      // leave one orphaned socket retrying forever per failed attempt.
      client.destroy();
    } catch {
      // Already torn down by the failed connect — nothing to clean up.
    }
    throw err;
  }
}
