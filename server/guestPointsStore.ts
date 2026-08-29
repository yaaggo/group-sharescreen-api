import fs from "node:fs";
import path from "node:path";
import { getRedis } from "./redisClient.js";

// Points held by a *guest* identity rather than an account.
//
// An account's points live on its Mongo document (see accountModels.ts's
// AccountDoc.points) because an account is a permanent thing. A guest is
// not: its whole identity is the token in one browser's localStorage (see
// signaling.ts's "register" handler, which mints `guest:<id>` and signs it),
// and that token is deliberately the only handle on it. So these are keyed
// by that guest id and nothing else — which is what makes "the points reset
// when the token changes" true by construction rather than by a rule
// somebody has to remember to enforce:
//
//   - localStorage cleared, a different browser, a private window: no token
//     to present, so "register" mints a brand new `guest:<id>` and this
//     store has never heard of it. Zero points.
//   - the token expires (30 days, see auth.ts's JWT_TTL): it stops
//     verifying, which is the same case as above.
//   - logging into an account: the account's own points take over
//     completely; whatever the guest identity had stays behind under its own
//     key, untouched, and is simply never consulted again.
//
// Note the flip side, which is what stops this from being farmable: a guest
// who wipes their identity to claim an ad's reward a second time (the claim
// set in partnerStore.ts remembers the *old* guest id) also wipes the points
// they were collecting. The reset is the reason re-claiming buys nothing.

const REDIS_URL = process.env.REDIS_URL;

const GUEST_POINTS_DATA_DIR = path.join(process.cwd(), "server", "data");
const GUEST_POINTS_FILE_PATH = path.join(GUEST_POINTS_DATA_DIR, "guest-points.json");

try {
  fs.mkdirSync(GUEST_POINTS_DATA_DIR, { recursive: true });
} catch {
  // Best-effort, same as partnerStore.ts's own data dir.
}

// Purely garbage collection, and deliberately *not* the mechanism behind the
// reset above — that is the key name. A guest id is unguessable and only
// ever reachable through the token that names it, so an entry whose token is
// gone is unreadable the moment it's gone, TTL or no TTL; this just stops
// those orphans from accumulating forever. Matches auth.ts's JWT_TTL, and
// slides on every write, so an entry can outlive its token by up to that
// long in storage and never by a single readable moment.
const GUEST_POINTS_TTL_SECONDS = 30 * 24 * 60 * 60;

// The Redis connection is shared by every store in this process — see
// redisClient.ts, which also wires REDIS_CA_CERT for a `rediss://` endpoint
// whose certificate comes from a private CA.

function guestPointsKey(guestId: string): string {
  return `sharescreen:guestPoints:${guestId}`;
}

type DiskEntry = { points: number; updatedAt: number };

// Mirror of the file for the no-Redis fallback, same shape and reasoning as
// partnerStore.ts's diskStats. Null until the first load.
let diskPoints: Record<string, DiskEntry> | null = null;

function loadFromDisk(): Record<string, DiskEntry> {
  if (diskPoints) return diskPoints;
  const out: Record<string, DiskEntry> = {};
  const cutoff = Date.now() - GUEST_POINTS_TTL_SECONDS * 1000;
  try {
    const parsed = JSON.parse(fs.readFileSync(GUEST_POINTS_FILE_PATH, "utf8")) as unknown;
    if (parsed && typeof parsed === "object") {
      for (const [id, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (!value || typeof value !== "object") continue;
        const { points, updatedAt } = value as Record<string, unknown>;
        if (typeof points !== "number" || typeof updatedAt !== "number") continue;
        // The disk fallback's stand-in for Redis's TTL — there's no
        // expiry here, so the prune happens on the one read that loads
        // the whole file anyway (once per process).
        if (updatedAt <= cutoff) continue;
        out[id] = { points, updatedAt };
      }
    }
  } catch {
    // No file yet, or unreadable — start empty, same as partnerStore's
    // fallbacks.
  }
  diskPoints = out;
  return diskPoints;
}

function saveToDisk() {
  try {
    fs.writeFileSync(GUEST_POINTS_FILE_PATH, JSON.stringify(diskPoints ?? {}));
  } catch {
    // Best-effort, same as the other writers in this project.
  }
}

/**
 * Credits `amount` points to a guest identity and returns its new total.
 *
 * The guest counterpart of accountStore.ts's addAccountPoints, and called
 * from the same two places for the same reasons — see signaling.ts's
 * /partner/:id/claim-reward and /claim-click-reward. Like that one, it is
 * only ever reached *after* the caller's claim check said this reward hadn't
 * been collected yet, so it never needs an idempotency check of its own.
 *
 * Returns null when the credit couldn't be persisted (a Redis hiccup), which
 * the caller surfaces as a failed claim rather than silently reporting a
 * total that was never stored.
 */
export async function addGuestPoints(guestId: string, amount: number): Promise<number | null> {
  if (!guestId || !amount) return null;
  if (!REDIS_URL) {
    const store = loadFromDisk();
    const entry = store[guestId] ?? (store[guestId] = { points: 0, updatedAt: Date.now() });
    entry.points += amount;
    entry.updatedAt = Date.now();
    saveToDisk();
    return entry.points;
  }
  try {
    const client = await getRedis();
    const key = guestPointsKey(guestId);
    // INCRBY creates the key at 0 first when it doesn't exist, so a guest's
    // very first reward needs no separate "does this exist" round trip.
    const total: number = await client.incrBy(key, amount);
    await client.expire(key, GUEST_POINTS_TTL_SECONDS);
    return total;
  } catch (err) {
    console.error("[guestPointsStore] Erro ao creditar pontos no Redis:", (err as Error).message);
    return null;
  }
}

/** A guest identity's current total. Unknown (or expired) ids read 0. */
export async function getGuestPoints(guestId: string): Promise<number> {
  if (!guestId) return 0;
  if (!REDIS_URL) return loadFromDisk()[guestId]?.points ?? 0;
  try {
    const client = await getRedis();
    const raw = await client.get(guestPointsKey(guestId));
    return Number(raw) || 0;
  } catch (err) {
    console.error("[guestPointsStore] Erro ao ler pontos no Redis:", (err as Error).message);
    return 0;
  }
}
