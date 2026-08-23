import fs from "node:fs";
import path from "node:path";
import { createClient } from "redis";

// Everything persisted about a room besides its chat history (that's
// chatStore.ts). `ownerId` is the only field anything currently *acts* on
// (see signaling.ts's "join" handler and leaveRoom's ownership handoff) —
// private/flags/code are stored and carried forward across restarts
// starting now, but nothing reads them to actually change behavior yet.
// They exist so that whenever that changes, every room created from here
// on already has real values sitting in Redis instead of needing a
// backfill migration.
export interface RoomRecord {
  ownerId: string;
  // Derived from the `priv-` handle prefix at creation time (see
  // isPrivateRoom in signaling.ts) — descriptive only for now; the actual
  // access-control behavior that prefix already has (hidden from the
  // public /rooms listing) lives entirely in signaling.ts and doesn't
  // consult this field.
  private: boolean;
  // Open-ended, room-scoped tags for whatever future per-room toggle needs
  // one (e.g. recording, moderation mode) — always empty for now, nothing
  // sets or reads it yet.
  flags: string[];
  // 6-digit access code, generated whenever `private` is true — stored so
  // it's ready the moment something actually gates entry on it, but no
  // "join" path checks it yet.
  code: string | null;
}

// Redis is opt-in: only used when REDIS_URL is set. With no Redis around,
// this falls back to one JSON file per room under server/data/rooms — same
// shape as chatStore.ts, but a different filename suffix so the two never
// collide on disk.
const REDIS_URL = process.env.REDIS_URL;

const ROOM_DATA_DIR = path.join(process.cwd(), "server", "data", "rooms");
try {
  fs.mkdirSync(ROOM_DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

// `room` is always pre-validated against HANDLE_RE by every caller before it
// reaches these, so it's safe to use directly as a filename.
function roomFilePath(room: string): string {
  return path.join(ROOM_DATA_DIR, `${room}.room.json`);
}

function loadFromDisk(room: string): RoomRecord | null {
  try {
    const raw = fs.readFileSync(roomFilePath(room), "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as RoomRecord) : null;
  } catch {
    return null;
  }
}

function saveToDisk(room: string, record: RoomRecord) {
  try {
    fs.writeFileSync(roomFilePath(room), JSON.stringify(record));
  } catch {
    // Best-effort — the room still works in-memory for the life of the
    // process even if the disk write fails.
  }
}

function deleteFromDisk(room: string) {
  try {
    fs.unlinkSync(roomFilePath(room));
  } catch {
    // Already gone (or nothing we can do about it) — fine either way.
  }
}

// See chatStore.ts's identical `RedisClient` alias for why this is `any`
// rather than a precise type.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

let redisReady: Promise<RedisClient> | null = null;

// Lazily connects on first use and memoizes the in-flight/connected client.
// A failed connect resets the memo so the next call retries instead of
// replaying the same rejection forever.
async function getRedis(): Promise<RedisClient> {
  if (redisReady) return redisReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[roomStore] Erro na conexão com o Redis:", err.message);
  });
  const connecting = client.connect().then(() => client);
  redisReady = connecting;
  try {
    return await connecting;
  } catch (err) {
    redisReady = null;
    throw err;
  }
}

function redisKey(room: string): string {
  return `sharescreen:room:${room}`;
}

// One GET, whole record as one JSON blob — same shape as
// announcementStore.ts's single-object GET/SET (a hash would need a second
// round trip's worth of (de)serialization work for what's always read and
// written together anyway). Called only when a room isn't already live in
// memory — see signaling.ts's "join" handler — never on every join, so a
// busy room's actual traffic (thousands of joins across many already-active
// rooms) never touches Redis for this at all.
export async function loadRoomRecord(room: string): Promise<RoomRecord | null> {
  if (!REDIS_URL) return loadFromDisk(room);
  try {
    const client = await getRedis();
    const raw: string | null = await client.get(redisKey(room));
    return raw ? (JSON.parse(raw) as RoomRecord) : null;
  } catch (err) {
    console.error("[roomStore] Erro ao carregar sala no Redis:", (err as Error).message);
    return null;
  }
}

// One SET, whole record overwritten at once. Called once when a room is
// created, and again only on the (comparatively rare) event of the current
// owner actually leaving — never per-join, per-message, or on any other hot
// path.
export async function saveRoomRecord(room: string, record: RoomRecord): Promise<void> {
  if (!REDIS_URL) return saveToDisk(room, record);
  try {
    const client = await getRedis();
    await client.set(redisKey(room), JSON.stringify(record));
  } catch (err) {
    console.error("[roomStore] Erro ao salvar sala no Redis:", (err as Error).message);
  }
}

export async function deleteRoomRecord(room: string): Promise<void> {
  if (!REDIS_URL) return deleteFromDisk(room);
  try {
    const client = await getRedis();
    await client.del(redisKey(room));
  } catch (err) {
    console.error("[roomStore] Erro ao apagar sala no Redis:", (err as Error).message);
  }
}
