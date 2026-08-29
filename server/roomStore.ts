import fs from "node:fs";
import path from "node:path";
import { getRedis } from "./redisClient.js";

// Everything persisted about a room besides its chat history (that's
// chatStore.ts). `ownerId`, `admins` and `permissions` are the fields
// anything currently *acts* on (see signaling.ts's "join" handler,
// leaveRoom's ownership handoff, and canUseRoomPermission) — private/flags/
// code are stored and carried forward across restarts, but nothing reads
// them to actually change behavior yet. They exist so that whenever that
// changes, every room created from here on already has real values sitting
// in Redis instead of needing a backfill migration.
// Someone the room's owner promoted to help run it (see signaling.ts's
// "room-admin-add"). An admin can do everything the owner can except hand
// out or take away admin — that stays the owner's alone. `name` is a copy of
// their display name at promotion time, kept purely so the "Gerenciar
// administradores" list can still name an admin who isn't currently in the
// room; whenever they *are* in it, the live peer list's name wins.
export interface RoomAdmin {
  id: string;
  name: string;
}

// Per-room switches for what an ordinary member is allowed to do. All true
// by default — a room only ever gets more restrictive by someone deliberately
// turning one off, never by upgrading past this. A false one doesn't disable
// the action outright: the owner and the room's admins are never subject to
// these (see canUseRoomPermission in signaling.ts), which is the whole point
// of turning one off — "only I get to do this", not "nobody does".
export interface RoomPermissions {
  mic: boolean;
  screen: boolean;
  camera: boolean;
  videoSource: boolean;
  chat: boolean;
  gif: boolean;
}

export const DEFAULT_ROOM_PERMISSIONS: RoomPermissions = {
  mic: true,
  screen: true,
  camera: true,
  videoSource: true,
  chat: true,
  gif: true,
};

export const ROOM_PERMISSION_KEYS = Object.keys(
  DEFAULT_ROOM_PERMISSIONS
) as (keyof RoomPermissions)[];

// Anything missing or not a boolean falls back to the permissive default —
// which covers both a record written before these existed (every room in
// Redis right now) and a client sending a partial update.
export function normalizeRoomPermissions(raw: unknown): RoomPermissions {
  const source = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const out = { ...DEFAULT_ROOM_PERMISSIONS };
  for (const key of ROOM_PERMISSION_KEYS) {
    if (typeof source[key] === "boolean") out[key] = source[key] as boolean;
  }
  return out;
}

// Same defensive read for the admin list, plus de-duplication by id: the
// promote handler already refuses to add someone twice, but a hand-edited or
// half-migrated record shouldn't be able to put the same person in the list
// (and therefore in the management UI) more than once.
export function normalizeRoomAdmins(raw: unknown): RoomAdmin[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: RoomAdmin[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const { id, name } = entry as { id?: unknown; name?: unknown };
    if (typeof id !== "string" || !id || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name: typeof name === "string" ? name : "" });
  }
  return out;
}

// Where on Earth the room's owner/admins put it, for the public room map
// (see the client's /mapa). Null for a room nobody has placed — which is
// every room until someone does, and the only state a private room is ever
// in as far as the map is concerned, since the map only ever lists public
// rooms.
export interface RoomLocation {
  lat: number;
  lng: number;
}

// Rejects anything that isn't a real point on the globe — a NaN, an Infinity,
// a latitude past the poles — rather than letting it through to a map that
// would then place a marker nowhere. Longitude is wrapped rather than
// rejected: a map panned east past the date line legitimately reports 190°,
// which is 170° W, not an error.
export function normalizeRoomLocation(raw: unknown): RoomLocation | null {
  if (!raw || typeof raw !== "object") return null;
  const { lat, lng } = raw as { lat?: unknown; lng?: unknown };
  if (typeof lat !== "number" || typeof lng !== "number") return null;
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  if (lat < -90 || lat > 90) return null;
  const wrapped = ((((lng + 180) % 360) + 360) % 360) - 180;
  return { lat, lng: wrapped };
}

// The room's own blurb and category, shown wherever a room is listed — the
// public list and the map (see the client's /rooms and /mapa). Both are set
// by the owner/admins and are purely descriptive: nothing keys behavior off
// either one.
export const MAX_ROOM_DESCRIPTION_LENGTH = 120;

// Fixed set, not free text: these are what the room list and the map filter
// and colour by, and a free-text category would be a thousand spellings of
// "gameplay". The client has its own copy with the human labels (see
// lib/roomCategories.ts) — the ids here are the contract between them.
export const ROOM_CATEGORIES = [
  "gameplay",
  "conversa",
  "musica",
  "filmes",
  "estudos",
  "trabalho",
  "esportes",
  "programacao",
  "arte",
  "outros",
] as const;

export type RoomCategory = (typeof ROOM_CATEGORIES)[number];

const ROOM_CATEGORY_SET = new Set<string>(ROOM_CATEGORIES);

// Anything not in the list — including a category this server has never heard
// of, from a newer client — reads as "no category" rather than being stored
// and then rendered as a blank chip everywhere.
export function normalizeRoomCategory(raw: unknown): RoomCategory | null {
  return typeof raw === "string" && ROOM_CATEGORY_SET.has(raw) ? (raw as RoomCategory) : null;
}

// Trimmed and hard-capped here rather than trusted from the client: the input
// enforces the same limit, but the limit is what the list layout is built
// around, so it has to hold for anything that reaches storage.
export function normalizeRoomDescription(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw.replace(/\s+/g, " ").trim().slice(0, MAX_ROOM_DESCRIPTION_LENGTH);
}

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
  // Everyone the owner promoted to co-run the room, and what an ordinary
  // member is allowed to do in it. Unlike the three fields above, these two
  // *are* acted on — see signaling.ts's canUseRoomPermission and the
  // "room-admin-add"/"room-permissions-set" handlers — so they're read back
  // through normalizeRoomAdmins/normalizeRoomPermissions on load, which is
  // what gives a room persisted before they existed sane starting values
  // without a backfill migration.
  admins: RoomAdmin[];
  permissions: RoomPermissions;
  // "" and null when nobody has set them — see the two normalizers above.
  description: string;
  category: RoomCategory | null;
  // See RoomLocation. Read by the public room map, and settable only by the
  // room's owner and admins (see signaling.ts's "room-location-set").
  location: RoomLocation | null;
}

// Fills in whatever a persisted record predates, so every caller can treat
// what comes back as a complete RoomRecord.
function normalizeRoomRecord(raw: unknown): RoomRecord | null {
  if (!raw || typeof raw !== "object") return null;
  const record = raw as Partial<RoomRecord>;
  if (typeof record.ownerId !== "string") return null;
  return {
    ownerId: record.ownerId,
    private: Boolean(record.private),
    flags: Array.isArray(record.flags) ? record.flags.filter((f) => typeof f === "string") : [],
    code: typeof record.code === "string" ? record.code : null,
    admins: normalizeRoomAdmins(record.admins),
    permissions: normalizeRoomPermissions(record.permissions),
    location: normalizeRoomLocation(record.location),
    description: normalizeRoomDescription(record.description),
    category: normalizeRoomCategory(record.category),
  };
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
    return normalizeRoomRecord(JSON.parse(raw));
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

// The Redis connection is shared by every store in this process — see
// redisClient.ts, which also wires REDIS_CA_CERT for a `rediss://` endpoint
// whose certificate comes from a private CA.

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
    return raw ? normalizeRoomRecord(JSON.parse(raw)) : null;
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
