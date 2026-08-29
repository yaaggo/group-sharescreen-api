import fs from "node:fs";
import path from "node:path";
import { getRedis } from "./redisClient.js";

export interface Supporter {
  name: string;
  amount: number;
}

// Same opt-in shape as announcementStore.ts: a single JSON blob, Redis when
// REDIS_URL is set, one file on disk otherwise. Whole list replaced at once
// on every save — same "one admin textarea, no incremental add/remove"
// reasoning as moderationStore.ts's banned words.
const REDIS_URL = process.env.REDIS_URL;

const DATA_DIR = path.join(process.cwd(), "server", "data");
const DATA_FILE = path.join(DATA_DIR, "supporters.json");
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch {
  // Persistence degrades gracefully (in-memory only, for the process's
  // lifetime) if the filesystem isn't writable — e.g. a read-only container.
}

function loadFromDisk(): Supporter[] {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as Supporter[]) : [];
  } catch {
    return [];
  }
}

function saveToDisk(supporters: Supporter[]) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(supporters));
  } catch {
    // Best-effort — the list still works in-memory for the life of the
    // process even if the disk write fails.
  }
}

// The Redis connection is shared by every store in this process — see
// redisClient.ts, which also wires REDIS_CA_CERT for a `rediss://` endpoint
// whose certificate comes from a private CA.

const REDIS_KEY = "sharescreen:supporters";

export async function loadPersistedSupporters(): Promise<Supporter[]> {
  if (!REDIS_URL) return loadFromDisk();
  try {
    const client = await getRedis();
    const raw: string | null = await client.get(REDIS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? (parsed as Supporter[]) : [];
  } catch (err) {
    console.error("[supporterStore] Erro ao carregar apoiadores do Redis:", (err as Error).message);
    return [];
  }
}

export async function savePersistedSupporters(supporters: Supporter[]): Promise<void> {
  if (!REDIS_URL) return saveToDisk(supporters);
  try {
    const client = await getRedis();
    await client.set(REDIS_KEY, JSON.stringify(supporters));
  } catch (err) {
    console.error("[supporterStore] Erro ao salvar apoiadores no Redis:", (err as Error).message);
  }
}
