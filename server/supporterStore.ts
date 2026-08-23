import fs from "node:fs";
import path from "node:path";
import { createClient } from "redis";

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

// See chatStore.ts's identical `RedisClient` alias for why this is `any`
// rather than a precise type.
type RedisClient = any; // eslint-disable-line @typescript-eslint/no-explicit-any

let redisReady: Promise<RedisClient> | null = null;

async function getRedis(): Promise<RedisClient> {
  if (redisReady) return redisReady;
  const client = createClient({ url: REDIS_URL });
  client.on("error", (err: Error) => {
    console.error("[supporterStore] Erro na conexão com o Redis:", err.message);
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
