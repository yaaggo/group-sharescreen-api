// Cluster-shared counter store for @fastify/rate-limit.
//
// The plugin's built-in store keeps its counters in the process that saw the
// request. With one process that's the whole picture; with N workers it
// silently multiplies every limit by N, because the same visitor's requests
// land on a different worker each time and each worker only ever sees its
// own share. A route capped at "30 per minute" would really be 30 per worker
// per minute — which is exactly the kind of behaviour change clustering is
// not allowed to introduce here.
//
// This store keeps the same fixed-window counters the built-in one does (the
// arithmetic below is deliberately a mirror of @fastify/rate-limit's
// LocalStore, including its continueExceeding/exponentialBackoff branches, so
// the numbers in the headers don't shift), but every increment is also
// published to the other workers, which apply it to their own copy without
// answering anything. Each worker therefore counts every request the cluster
// saw, and the decision itself still happens locally with no round trip — a
// shared *counter*, not a shared *lock*. The cost is that two requests
// landing on two workers in the same instant can both be allowed by a limit
// with exactly one slot left; that window is sub-millisecond and the next
// request is already counted correctly.
//
// Unclustered, busPublish is a no-op and this behaves exactly like the
// built-in store.
import { CLUSTER_ENABLED, busPublish, onBus } from "./clusterBus.js";

interface Entry {
  current: number;
  ttl: number;
  iterationStartMs: number;
}

// scope ("METHOD|/route", or "" for the plugin's root store) -> key (the
// caller's IP, by default) -> window state. Scoped by route because that's
// what the plugin's own per-route `child()` stores do — two routes with
// different budgets must never share a counter.
const scopes = new Map<string, Map<string, Entry>>();

function bucket(scope: string): Map<string, Entry> {
  let map = scopes.get(scope);
  if (!map) {
    map = new Map();
    scopes.set(scope, map);
  }
  return map;
}

// Entries are only ever added on a request, and a window that elapsed can
// never come back — without this sweep every IP ever seen would stay in
// memory for the life of the process. Piggybacks on one timer for every
// scope rather than a timer per entry.
const SWEEP_INTERVAL_MS = 60_000;
setInterval(() => {
  const now = Date.now();
  for (const [scope, map] of scopes) {
    for (const [key, entry] of map) {
      if (entry.iterationStartMs + entry.ttl <= now) map.delete(key);
    }
    if (map.size === 0) scopes.delete(scope);
  }
}, SWEEP_INTERVAL_MS).unref();

interface IncrPayload {
  scope: string;
  key: string;
  timeWindow: number;
  max: number;
  at: number;
  continueExceeding: boolean;
  exponentialBackoff: boolean;
}

// The window arithmetic itself, shared by the local path and the replicated
// one. `nowInMs` is the *originating* worker's clock so that every worker
// starts and ends the same visitor's window at the same instant, rather than
// each one opening its own a few milliseconds apart.
function applyIncrement(payload: IncrPayload): Entry {
  const { scope, key, timeWindow, max, at, continueExceeding, exponentialBackoff } = payload;
  const map = bucket(scope);
  let entry = map.get(key);
  if (!entry) {
    entry = { current: 1, ttl: timeWindow, iterationStartMs: at };
  } else if (entry.iterationStartMs + timeWindow <= at) {
    entry.current = 1;
    entry.ttl = timeWindow;
    entry.iterationStartMs = at;
  } else {
    entry.current += 1;
    if (continueExceeding && entry.current > max) {
      entry.ttl = timeWindow;
      entry.iterationStartMs = at;
    } else if (exponentialBackoff && entry.current > max) {
      const backoffExponent = entry.current - max - 1;
      const ttl = timeWindow * 2 ** backoffExponent;
      entry.ttl = Number.isSafeInteger(ttl) ? ttl : Number.MAX_SAFE_INTEGER;
      entry.iterationStartMs = at;
    } else {
      entry.ttl = timeWindow - (at - entry.iterationStartMs);
    }
  }
  map.set(key, entry);
  return entry;
}

if (CLUSTER_ENABLED) {
  onBus("http-rate-limit:incr", (payload: IncrPayload) => {
    applyIncrement(payload);
  });
}

interface RouteInfoLike {
  method?: string | string[];
  path?: string;
  url?: string;
  prefix?: string;
}

interface StoreOptionsLike {
  continueExceeding?: boolean;
  exponentialBackoff?: boolean;
  // @fastify/rate-limit calls child() with the *merged rate-limit params* for
  // the route, not with the route itself — the route is tucked under
  // `routeInfo` (see the plugin's onRoute hook). Reading the method and path
  // from the wrong level would leave every route sharing one scope, i.e. one
  // budget for the whole API.
  routeInfo?: RouteInfoLike;
}

// Every worker registers the same routes from the same source in the same
// order, so building the scope out of the route itself (rather than, say, a
// counter) gives the same string in every process — which is what lets a
// published increment find the right bucket on the other side.
function scopeFor(options: StoreOptionsLike): string {
  const route = options.routeInfo ?? {};
  const method = Array.isArray(route.method) ? route.method.join(",") : route.method ?? "";
  const path = route.path ?? route.url ?? "";
  return `${method}|${route.prefix ?? ""}${path}`;
}

type IncrCallback = (
  error: Error | null,
  result?: { current: number; ttl: number }
) => void;

export class ClusterRateLimitStore {
  private readonly scope: string;
  private readonly continueExceeding: boolean;
  private readonly exponentialBackoff: boolean;

  constructor(options?: StoreOptionsLike, scope = "") {
    this.scope = scope;
    this.continueExceeding = Boolean(options?.continueExceeding);
    this.exponentialBackoff = Boolean(options?.exponentialBackoff);
  }

  incr(key: string, callback: IncrCallback, timeWindow: number, max: number): void {
    const payload: IncrPayload = {
      scope: this.scope,
      key,
      timeWindow,
      max,
      at: Date.now(),
      continueExceeding: this.continueExceeding,
      exponentialBackoff: this.exponentialBackoff,
    };
    const entry = applyIncrement(payload);
    busPublish("http-rate-limit:incr", payload);
    callback(null, { current: entry.current, ttl: entry.ttl });
  }

  // Non-mutating peek, same contract as the built-in store's — used by the
  // plugin's `rateLimit()` inspection path, which must never advance a
  // window just by looking at it.
  read(key: string, callback: IncrCallback, timeWindow: number): void {
    const now = Date.now();
    const entry = scopes.get(this.scope)?.get(key);
    if (!entry || entry.iterationStartMs + timeWindow <= now) {
      callback(null, { current: 0, ttl: 0 });
      return;
    }
    callback(null, { current: entry.current, ttl: timeWindow - (now - entry.iterationStartMs) });
  }

  child(options: StoreOptionsLike): ClusterRateLimitStore {
    return new ClusterRateLimitStore(options, scopeFor(options));
  }
}
