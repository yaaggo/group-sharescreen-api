import { Registry, collectDefaultMetrics, Gauge, Counter, AggregatorRegistry } from "prom-client";
import { CLIENT_PLATFORMS, type ClientPlatform } from "./clientPlatform.js";
import { CLUSTER_ENABLED } from "./clusterBus.js";
import { clusterHealth } from "./clusterInfo.js";

export const register = new Registry();

// CPU, memory (RSS/heap), event loop lag, GC, open file descriptors, etc. —
// everything Node/prom-client can tell us about this process for free.
collectDefaultMetrics({ register });

// Every worker keeps its own registry; the primary merges them into a single
// scrape (see clusterPrimary.ts and the /metrics route in index.ts). Two
// things are needed for that on this side: telling prom-client to answer
// the primary with *this* registry rather than the global one it defaults
// to, and constructing an AggregatorRegistry at all, which is what installs
// the worker-side listener that answers those collection requests.
if (CLUSTER_ENABLED) {
  AggregatorRegistry.setRegistries(register);
  new AggregatorRegistry();
}

// How a metric is merged across workers when the primary aggregates them.
//
// prom-client sums by default, which is right for the counters further down
// (each worker counts the events it handled, and the cluster's total is the
// sum) but wrong for everything fed by registerStatsProvider below: those
// gauges are already cluster-wide in *every* worker, because signaling.ts
// replicates the connection and room state to all of them. Summing "people
// online" across four workers that each already know about everyone would
// report four times the site's actual population. "first" takes one
// worker's answer, which is the whole answer.
const REPLICATED_GAUGE_AGGREGATOR = "first" as const;

export type RoomStats = {
  handle: string;
  peopleCount: number;
  sharingCount: number;
  isPrivate: boolean;
};
// A breakdown of registeredPeers by what kind of identity backs them — see
// server/signaling.ts's ClientInfo (accountId/guestId/guestVerified) and its
// "register" handler for what each of these actually means:
//   - accounts: logged into a registered account (a verified account JWT).
//   - guestsWithToken: a guest whose identity was proven via a guest token
//     this connection presented (see isSameOwner) — protected against
//     someone else hijacking their session via a guessed/observed name or
//     connection id.
//   - guestsWithoutToken: a guest with no such proof yet — either an old,
//     non-updated client that doesn't know about guest tokens at all, or a
//     brand new guest that hasn't had its first token round-trip yet.
export type IdentityStats = {
  accounts: number;
  guestsWithToken: number;
  guestsWithoutToken: number;
};

// How the same registered peers counted by IdentityStats split across the
// kinds of client they're running — see clientPlatform.ts for what each
// bucket means and how a connection is sorted into one. Every bucket is
// always present, including the ones sitting at zero, so a Grafana panel
// keeps a stable set of series instead of losing one the moment nobody is
// on that platform right now.
export type PlatformStats = Record<ClientPlatform, number>;

export function emptyPlatformStats(): PlatformStats {
  return Object.fromEntries(CLIENT_PLATFORMS.map((p) => [p, 0])) as PlatformStats;
}

// A count of currently-connected sockets sharing one GeoIP location (see
// server/geoip.ts) — country plus lat/lon already rounded to ~11km. Entries
// only ever exist for locations with at least one connection *right now*;
// see connectionsByLocationGauge below for why that matters.
export type LocationStats = {
  country: string;
  lat: string;
  lon: string;
  count: number;
};

// How the cluster's connections are split across the processes actually
// terminating them (see ClientInfo.worker in server/signaling.ts). Only
// workers with at least one connection appear here; the gauges below fill in
// the idle ones from the primary's roster, so a worker sitting at zero is
// still visible rather than silently missing.
export type WorkerStats = {
  id: number;
  sockets: number;
  registeredPeers: number;
};

export type SignalingStats = {
  connectedSockets: number;
  registeredPeers: number;
  identities: IdentityStats;
  platforms: PlatformStats;
  rooms: RoomStats[];
  locations: LocationStats[];
  workers: WorkerStats[];
};

const emptyStats: SignalingStats = {
  connectedSockets: 0,
  registeredPeers: 0,
  identities: { accounts: 0, guestsWithToken: 0, guestsWithoutToken: 0 },
  platforms: emptyPlatformStats(),
  rooms: [],
  locations: [],
  workers: [],
};

// signaling.ts owns the actual connection/room state; it hands us a getter
// once at startup instead of this module importing signaling.ts directly,
// so the metrics module never needs to know about ClientInfo/RoomInfo
// internals and there's no import cycle between the two files.
let statsProvider: (() => SignalingStats) | null = null;

export function registerStatsProvider(provider: () => SignalingStats) {
  statsProvider = provider;
}

function getStats(): SignalingStats {
  return statsProvider ? statsProvider() : emptyStats;
}

const TOP_PRIVATE_ROOMS = 5;

new Gauge({
  name: "sharescreen_connected_sockets",
  help: "WebSocket connections currently open on the signaling server",
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.set(getStats().connectedSockets);
  },
});

new Gauge({
  name: "sharescreen_registered_peers",
  help: "Connected sockets that have completed name registration",
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.set(getStats().registeredPeers);
  },
});

new Gauge({
  name: "sharescreen_identities",
  help: "Registered peers broken down by identity kind: a logged-in account, a guest whose token-proven identity protects it from session takeover (see isSameOwner), or a guest with no such proof yet (old client, or not yet through its first token round-trip)",
  labelNames: ["kind"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    const { identities } = getStats();
    this.set({ kind: "account" }, identities.accounts);
    this.set({ kind: "guest_with_token" }, identities.guestsWithToken);
    this.set({ kind: "guest_without_token" }, identities.guestsWithoutToken);
  },
});

new Gauge({
  name: "sharescreen_clients_by_platform",
  help: "Registered peers by the kind of client they're using: an ordinary browser or an embedded WebView (an in-app browser such as Instagram's or Facebook's), on a phone/tablet or on a PC, plus GoLive's own desktop app. Same population as sharescreen_registered_peers, so the two always sum to the same number. \"unknown\" is a connection whose kind couldn't be established rather than a PC — see server/clientPlatform.ts.",
  labelNames: ["platform"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    const { platforms } = getStats();
    // No reset() here, unlike the room/location gauges below: the label set
    // is this fixed list and every one of them is written on every scrape,
    // so there is no such thing as a stale combination to drop.
    for (const platform of CLIENT_PLATFORMS) {
      this.set({ platform }, platforms[platform] ?? 0);
    }
  },
});

new Gauge({
  name: "sharescreen_rooms",
  help: "Active rooms (at least one person connected), by visibility",
  labelNames: ["visibility"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    const { rooms } = getStats();
    this.set({ visibility: "public" }, rooms.filter((r) => !r.isPrivate).length);
    this.set({ visibility: "private" }, rooms.filter((r) => r.isPrivate).length);
  },
});

new Gauge({
  name: "sharescreen_room_people",
  help: "People connected per public room. Private rooms are intentionally never labeled by handle here — /metrics has no access control by default, and doing so would leak private room identities to anyone who finds this endpoint, defeating the point of them being private. See sharescreen_private_room_top_people for an anonymized view.",
  labelNames: ["room"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    // A labeled Gauge remembers every label combination it has ever seen
    // and keeps reporting the last value forever, even after that room is
    // long gone — reset() first so a room that emptied out actually drops
    // out of the exposed metrics instead of showing phantom people.
    this.reset();
    for (const r of getStats().rooms) {
      if (!r.isPrivate) this.set({ room: r.handle }, r.peopleCount);
    }
  },
});

new Gauge({
  name: "sharescreen_room_sharing_screen",
  help: "People actively broadcasting their screen/camera, per public room. Private rooms excluded for the same reason as sharescreen_room_people — see sharescreen_sharing_screen_total for the aggregate across all rooms.",
  labelNames: ["room"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.reset();
    for (const r of getStats().rooms) {
      if (!r.isPrivate) this.set({ room: r.handle }, r.sharingCount);
    }
  },
});

new Gauge({
  name: "sharescreen_sharing_screen_total",
  help: "People actively broadcasting their screen/camera right now, across all rooms (public and private combined)",
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    const total = getStats().rooms.reduce((sum, r) => sum + r.sharingCount, 0);
    this.set(total);
  },
});

new Gauge({
  name: "sharescreen_private_rooms_people_total",
  help: "Total people currently in any private room combined",
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    const total = getStats()
      .rooms.filter((r) => r.isPrivate)
      .reduce((sum, r) => sum + r.peopleCount, 0);
    this.set(total);
  },
});

new Gauge({
  name: "sharescreen_private_room_top_people",
  help: `Sizes of the ${TOP_PRIVATE_ROOMS} largest private rooms, ranked but not identified — gives capacity/activity visibility without exposing which private room it is`,
  labelNames: ["rank"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    // Same reasoning as sharescreen_room_people: without this, a rank that
    // no longer has a private room behind it (fewer private rooms now than
    // before) would keep reporting its last stale size forever.
    this.reset();
    const sizes = getStats()
      .rooms.filter((r) => r.isPrivate)
      .map((r) => r.peopleCount)
      .sort((a, b) => b - a)
      .slice(0, TOP_PRIVATE_ROOMS);
    for (let i = 0; i < sizes.length; i += 1) {
      this.set({ rank: String(i + 1) }, sizes[i]);
    }
  },
});

// ─── Cluster ──────────────────────────────────────────────────────────────
//
// All of these are aggregated with "first" for the same reason the gauges
// above are: every worker already knows the whole cluster (the roster comes
// from the primary, the connection split comes from the replicated state in
// signaling.ts), so summing them across workers would report each number N
// times over.
//
// Unclustered they still work and describe the single process, which reports
// itself as worker 0 — a dashboard doesn't need to know which mode it is
// looking at.

new Gauge({
  name: "sharescreen_cluster_workers_online",
  help: "Workers currently accepting connections. Below sharescreen_cluster_workers_configured means one is still booting or is being replaced",
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.set(clusterHealth().online);
  },
});

new Gauge({
  name: "sharescreen_cluster_workers_configured",
  help: "Workers the primary was told to run (CLUSTER_WORKERS, defaulting to one per available core). 1 when clustering is off",
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.set(clusterHealth().configured);
  },
});

new Gauge({
  name: "sharescreen_cluster_worker_restarts",
  help: "Workers replaced since the primary started. Deliberately a gauge and not a _total counter: it is the primary's own tally and goes back to zero when the primary restarts, which a counter's reset semantics would misreport as the process having been redeployed. A number that keeps climbing means something is killing workers",
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.set(clusterHealth().restarts);
  },
});

new Gauge({
  name: "sharescreen_cluster_worker_up",
  help: "1 while a worker is accepting connections, 0 while it is forked but not yet listening (booting, or connecting to Mongo/Redis)",
  labelNames: ["worker", "pid"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    // Same reasoning as sharescreen_room_people: worker ids are never reused
    // and a replaced worker brings a new pid with it, so without reset() every
    // worker that ever ran would keep reporting forever.
    this.reset();
    for (const w of clusterHealth().workers) {
      this.set({ worker: String(w.id), pid: String(w.pid) }, w.listening ? 1 : 0);
    }
  },
});

new Gauge({
  name: "sharescreen_cluster_worker_uptime_seconds",
  help: "How long each worker has been up, since the primary forked it — a worker whose uptime keeps resetting is one that keeps dying",
  labelNames: ["worker"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.reset();
    for (const w of clusterHealth().workers) this.set({ worker: String(w.id) }, w.uptimeSeconds);
  },
});

new Gauge({
  name: "sharescreen_worker_connected_sockets",
  help: "Open WebSocket connections by the worker actually terminating them. Sums to sharescreen_connected_sockets; a lopsided split means connections are not being spread evenly (see CLUSTER_SCHEDULING)",
  labelNames: ["worker"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.reset();
    for (const w of workerBreakdown()) this.set({ worker: String(w.id) }, w.sockets);
  },
});

new Gauge({
  name: "sharescreen_worker_registered_peers",
  help: "Connections that have completed name registration, by the worker terminating them. Sums to sharescreen_registered_peers",
  labelNames: ["worker"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.reset();
    for (const w of workerBreakdown()) this.set({ worker: String(w.id) }, w.registeredPeers);
  },
});

// The connection split, with every live worker present even when it is
// holding nothing — signaling.ts only reports workers that have connections,
// and a worker missing from a graph is indistinguishable from a worker that
// died, which is the opposite of what these are for.
function workerBreakdown(): WorkerStats[] {
  const byId = new Map<number, WorkerStats>();
  for (const w of clusterHealth().workers) {
    byId.set(w.id, { id: w.id, sockets: 0, registeredPeers: 0 });
  }
  for (const w of getStats().workers) byId.set(w.id, w);
  return [...byId.values()].sort((a, b) => a.id - b.id);
}

export const wsConnectionsTotal = new Counter({
  name: "sharescreen_ws_connections_total",
  help: "WebSocket connections accepted since process start",
  registers: [register],
});

export const wsDisconnectionsTotal = new Counter({
  name: "sharescreen_ws_disconnections_total",
  help: "WebSocket connections closed since process start",
  registers: [register],
});

export const heartbeatReapedTotal = new Counter({
  name: "sharescreen_heartbeat_reaped_total",
  help: "Connections forcibly terminated for failing to respond to a heartbeat ping (network dropped without a clean close)",
  registers: [register],
});

export const registerErrorsTotal = new Counter({
  name: "sharescreen_register_errors_total",
  help: "Name registration attempts rejected (invalid name or already in use)",
  registers: [register],
});

export const roomsCreatedTotal = new Counter({
  name: "sharescreen_rooms_created_total",
  help: "Rooms created (first person to join) since process start",
  registers: [register],
  labelNames: ["visibility"],
});

export const signalsRelayedTotal = new Counter({
  name: "sharescreen_signals_relayed_total",
  help: "WebRTC signaling messages (offer/answer/ice/stop) relayed between peers",
  labelNames: ["kind"],
  registers: [register],
});

export const bannedIpConnectionsRejectedTotal = new Counter({
  name: "sharescreen_banned_ip_connections_rejected_total",
  help: "WebSocket connection attempts rejected because the source IP is banned",
  registers: [register],
});

export const chatMessagesBlockedTotal = new Counter({
  name: "sharescreen_chat_messages_blocked_total",
  help: "Chat messages blocked by the banned-words filter",
  registers: [register],
});

export const httpRateLimitedTotal = new Counter({
  name: "sharescreen_http_rate_limited_total",
  help: "HTTP requests rejected by @fastify/rate-limit (429), by route",
  labelNames: ["route"],
  registers: [register],
});

export const wsRateLimitedTotal = new Counter({
  name: "sharescreen_ws_rate_limited_total",
  help: "WebSocket messages dropped for exceeding a per-connection rate limit (see rateLimiter.ts), by message category",
  labelNames: ["kind"],
  registers: [register],
});

export const autoBansTotal = new Counter({
  name: "sharescreen_auto_bans_total",
  help: "IP bans issued automatically after repeated rate-limit violations (as opposed to an admin banning by hand)",
  registers: [register],
});

export const turnstileVerificationsTotal = new Counter({
  name: "sharescreen_turnstile_verifications_total",
  help: "Cloudflare Turnstile token verifications performed on room join, by result",
  labelNames: ["result"],
  registers: [register],
});

// Current WebSocket connections by approximate client location (GeoIP —
// see geoip.ts's lookupConnectionLocation) — built for a Grafana Geomap
// panel in "Coords" mode using the lat/lon labels directly. country is an
// ISO 3166-1 alpha-2 code, also usable on its own via `sum by (country)`
// for a country-level breakdown. A connection whose IP couldn't be placed
// (private/local address, unroutable range, or just missing from the
// offline database) is never counted here at all — see signaling.ts's "/ws"
// handler — rather than showing up as a pile of connections at 0,0.
//
// Recomputed from scratch on every scrape (via getStats().locations) rather
// than incremented/decremented as connections open/close: same reasoning as
// sharescreen_room_people above — a plain inc()/dec()'d labeled Gauge
// remembers every distinct label combination it has *ever* seen and keeps
// reporting it (stuck at 0) forever once no one's left there, and unlike a
// room count, distinct (country, lat, lon) triples only ever accumulate
// over a long-running process's whole lifetime as visitors come from more
// and more places — reset() first is what keeps this bounded by "how many
// locations have someone connected *right now*" instead of "how many ever."
export const connectionsByLocationGauge = new Gauge({
  name: "sharescreen_connections_by_location",
  help: "Current WebSocket connections by approximate GeoIP location (country, and lat/lon rounded to ~11km)",
  labelNames: ["country", "lat", "lon"],
  registers: [register],
  aggregator: REPLICATED_GAUGE_AGGREGATOR,
  collect() {
    this.reset();
    for (const loc of getStats().locations) {
      this.set({ country: loc.country, lat: loc.lat, lon: loc.lon }, loc.count);
    }
  },
});
