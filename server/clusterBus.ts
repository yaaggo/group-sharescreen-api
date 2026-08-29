// Message bus between the cluster's workers (see clusterPrimary.ts).
//
// node:cluster only gives a worker a channel to the *primary* — two workers
// can never talk to each other directly — so every cross-worker message here
// travels worker -> primary -> worker, with the primary doing nothing but
// relaying (see relayFromWorker). That's the whole reason this file exists
// as its own module rather than being folded into signaling.ts: the primary
// needs the envelope format too, and it must be able to load it without
// pulling in the entire signaling/Fastify/mongoose graph.
//
// When the process wasn't forked by clusterPrimary.ts (a single-worker
// deployment, `CLUSTER_WORKERS=1`, or anything running server/index.ts
// directly) every function below is a no-op: publish sends nothing,
// subscribers never fire, and the server behaves exactly as it did before
// clustering existed. That "off" path is deliberately the default so a
// deployment that doesn't want more than one process pays nothing for this.
import cluster from "node:cluster";

// Set by clusterPrimary.ts on the workers it forks — and only when it
// actually forked more than one, so a one-worker run stays on the no-op
// path above.
export const CLUSTER_ENABLED = Boolean(cluster.isWorker && process.env.SS_CLUSTER === "1");

// 1-based within the cluster (node:cluster's own worker ids, which are
// never reused — a respawned worker gets a fresh one, which is what lets
// stale state from a dead worker be identified and dropped, see
// "worker:gone" in signaling.ts). 0 means "not clustered", i.e. this single
// process is the whole server.
export const WORKER_ID = CLUSTER_ENABLED && cluster.worker ? cluster.worker.id : 0;

// How many workers the primary started with — used only for sizing/logging
// decisions, never for routing (that always goes through the primary, which
// knows who is actually alive).
export const CLUSTER_SIZE = CLUSTER_ENABLED ? Number(process.env.SS_CLUSTER_SIZE || 1) : 1;

// Tag on every message this module puts on the IPC channel. Everything that
// doesn't carry it is left alone — node:cluster's channel is shared with
// whatever else uses process.send (prom-client's cluster metrics collection
// is the one in play here, see metrics.ts), so both have to be able to
// ignore each other's traffic.
export const BUS_TAG = "__ssbus";

export interface BusEnvelope {
  __ssbus: 1;
  kind: "event" | "req" | "res";
  topic: string;
  // Worker id of the sender; 0 when the primary itself is the sender.
  from: number;
  // "*" = every worker except `from`. A number targets one specific worker.
  // "primary" = handled by the primary itself rather than relayed.
  to: number | "*" | "primary";
  // Correlates a "res" with the "req" that asked for it.
  id?: number;
  payload?: unknown;
  error?: string;
}

export function isBusEnvelope(msg: unknown): msg is BusEnvelope {
  return Boolean(msg && typeof msg === "object" && (msg as { __ssbus?: unknown }).__ssbus === 1);
}

const handlers = new Map<string, BusHandler[]>();

export type BusHandler = (payload: any, from: number) => void; // eslint-disable-line @typescript-eslint/no-explicit-any

interface PendingRequest {
  resolve: (value: any) => void; // eslint-disable-line @typescript-eslint/no-explicit-any
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}
const pendingRequests = new Map<number, PendingRequest>();
let nextRequestId = 1;

// Subscribes to a topic. Handlers are never removed — every subscriber here
// is registered once at module load and lives as long as the process.
export function onBus(topic: string, handler: BusHandler): void {
  const list = handlers.get(topic);
  if (list) list.push(handler);
  else handlers.set(topic, [handler]);
}

function dispatch(topic: string, payload: unknown, from: number): void {
  const list = handlers.get(topic);
  if (!list) return;
  for (const handler of list) {
    try {
      handler(payload, from);
    } catch (err) {
      console.error(`[cluster-bus] Falha ao processar "${topic}":`, err);
    }
  }
}

function post(envelope: BusEnvelope): void {
  // process.send only exists on a forked child; the `connected` check is
  // what keeps a worker that's already shutting down from throwing on a
  // closed channel instead of just dropping the message.
  if (!process.send || !process.connected) return;
  try {
    process.send(envelope);
  } catch {
    // A closed/full IPC channel is not worth taking a request down over —
    // the state this carries is re-published on the next change anyway.
  }
}

// Fire-and-forget to every *other* worker. Never delivered back to the
// sender, which is what lets a handler apply an event unconditionally
// without having to check whether it was the one that caused it.
export function busPublish(topic: string, payload?: unknown): void {
  if (!CLUSTER_ENABLED) return;
  post({ __ssbus: 1, kind: "event", topic, from: WORKER_ID, to: "*", payload });
}

// Fire-and-forget to one specific worker — used for anything that has to run
// where a particular socket actually lives (see RemoteSocket in
// signaling.ts).
export function busSendTo(workerId: number, topic: string, payload?: unknown): void {
  if (!CLUSTER_ENABLED || workerId === WORKER_ID) return;
  post({ __ssbus: 1, kind: "event", topic, from: WORKER_ID, to: workerId, payload });
}

// Ask the primary something and wait for its answer (currently just the
// aggregated Prometheus scrape — see clusterPrimary.ts). Rejects on timeout
// rather than hanging, so a caller can fall back to a local answer.
export function busRequest<T>(topic: string, payload?: unknown, timeoutMs = 5_000): Promise<T> {
  if (!CLUSTER_ENABLED) return Promise.reject(new Error("cluster desativado"));
  const id = nextRequestId++;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingRequests.delete(id);
      reject(new Error(`Tempo esgotado aguardando "${topic}" do processo primário.`));
    }, timeoutMs);
    // Node keeps the event loop alive for a pending timer; this one is
    // purely a safety net, so it shouldn't hold a shutdown open.
    timer.unref?.();
    pendingRequests.set(id, { resolve, reject, timer });
    post({ __ssbus: 1, kind: "req", topic, from: WORKER_ID, to: "primary", id, payload });
  });
}

if (CLUSTER_ENABLED) {
  process.on("message", (msg: unknown) => {
    if (!isBusEnvelope(msg)) return;
    if (msg.kind === "res") {
      const pending = msg.id !== undefined ? pendingRequests.get(msg.id) : undefined;
      if (!pending) return;
      pendingRequests.delete(msg.id!);
      clearTimeout(pending.timer);
      if (msg.error) pending.reject(new Error(msg.error));
      else pending.resolve(msg.payload);
      return;
    }
    dispatch(msg.topic, msg.payload, msg.from);
  });
}
