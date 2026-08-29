// Cluster bootstrap: the primary process forks one worker per CPU and then
// does nothing but supervise and relay.
//
// The point of this file is that it is the *only* thing the primary runs.
// It never imports signaling.ts, Fastify, mongoose or geoip — those all live
// in the workers, so the primary stays a small, idle process whose event
// loop is free to move IPC traffic around instead of competing with the
// server for the same core.
//
// Every worker runs the exact same server/index.ts that a single-process
// deployment runs; node:cluster hands them all the same listening socket, so
// nothing about the port, the reverse proxy, or the client changes. What
// keeps them from behaving like N independent servers is the replication in
// signaling.ts, which travels over the relay below.
import cluster from "node:cluster";
import { availableParallelism } from "node:os";
import { randomUUID } from "node:crypto";
import { AggregatorRegistry } from "prom-client";
import { isBusEnvelope, type BusEnvelope } from "./clusterBus.js";

// How many workers to fork. Defaults to one per available core; set
// CLUSTER_WORKERS=1 to turn clustering off entirely (the primary then runs
// the server inline, exactly as it did before this existed).
// availableParallelism respects cgroup CPU limits, which os.cpus() doesn't —
// inside a container capped at 2 cores, os.cpus() would report the host's 32
// and fork 32 workers that all fight over the same two.
export function availableCores(): number {
  try {
    return Math.max(1, availableParallelism());
  } catch {
    return 1;
  }
}

export function resolveWorkerCount(): number {
  const raw = process.env.CLUSTER_WORKERS;
  if (raw !== undefined && raw !== "") {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= 1) return Math.floor(parsed);
  }
  return availableCores();
}

// Aggregates every worker's Prometheus registry into one scrape (see the
// /metrics route in signaling.ts, which asks for this over the bus). Lives
// in the primary because that's the only process that can talk to all the
// others — prom-client's own cluster support is built around exactly that.
const aggregatorRegistry = new AggregatorRegistry();

// The primary is the only process that knows who is alive — it is the one
// that forks and buries them — so it keeps the roster and pushes it to every
// worker whenever it changes. Workers cache it (see clusterInfo.ts) and
// answer GET /health and the cluster gauges from that cache, rather than
// asking across the IPC channel on every request.
interface RosterEntry {
  id: number;
  pid: number;
  startedAt: number;
  listening: boolean;
}

const roster = new Map<number, RosterEntry>();
const primaryStartedAt = Date.now();
let configuredWorkers = 1;
let workerRestarts = 0;

function rosterPayload() {
  return {
    // Sorted by id so a scrape or a health check reads the same order every
    // time instead of whatever order the map happens to be in.
    workers: [...roster.values()].sort((a, b) => a.id - b.id),
    restarts: workerRestarts,
    configured: configuredWorkers,
    primaryPid: process.pid,
    startedAt: primaryStartedAt,
  };
}

function broadcastRoster(): void {
  const payload = rosterPayload();
  for (const id in cluster.workers) {
    const worker = cluster.workers[id];
    if (!worker || !worker.isConnected()) continue;
    worker.send({
      __ssbus: 1,
      kind: "event",
      topic: "cluster:roster",
      from: 0,
      to: worker.id,
      payload,
    } satisfies BusEnvelope);
  }
}

function liveWorkerIds(): number[] {
  const ids: number[] = [];
  for (const id in cluster.workers) {
    const worker = cluster.workers[id];
    if (worker && worker.isConnected()) ids.push(worker.id);
  }
  return ids;
}

function sendToWorker(workerId: number, envelope: BusEnvelope): void {
  const worker = cluster.workers?.[String(workerId)];
  if (worker && worker.isConnected()) worker.send(envelope);
}

function broadcast(envelope: BusEnvelope, exceptWorkerId: number): void {
  for (const id in cluster.workers) {
    const worker = cluster.workers[id];
    if (!worker || !worker.isConnected() || worker.id === exceptWorkerId) continue;
    worker.send(envelope);
  }
}

async function handleRequest(envelope: BusEnvelope, fromWorkerId: number): Promise<void> {
  const reply = (payload: unknown, error?: string): void =>
    sendToWorker(fromWorkerId, {
      __ssbus: 1,
      kind: "res",
      topic: envelope.topic,
      from: 0,
      to: fromWorkerId,
      id: envelope.id,
      payload,
      error,
    });
  try {
    if (envelope.topic === "metrics:collect") {
      reply(await aggregatorRegistry.clusterMetrics());
      return;
    }
    if (envelope.topic === "cluster:roster") {
      reply(rosterPayload());
      return;
    }
    reply(undefined, `Tópico desconhecido: ${envelope.topic}`);
  } catch (err) {
    reply(undefined, err instanceof Error ? err.message : String(err));
  }
}

export function startClusterPrimary(workerCount: number): void {
  // One id for the whole cluster rather than one per worker: GET /health
  // returns it, and a value that changed depending on which worker answered
  // would make the endpoint useless for telling "the server restarted" apart
  // from "a different process answered". Same reasoning for the start time,
  // which signaling.ts's Turnstile startup grace window is measured against
  // — a grace period that restarted per worker would be N overlapping
  // windows instead of one.
  const currentId = randomUUID();
  const startedAt = String(Date.now());

  // Node defaults to round-robin everywhere except Windows, where it hands
  // the accept() decision to the OS instead (SCHED_NONE) — which in practice
  // can pile most connections onto one worker. Production here is Linux, so
  // the default is already round-robin; CLUSTER_SCHEDULING is an escape
  // hatch for forcing either policy (notably "rr" when developing on
  // Windows, where the default would otherwise leave the other workers
  // idle).
  const scheduling = (process.env.CLUSTER_SCHEDULING || "").toLowerCase();
  if (scheduling === "rr") cluster.schedulingPolicy = cluster.SCHED_RR;
  else if (scheduling === "none") cluster.schedulingPolicy = cluster.SCHED_NONE;

  cluster.setupPrimary({
    // Workers inherit the primary's own argv/execArgv (which is what carries
    // the tsx loader through, see package.json's `start` script), so there is
    // nothing to configure here beyond the shared environment below.
    silent: false,
  });

  configuredWorkers = workerCount;

  const forkWorker = (): void => {
    const worker = cluster.fork({
      SS_CLUSTER: "1",
      SS_CLUSTER_SIZE: String(workerCount),
      SS_CURRENT_ID: currentId,
      SS_START_TIME: startedAt,
    });
    roster.set(worker.id, {
      id: worker.id,
      pid: worker.process.pid ?? 0,
      startedAt: Date.now(),
      // Flipped by the "listening" event below. A worker sits here for the
      // second or two it takes to load and connect to Mongo/Redis, and that
      // gap is exactly what makes this flag worth reporting.
      listening: false,
    });
  };

  for (let i = 0; i < workerCount; i += 1) forkWorker();

  cluster.on("listening", (worker) => {
    const entry = roster.get(worker.id);
    if (entry) entry.listening = true;
    broadcastRoster();
  });

  // Fires when a worker's IPC channel goes away — on the way to "exit", but
  // also on a clean shutdown. Reporting it separately from being gone is what
  // makes "up but no longer serving" visible instead of looking healthy right
  // up until it vanishes.
  cluster.on("disconnect", (worker) => {
    const entry = roster.get(worker.id);
    if (entry) entry.listening = false;
    broadcastRoster();
  });

  cluster.on("message", (worker, message) => {
    if (!isBusEnvelope(message)) return;
    const envelope = message as BusEnvelope;
    if (envelope.kind === "req") {
      void handleRequest(envelope, worker.id);
      return;
    }
    // Plain relay: the primary never inspects an event's payload, it only
    // moves it to whoever it was addressed to.
    if (envelope.to === "*") broadcast(envelope, worker.id);
    else if (typeof envelope.to === "number") sendToWorker(envelope.to, envelope);
  });

  let shuttingDown = false;

  cluster.on("exit", (worker, code, signal) => {
    roster.delete(worker.id);
    if (shuttingDown) return;
    workerRestarts += 1;
    console.error(
      `[cluster] Worker ${worker.id} (pid ${worker.process.pid}) saiu (código ${code}, sinal ${signal}) — reiniciando.`
    );
    // Every surviving worker still holds a full replica of the dead one's
    // connections (see signaling.ts) — they have to be told to drop them,
    // and exactly one of them has to be the one that broadcasts the
    // resulting "peer-left"s. Naming that worker here, rather than letting
    // each decide for itself, is what keeps it to exactly one.
    const survivors = liveWorkerIds();
    const cleanupBy = survivors.length > 0 ? Math.min(...survivors) : 0;
    for (const id of survivors) {
      sendToWorker(id, {
        __ssbus: 1,
        kind: "event",
        topic: "worker:gone",
        from: 0,
        to: id,
        payload: { workerId: worker.id, cleanupBy },
      });
    }
    forkWorker();
    broadcastRoster();
  });

  // A container stop sends SIGTERM to the primary only — without forwarding
  // it, the workers would keep serving until the runtime SIGKILLs them.
  const shutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    for (const id in cluster.workers) {
      try {
        cluster.workers[id]?.process.kill(signal);
      } catch {
        // Already gone — nothing to do.
      }
    }
    // Long enough for an in-flight response to finish, short enough that a
    // deploy isn't held up by a worker that's wedged.
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  console.log(`[cluster] Primário ${process.pid} iniciou ${workerCount} workers.`);
}
