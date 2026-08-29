// The worker's view of the cluster it belongs to.
//
// A worker only ever talks to the primary, so it has no way of knowing on its
// own how many siblings it has, which of them are up, or how long they have
// been running. The primary keeps that roster (it is the process that forks
// and buries them) and pushes it out whenever it changes — on every worker
// that starts listening, disconnects or dies. This module is just the
// receiving end plus a cache, so both GET /health and the Prometheus gauges
// can answer from memory instead of a round trip per request.
//
// Unclustered, there is no roster to receive and every reader falls back to
// describing this single process, which is the honest answer: it *is* the
// whole server.
import { CLUSTER_ENABLED, CLUSTER_SIZE, WORKER_ID, busRequest, onBus } from "./clusterBus.js";

export interface ClusterWorkerInfo {
  // node:cluster's own worker id — 1-based, never reused, so a respawned
  // worker is visibly a different one rather than the same id coming back.
  id: number;
  pid: number;
  // When the primary forked it, ms since epoch.
  startedAt: number;
  // Whether it has reached app.listen(). False for the couple of seconds
  // between being forked and being ready to serve.
  listening: boolean;
}

export interface ClusterRoster {
  workers: ClusterWorkerInfo[];
  // How many workers have been replaced since the primary came up. A number
  // that keeps climbing is the signal that something is crashing them.
  restarts: number;
  // How many the primary was told to run (CLUSTER_WORKERS), as opposed to how
  // many are actually up right now — the two differing is what a restart in
  // progress looks like.
  configured: number;
  primaryPid: number;
  startedAt: number;
}

let roster: ClusterRoster | null = null;

if (CLUSTER_ENABLED) {
  onBus("cluster:roster", (payload: ClusterRoster) => {
    roster = payload;
  });
}

// Belt and braces for the gap between this worker booting and the primary's
// next roster broadcast. The broadcast that fires when *this* worker starts
// listening closes that gap on its own within milliseconds, so this is only
// ever covering the case where that one was missed.
export async function refreshClusterRoster(): Promise<void> {
  if (!CLUSTER_ENABLED) return;
  try {
    roster = await busRequest<ClusterRoster>("cluster:roster");
  } catch {
    // Answering from what's already cached (or from this process alone) beats
    // failing a health check over a roster that will arrive on its own.
  }
}

export interface ClusterHealth {
  // false means this process is the entire server — no primary, no siblings.
  enabled: boolean;
  // Which worker answered this particular request. 0 when not clustered.
  servedBy: { id: number; pid: number };
  // Up right now, vs. how many were asked for.
  online: number;
  configured: number;
  restarts: number;
  primaryPid: number | null;
  workers: (ClusterWorkerInfo & { uptimeSeconds: number })[];
}

function uptimeSeconds(startedAt: number): number {
  return Math.max(0, Math.round((Date.now() - startedAt) / 1000));
}

// What GET /health reports, and what the cluster gauges in metrics.ts are
// built from. Never throws and never waits: a health check that can hang is
// worse than one that answers with a slightly stale roster.
export function clusterHealth(): ClusterHealth {
  if (!CLUSTER_ENABLED || !roster) {
    return {
      enabled: CLUSTER_ENABLED,
      servedBy: { id: WORKER_ID, pid: process.pid },
      online: 1,
      configured: CLUSTER_SIZE,
      restarts: 0,
      primaryPid: null,
      workers: [
        {
          id: WORKER_ID,
          pid: process.pid,
          startedAt: Date.now() - Math.round(process.uptime() * 1000),
          listening: true,
          uptimeSeconds: Math.round(process.uptime()),
        },
      ],
    };
  }
  return {
    enabled: true,
    servedBy: { id: WORKER_ID, pid: process.pid },
    online: roster.workers.filter((w) => w.listening).length,
    configured: roster.configured,
    restarts: roster.restarts,
    primaryPid: roster.primaryPid,
    workers: roster.workers.map((w) => ({ ...w, uptimeSeconds: uptimeSeconds(w.startedAt) })),
  };
}
