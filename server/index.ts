// Side-effect import (not `import dotenv from "dotenv"; dotenv.config();`)
// on purpose: ES module evaluation runs every statically imported module
// (signaling.js, accountStore.js, mongo.ts, auth.ts, and everything they in
// turn import) to completion *before* any of this file's own top-level
// statements run — regardless of where those statements sit relative to
// the import declarations in the source. A plain `dotenv.config()` call
// here would therefore only populate process.env after ADMIN_USER,
// MONGO_URL, JWT_SECRET etc. had already been read (as undefined) by those
// modules' own top-level code. Being the first *import* instead makes it
// the first module actually evaluated, ahead of everything else this file
// imports.
import "dotenv/config";

import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import websocketPlugin from "@fastify/websocket";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { registerSignalingRoutes, ADMIN_WS_PROTOCOL } from "./signaling.js";
import { register as metricsRegister, httpRateLimitedTotal } from "./metrics.js";
import { initModerationStore } from "./moderationStore.js";
import { initAccountStore } from "./accountStore.js";
import { registerOAuthRoutes } from "./oauthRoutes.js";
import { CLUSTER_ENABLED, WORKER_ID, busRequest } from "./clusterBus.js";
import { clusterHealth, refreshClusterRoster } from "./clusterInfo.js";
import { ClusterRateLimitStore } from "./httpRateLimitStore.js";

const PORT = Number(process.env.PORT || 4000);
const HOST = process.env.HOST || "0.0.0.0";
// Optional: if set, /metrics requires `Authorization: Bearer <token>`.
// Prometheus scrape configs support this natively (`bearer_token: ...`).
// Left unset by default to match this project's no-config-needed-for-dev
// pattern, but set it in production — metrics expose room activity and
// shouldn't be world-readable on an unauthenticated endpoint.
const METRICS_TOKEN = process.env.METRICS_TOKEN || null;

// Shared across the whole cluster when there is one (see clusterPrimary.ts,
// which mints it once and passes it to every worker it forks): GET /health
// hands this back, and a value that differed per worker would turn a
// perfectly healthy cluster into an endpoint that reports a "new" server on
// every other poll.
const CURRENT_ID = process.env.SS_CURRENT_ID || randomUUID();

process.on("uncaughtException", (err) => {
  console.error("[fatal] uncaughtException:", err);
  process.exit(1);
});
process.on("unhandledRejection", (reason) => {
  console.error("[fatal] unhandledRejection:", reason);
  process.exit(1);
});

async function main() {
  // trustProxy: this always runs behind a reverse proxy in production (see
  // README — apigolive.nemtudo.me), so request.ip needs to read the real
  // client address from X-Forwarded-For instead of the proxy's own address.
  // Without it every connection would appear to come from the same IP,
  // making IP bans useless.
  const app = Fastify({ logger: false, trustProxy: true });

  // Loads persisted IP bans and banned words (Mongo if MONGO_URL is set,
  // otherwise a local JSON file — see moderationStore.ts) before the server
  // starts accepting connections, so the very first WebSocket upgrade is
  // already checked against whatever was configured in a previous run.
  await initModerationStore();
  // Loads registered accounts (and bootstraps the initial ADMIN one from
  // ADMIN_USER/ADMIN_PASSWORD if configured) before the server starts
  // accepting connections — see accountStore.ts.
  await initAccountStore();

  // @fastify/cors defaults to methods: "GET,HEAD,POST" — without listing
  // DELETE and PUT explicitly here, the browser's preflight for
  // DELETE /admin/announcement (clearing an announcement) or
  // PUT /admin/banned-words (saving the chat filter) gets back an
  // Access-Control-Allow-Methods that doesn't include them, so it blocks
  // the real request client-side with a CORS error before it ever reaches
  // this server.
  await app.register(cors, {
    origin: true,
    methods: ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: "*",
    exposedHeaders: "*",
  });
  await app.register(websocketPlugin, {
    options: {
      maxPayload: 64 * 1024,
      // A browser aborts the handshake outright when it offered subprotocols
      // and the response names none, so a moderator presenting its admin
      // token this way (see ADMIN_WS_PROTOCOL in signaling.ts) needs the
      // marker echoed back. Only ever the marker — never the token that
      // follows it, which has no business in a response header.
      //
      // Anything else offered is declined rather than reflected, which is
      // tighter than ws's default of echoing back whatever came first. No
      // client of this server offers a subprotocol for any other reason, so
      // there is nothing to preserve there.
      //
      // Called only when the client actually offered something (see ws's
      // completeUpgrade), so an ordinary connection never reaches this.
      handleProtocols: (protocols: Set<string>) =>
        protocols.has(ADMIN_WS_PROTOCOL) ? ADMIN_WS_PROTOCOL : false,
    },
  });

  // Global default: applies to every route below unless overridden via that
  // route's own `config.rateLimit` (see signaling.ts, and the /health and
  // /metrics overrides right here) — most routes never touch this default
  // at all, it's just the floor for anything nobody's specifically tuned.
  // `global: true` (the plugin default) is what makes it apply automatically
  // to routes registered later, including the ones inside the nested
  // `registerSignalingRoutes` context below — a root-level onRequest hook
  // reaches every child context in Fastify's encapsulation model.
  await app.register(rateLimit, {
    max: 100,
    timeWindow: "1 minute",
    // Only when clustered: the plugin's own store counts per process, so N
    // workers would quietly turn every limit below (and every per-route one
    // in signaling.ts) into N times what it says. See httpRateLimitStore.ts
    // — it keeps the same fixed-window arithmetic and shares the counts.
    ...(CLUSTER_ENABLED ? { store: ClusterRateLimitStore as never } : {}),
    onExceeded: (request) => {
      httpRateLimitedTotal.inc({ route: request.routeOptions?.url ?? request.url });
    },
  });

  // Health checks (uptime monitors, container orchestrator probes, load
  // balancers) can legitimately poll every few seconds from a fixed set of
  // IPs — rate limiting this would risk the check itself flapping the
  // service as unhealthy, which is worse than any abuse this endpoint could
  // realistically absorb (it does nothing but echo a constant).
  // `ok` and `CURRENT_ID` are unchanged and still the whole answer for an
  // uptime monitor. `cluster` is additive: which worker took this particular
  // request, how many are up against how many were asked for, how many have
  // been replaced since the primary started, and each one's pid and uptime.
  // Answered from the roster the primary pushes out (see clusterInfo.ts), so
  // it stays a memory read with no IPC round trip — this endpoint is
  // deliberately exempt from rate limiting and gets polled hard.
  app.get("/health", { config: { rateLimit: false } }, async () => ({
    ok: true,
    CURRENT_ID,
    cluster: clusterHealth(),
  }));

  app.get(
    "/metrics",
    {
      // Scraped automatically (Prometheus et al.) on a fixed interval from a
      // small, known set of scrapers — generous enough to tolerate several
      // scrape configs hitting it in parallel, but still capped in case this
      // ever ends up reachable without METRICS_TOKEN set.
      config: { rateLimit: { max: 60, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      if (METRICS_TOKEN) {
        const header = request.headers.authorization || "";
        const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
        if (provided !== METRICS_TOKEN) {
          return reply.code(401).send("Unauthorized");
        }
      }
      reply.header("Content-Type", metricsRegister.contentType);
      // A scrape reaches whichever worker the OS handed the connection to,
      // so answering with just that worker's registry would report a
      // different slice of the process pool on every scrape — counters
      // sawing up and down, default metrics (CPU, heap) describing one
      // arbitrary process. The primary is the only one that can talk to all
      // the workers, so it collects and merges them (see clusterPrimary.ts).
      // The room/connection gauges are already cluster-wide on every worker
      // thanks to the replication in signaling.ts, which is why they're
      // aggregated with "first" rather than summed — see metrics.ts.
      if (CLUSTER_ENABLED) {
        try {
          return await busRequest<string>("metrics:collect");
        } catch (err) {
          // Falling back to this worker's own numbers beats answering a
          // scrape with an error: partial metrics still graph, a 500 leaves
          // a hole and fires whatever alerts watch for one.
          app.log.error(err, "metrics: falha ao agregar o cluster");
        }
      }
      return metricsRegister.metrics();
    }
  );

  // Social login (see oauthRoutes.ts). Registered at the root rather than
  // inside the signaling context below because it shares nothing with it —
  // it only needs the account store, which initAccountStore already
  // prepared above, and the rate limiter registered at this level.
  await registerOAuthRoutes(app);

  await app.register(async (instance) => {
    await registerSignalingRoutes(instance, randomUUID);
  });

  try {
    await app.listen({ port: PORT, host: HOST });
    if (CLUSTER_ENABLED) {
      console.log(`[cluster] Worker ${WORKER_ID} (pid ${process.pid}) ouvindo em ${HOST}:${PORT}.`);
      // The primary broadcasts the roster the moment this worker starts
      // listening, so this only covers having missed that one. Not awaited:
      // nothing here should hold up a server that is already serving.
      void refreshClusterRoster();
    }
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

main();
