// Process entry point.
//
// Decides, once, whether this process is the cluster's supervisor or one of
// its workers, and then loads only what that role needs — the imports are
// dynamic on purpose. A static `import "./index.js"` would pull Fastify,
// mongoose, geoip's in-memory database and the whole of signaling.ts into
// the primary too, which never serves a request and shouldn't be paying for
// any of it.
//
// With CLUSTER_WORKERS=1 (or a single available core) nothing is forked at
// all: this file just loads server/index.ts in-process, which is byte for
// byte the server that ran before clustering existed.
import cluster from "node:cluster";

function runServer(): void {
  void import("./index.js").catch((err) => {
    console.error("[boot] Falha ao iniciar o servidor:", err);
    process.exit(1);
  });
}

if (cluster.isPrimary) {
  void import("./clusterPrimary.js")
    .then(({ resolveWorkerCount, startClusterPrimary }) => {
      const workers = resolveWorkerCount();
      if (workers > 1) startClusterPrimary(workers);
      else runServer();
    })
    .catch((err) => {
      console.error("[boot] Falha ao iniciar o cluster:", err);
      process.exit(1);
    });
} else {
  runServer();
}
