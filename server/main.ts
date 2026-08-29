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

// Same reasoning as the identical import at the top of index.ts, and for the
// same reason it is the *first* one here: this file reads CLUSTER_WORKERS to
// decide whether to fork at all, and that decision happens before index.ts —
// the file that used to be the only place dotenv was loaded — is imported at
// all. Without this, CLUSTER_WORKERS set in a .env is invisible here: the
// count silently falls back to the core count, and on a single-core container
// that means never clustering no matter what the .env says.
import "dotenv/config";

import cluster from "node:cluster";

function runServer(): void {
  void import("./index.js").catch((err) => {
    console.error("[boot] Falha ao iniciar o servidor:", err);
    process.exit(1);
  });
}

if (cluster.isPrimary) {
  void import("./clusterPrimary.js")
    .then(({ resolveWorkerCount, availableCores, startClusterPrimary }) => {
      const workers = resolveWorkerCount();
      if (workers > 1) {
        startClusterPrimary(workers);
        return;
      }
      // Says *why* out loud, because "the cluster silently didn't start" is
      // otherwise only visible as an `enabled: false` in GET /health with
      // nothing to explain it — and the usual cause is a container reporting
      // a single core while CLUSTER_WORKERS was never actually set in the
      // environment this process can see.
      console.log(
        `[cluster] Processo único (CLUSTER_WORKERS=${process.env.CLUSTER_WORKERS ?? "não definida"}, núcleos disponíveis=${availableCores()}).`
      );
      runServer();
    })
    .catch((err) => {
      console.error("[boot] Falha ao iniciar o cluster:", err);
      process.exit(1);
    });
} else {
  runServer();
}
