/**
 * Entry point: node packages/gateway/dist/main.js, configured from GATEWAY_* env.
 */

import { loadConfig } from './config.js';
import { startGateway } from './index.js';

async function main(): Promise<void> {
  const config = loadConfig();
  if (config.allowAnonymous) {
    process.stderr.write('gateway: anonymous access is ON - for local testing only\n');
  }
  const running = await startGateway(config);
  process.stderr.write(`gateway: listening on ${config.host}:${running.port}, program pinned\n`);
  const stop = () => {
    void running.close().then(() => process.exit(0));
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((err) => {
  process.stderr.write(`gateway: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
