/**
 * A throwaway Ghidra Server for e2e tests that need versioned programs.
 *
 * It runs from $GHIDRA_HOME's own jars but with its own repositories directory and its
 * own config file in a temp dir, on loopback, on a port block far from the default 13100,
 * so it never touches the installation's server.conf or any real server. It is stopped
 * by the exact pid this helper started.
 */

import * as child_process from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

export interface TestGhidraServer {
  host: string;
  /** Base port; the server also uses port+1 and port+2. */
  port: number;
  user: string;
  /** The account starts with Ghidra's default password; the worker keeps it on the forced reset. */
  password: string;
  /** Environment that points a daemon at this server. */
  daemonEnv: Record<string, string>;
  repoDir: string;
  stop(): Promise<void>;
}

export const TEST_SERVER_PORT = 13700;
export const TEST_SERVER_USER = 'e2euser';
const DEFAULT_PASSWORD = 'changeme';

/** Why a server-backed test cannot run here, or undefined when it can. */
export function ghidraServerSkipReason(): string | undefined {
  const home = process.env.GHIDRA_HOME;
  if (!home) return 'GHIDRA_HOME not set';
  if (!fs.existsSync(path.join(home, 'support', 'launch.sh'))) return 'GHIDRA_HOME has no support/launch.sh';
  if (!fs.existsSync(path.join(home, 'server', 'svrAdmin'))) return 'GHIDRA_HOME has no server/ directory';
  return undefined;
}

function portFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)));
  });
}

function portOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1');
    sock.once('connect', () => { sock.destroy(); resolve(true); });
    sock.once('error', () => resolve(false));
  });
}

function runLaunch(home: string, name: string, mem: string, vmArgs: string, mainClass: string, args: string[],
  opts: { cwd: string }): string {
  const launch = path.join(home, 'support', 'launch.sh');
  return child_process.execFileSync('bash', [launch, 'fg', 'jdk', name, mem, vmArgs, mainClass, ...args],
    { cwd: opts.cwd, encoding: 'utf8', timeout: 120_000 });
}

/**
 * Start a server with one user who may create repositories. Resolves once the server
 * accepts connections.
 */
export async function startTestGhidraServer(port = TEST_SERVER_PORT): Promise<TestGhidraServer> {
  const home = process.env.GHIDRA_HOME;
  const skip = ghidraServerSkipReason();
  if (skip || !home) throw new Error(skip);
  for (const p of [port, port + 1, port + 2]) {
    if (!(await portFree(p))) throw new Error(`Port ${p} is in use; the test server needs ${port}-${port + 2}`);
  }

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-test-server-'));
  const repoDir = path.join(root, 'repositories');
  fs.mkdirSync(repoDir);
  // svrAdmin finds the repositories through this file; it is the only key it reads.
  const conf = path.join(root, 'server.conf');
  fs.writeFileSync(conf, `ghidra.repositories.dir=${repoDir}\n`);

  // GhidraServer is not a launchable class: the service wrapper starts it straight from
  // the module's classpath fragment, so do the same, minus the wrapper.
  const frag = path.join(home, 'Ghidra', 'Features', 'GhidraServer', 'data', 'classpath.frag');
  const classpath = fs.readFileSync(frag, 'utf8').split('\n')
    .map((l) => /^wrapper\.java\.classpath\.\d+=(.*)$/.exec(l.trim())?.[1])
    .filter((v): v is string => !!v)
    .map((v) => v.replace('${ghidra_home}', home))
    .join(path.delimiter);
  const java = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
  const proc = child_process.spawn(java, [
    '-Xmx768M', '-Djava.net.preferIPv4Stack=true', `-Djava.io.tmpdir=${root}`, '-Djava.awt.headless=true',
    `-Dclasspath_frag=${frag}`, '-cp', classpath,
    'ghidra.server.remote.GhidraServer', '-a0', '-ip', '127.0.0.1', `-p${port}`, repoDir,
  ], { cwd: home, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  proc.stdout?.on('data', (d) => { log += d.toString(); if (process.env.DEBUG) process.stdout.write(`[ghidra-server] ${d}`); });
  proc.stderr?.on('data', (d) => { log += d.toString(); if (process.env.DEBUG) process.stderr.write(`[ghidra-server] ${d}`); });

  const pid = proc.pid!;
  const stop = async (): Promise<void> => {
    if (proc.exitCode !== null || proc.signalCode !== null) return;
    const exited = new Promise<void>((resolve) => proc.once('exit', () => resolve()));
    proc.kill('SIGTERM');
    const timer = setTimeout(() => proc.kill('SIGKILL'), 10_000);
    await exited;
    clearTimeout(timer);
  };

  const deadline = Date.now() + 120_000;
  for (;;) {
    if (proc.exitCode !== null) throw new Error(`Ghidra Server exited early:\n${log.slice(-2000)}`);
    if (await portOpen(port) && /Registered remote|Server listening|ready/i.test(log)) break;
    if (Date.now() > deadline) {
      await stop();
      throw new Error(`Ghidra Server did not come up:\n${log.slice(-2000)}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }

  // svrAdmin only accepts a directory the server has initialised. The command is queued
  // there and the running server applies it on its next poll; wait for the user to exist.
  runLaunch(home, 'svrAdmin', '128M', '-DUserAdmin.invocation=svrAdmin -Djava.awt.headless=true',
    'ghidra.server.ServerAdmin', [conf, '-add', TEST_SERVER_USER], { cwd: root });
  const usersFile = path.join(repoDir, 'users');
  const userDeadline = Date.now() + 60_000;
  while (!(fs.existsSync(usersFile) && fs.readFileSync(usersFile, 'utf8').includes(`${TEST_SERVER_USER}:`))) {
    if (Date.now() > userDeadline) {
      await stop();
      throw new Error(`Ghidra Server did not add the test user:\n${log.slice(-2000)}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }

  return {
    host: '127.0.0.1',
    port,
    user: TEST_SERVER_USER,
    password: DEFAULT_PASSWORD,
    daemonEnv: {
      GHIDRA_SERVER_HOST: '127.0.0.1',
      GHIDRA_SERVER_PORT: String(port),
      GHIDRA_SERVER_USER: TEST_SERVER_USER,
      GHIDRA_SERVER_PASSWORD: DEFAULT_PASSWORD,
    },
    repoDir,
    stop,
  };
}
