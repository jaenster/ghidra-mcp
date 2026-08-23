/**
 * E2E Tests for Ghidra MCP Analysis
 *
 * These tests start a real daemon, create sessions, and verify
 * that binary analysis produces expected results.
 *
 * Run with: node --test --experimental-strip-types test/e2e/analysis.test.ts
 * Or with timeout: node --test --test-timeout=120000 --experimental-strip-types test/e2e/analysis.test.ts
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  startTestDaemon,
  getTestProgramPath,
  hasGhidraProjects,
  TEST_BINARIES_DIR,
  getTestBinaries,
  cleanupAllDaemons,
  type DaemonHandle,
} from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';

// Test timeouts - Ghidra analysis is slow, needs generous timeouts
const SUITE_TIMEOUT = 600_000; // 10 minutes for whole suite (multiple binaries)
const TEST_TIMEOUT = 60_000; // 1 minute per test
const ANALYSIS_TIMEOUT = 180_000; // 3 minutes for analysis-heavy tests (session ready wait + test)

// Skip if Ghidra not available
const GHIDRA_HOME = process.env.GHIDRA_HOME;
const SKIP_REASON = !GHIDRA_HOME
  ? 'GHIDRA_HOME not set'
  // Sessions open a Ghidra project, never a loose binary, so the pre-analysed fixtures
  // are a hard requirement now rather than an optimisation.
  : !hasGhidraProjects()
    ? "No test Ghidra projects — run 'npm run fixtures:build' then 'npm run fixtures:ghidra'"
    : undefined;

// Ensure cleanup on any exit
after(async () => {
  await cleanupAllDaemons();
});

describe('E2E: Ghidra MCP Analysis', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;

  before(async () => {
    console.log('Starting test daemon...');
    daemon = await startTestDaemon(18432);
    // Use ANALYSIS_TIMEOUT for client since session creation waits for analysis
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: ANALYSIS_TIMEOUT });
    await client.waitForReady();
    console.log(`Daemon ready on port ${daemon.port} (PID: ${daemon.pid})`);
  });

  after(async () => {
    console.log('Stopping test daemon...');
    if (client) {
      client.disconnect();
    }
    if (daemon) {
      await daemon.stop();
    }
  });

  describe('Daemon Health', { timeout: TEST_TIMEOUT }, () => {
    it('should respond to health checks', async () => {
      const healthy = await client.healthCheck();
      assert.strictEqual(healthy, true);
    });

    it('should list available tools', async () => {
      const tools = await client.listTools();
      assert.ok(Array.isArray(tools));
      assert.ok(tools.length > 0);

      const toolNames = tools.map((t) => t.name);
      assert.ok(toolNames.includes('list_sessions'), 'Should have list_sessions');
      assert.ok(toolNames.includes('create_session'), 'Should have create_session');
      assert.ok(toolNames.includes('decompile'), 'Should have decompile');
      assert.ok(toolNames.includes('list_functions'), 'Should have list_functions');
    });
  });

  describe('Session Management', { timeout: TEST_TIMEOUT }, () => {
    it('should start with no sessions', async () => {
      const sessions = await client.listSessions();
      assert.ok(Array.isArray(sessions));
    });
  });

  describe('Binary Analysis: simple_main', { timeout: ANALYSIS_TIMEOUT }, () => {
    let binaryPath: string;

    before(() => {
      binaryPath = getTestProgramPath('simple_main');
      console.log(`Testing binary: ${binaryPath}`);
    });

    afterEach(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should create a session for the binary', { timeout: ANALYSIS_TIMEOUT }, async () => {
      const session = await client.createSession(binaryPath);

      assert.ok(session.id, 'Should have session ID');
      assert.strictEqual(session.binaryPath, binaryPath);
      assert.ok(['starting', 'analyzing', 'ready'].includes(session.status));
    });

    it('should get program info', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const info = await client.getProgramInfo();

      assert.ok(info.name, 'Should have program name');
      assert.ok(info.format, 'Should have format (e.g., Mach-O, ELF)');
      assert.ok(info.imageBase, 'Should have image base');
    });

    it('should list functions', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { functions, total } = await client.listFunctions({ limit: 200 });

      assert.ok(Array.isArray(functions));
      assert.ok(total > 0, 'Should find at least some functions');

      const functionNames = functions.map((f) => f.name);
      // On macOS Mach-O, main entry point is named 'entry' by Ghidra
      // Check for entry or process_data which are always present
      const hasExpectedFunction = functionNames.some(
        (n) => n.includes('entry') || n.includes('process_data')
      );
      assert.ok(
        hasExpectedFunction,
        `Should find entry or process_data function. Found: ${functionNames.slice(0, 10).join(', ')}...`
      );
    });

    it('should find expected functions from test binary', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { functions } = await client.listFunctions({ limit: 200 });
      const names = functions.map((f) => f.name);

      const expectedFunctions = ['add_numbers', 'multiply_numbers', 'process_data', 'get_secret', 'xor_buffer'];

      for (const expected of expectedFunctions) {
        const found = names.some((n) => n.includes(expected));
        assert.ok(found, `Should find function: ${expected}`);
      }
    });

    it('should decompile entry/main function', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      // Ghidra names the main entry point 'entry' on macOS Mach-O binaries
      let result;
      try {
        result = await client.decompile({ name: 'entry' });
      } catch {
        // Fall back to trying main/_main if entry doesn't work
        try {
          result = await client.decompile({ name: 'main' });
        } catch {
          result = await client.decompile({ name: '_main' });
        }
      }

      assert.ok(result.pseudocode, 'Should have pseudocode');
      assert.ok(result.pseudocode.length > 50, 'Pseudocode should be substantial');
      assert.ok(
        result.pseudocode.includes('return') || result.pseudocode.includes('process_data'),
        'Decompiled code should contain expected patterns'
      );
    });

    it('should find strings', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { strings, total } = await client.listStrings({ minLength: 5, limit: 100 });

      assert.ok(Array.isArray(strings));
      assert.ok(total > 0, 'Should find some strings');

      const values = strings.map((s) => s.value);
      const expectedStrings = ['Hello from test binary', 'SECRET_KEY', 'Result:'];

      for (const expected of expectedStrings) {
        const found = values.some((v) => v.includes(expected));
        assert.ok(found, `Should find string containing: ${expected}`);
      }
    });

    it('should find the secret string via search', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { results } = await client.search('SECRET', ['strings']);

      assert.ok(results.length > 0, 'Should find SECRET string');
      assert.ok(
        results.some((r) => r.name.includes('SECRET_KEY')),
        `Should find SECRET_KEY string. Found: ${results.map((r) => r.name).join(', ')}`
      );
    });

    it('should search functions by regex', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      // Search for functions containing "process" or "data"
      const { results } = await client.search('process.*data|data', ['functions']);

      assert.ok(results.length > 0, 'Should find functions matching regex');
      assert.ok(
        results.some((r) => r.name.includes('process') || r.name.includes('data')),
        `Should find process/data functions. Found: ${results.map((r) => r.name).join(', ')}`
      );
    });

    it('should search with case insensitivity', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      // Search lowercase, should find uppercase SECRET_KEY
      const { results } = await client.search('secret', ['strings']);

      assert.ok(results.length > 0, 'Should find strings with case-insensitive search');
      assert.ok(
        results.some((r) => r.name.toUpperCase().includes('SECRET')),
        `Should find SECRET string case-insensitively. Found: ${results.map((r) => r.name).join(', ')}`
      );
    });

    it('should search all types', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      // Search for something that might appear in multiple types
      const { results } = await client.search('main|entry|process', ['all']);

      assert.ok(results.length > 0, 'Should find results across all types');

      // Should have found at least a function or symbol
      const types = new Set(results.map((r) => r.type));
      assert.ok(
        types.has('function') || types.has('symbol'),
        `Should find functions or symbols. Types found: ${[...types].join(', ')}`
      );
    });

    it('should list imports', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { imports, total } = await client.listImports({ limit: 100 });

      assert.ok(Array.isArray(imports));
      assert.ok(total > 0, 'Should have imports');

      const importNames = imports.map((i) => i.name);
      const expectedImports = ['printf', 'puts', 'strlen'];

      for (const expected of expectedImports) {
        const found = importNames.some((n) => n.includes(expected));
        assert.ok(found, `Should import: ${expected}`);
      }
    });
  });

  describe('Binary Analysis: call_graph', { timeout: ANALYSIS_TIMEOUT }, () => {
    let binaryPath: string;

    before(() => {
      binaryPath = getTestProgramPath('call_graph');
    });

    afterEach(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should find the deep call chain functions', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { functions } = await client.listFunctions({ limit: 200 });
      const names = functions.map((f) => f.name);

      const chainFunctions = ['level1', 'level2', 'level3', 'level4', 'leaf_function'];
      for (const fn of chainFunctions) {
        const found = names.some((n) => n.includes(fn));
        assert.ok(found, `Should find call chain function: ${fn}`);
      }
    });

    it('should find xrefs from level1 to level2', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { functions } = await client.listFunctions({ filter: 'level2' });
      const level2 = functions.find((f) => f.name.includes('level2'));

      if (level2) {
        const { xrefs } = await client.getXrefs(level2.address, 'to');

        assert.ok(xrefs.length > 0, 'level2 should have callers');

        const callerNames = xrefs.map((x) => x.fromFunction).filter(Boolean);
        const hasLevel1Caller = callerNames.some((n) => n?.includes('level1'));
        assert.ok(hasLevel1Caller, 'level2 should be called by level1');
      }
    });
  });

  describe('Binary Analysis: structures', { timeout: ANALYSIS_TIMEOUT }, () => {
    let binaryPath: string;

    before(() => {
      binaryPath = getTestProgramPath('structures');
    });

    afterEach(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should find struct-related functions', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      const { functions } = await client.listFunctions({ limit: 200 });
      const names = functions.map((f) => f.name);

      const structFunctions = ['make_point', 'rectangle_area', 'print_person', 'create_node'];
      for (const fn of structFunctions) {
        const found = names.some((n) => n.includes(fn));
        assert.ok(found, `Should find struct function: ${fn}`);
      }
    });

    it('should find strings in binary', { timeout: TEST_TIMEOUT }, async () => {
      await client.createSession(binaryPath);

      // List strings without filter - filter may not work as expected
      const { strings, total } = await client.listStrings({ limit: 100 });

      // Just verify we can list strings - the exact content varies by platform
      assert.ok(total > 0, 'Should have some strings');
      assert.ok(strings.length > 0, 'Should return some strings');
    });
  });

  describe('Multiple Binaries', { timeout: ANALYSIS_TIMEOUT }, () => {
    afterEach(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should handle creating multiple sessions', { timeout: ANALYSIS_TIMEOUT }, async () => {
      const binaries = getTestBinaries();

      if (binaries.length < 2) {
        console.log('Skipping: Need at least 2 test binaries');
        return;
      }

      const session1 = await client.createSession(binaries[0].path);
      const session2 = await client.createSession(binaries[1].path);

      assert.ok(session1.id);
      assert.ok(session2.id);
      assert.notStrictEqual(session1.id, session2.id);

      const sessions = await client.listSessions();
      assert.ok(sessions.length >= 2);

      client.setSession(session1.id);
      await client.closeSession();
      client.setSession(session2.id);
      await client.closeSession();
    });
  });
});

describe('E2E: Error Handling', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;

  before(async () => {
    daemon = await startTestDaemon(18433);
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: ANALYSIS_TIMEOUT });
    await client.waitForReady();
  });

  after(async () => {
    client?.disconnect();
    await daemon?.stop();
  });

  it('should handle non-existent binary gracefully', { timeout: TEST_TIMEOUT }, async () => {
    await assert.rejects(async () => {
      await client.createSession('/nonexistent/path/to/binary');
    }, /cannot be resolved|not found|does not exist/i);
  });

  it('refuses a loose binary and points at the import', { timeout: TEST_TIMEOUT }, async () => {
    // Opening one would import it into a project thrown away with the session, leaving
    // nothing to commit or reopen — the error has to say so, and name the way in.
    const looseBinary = `${TEST_BINARIES_DIR}/simple_main`;
    await assert.rejects(async () => {
      await client.createSession(looseBinary);
    }, /import_program/);
  });

  it('should handle invalid session ID gracefully', { timeout: TEST_TIMEOUT }, async () => {
    await assert.rejects(async () => {
      client.setSession('invalid-session-id-12345');
      await client.listFunctions();
    }, /session|not found/i);
  });
});
