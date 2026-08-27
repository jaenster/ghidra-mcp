/**
 * E2E Tests for Ghidra MCP Modification Tools
 *
 * Tests create/update/delete operations for:
 * - Structures, enums, unions, typedefs
 * - Bookmarks and comments
 * - Labels and symbols
 * - Functions
 * - Wildcard filter support
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import {
  startTestDaemon,
  getTestProgramPath,
  hasGhidraProjects,
  cleanupAllDaemons,
  type DaemonHandle,
} from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';

/**
 * Helper to call a tool and parse the JSON response
 */
async function call<T = Record<string, unknown>>(
  client: McpTestClient,
  name: string,
  args: Record<string, unknown> = {}
): Promise<T> {
  const result = await client.callTool(name, args);
  const text = result.content?.[0]?.text;
  if (!text) {
    throw new Error(`Empty response from ${name}`);
  }
  if (text.startsWith('Error:')) {
    throw new Error(text);
  }
  return JSON.parse(text) as T;
}

const TEST_TIMEOUT = 60_000;
const ANALYSIS_TIMEOUT = 180_000;
const SUITE_TIMEOUT = 600_000;

const GHIDRA_HOME = process.env.GHIDRA_HOME;
const SKIP_REASON = !GHIDRA_HOME
  ? 'GHIDRA_HOME not set'
  // Sessions open a Ghidra project, never a loose binary, so the pre-analysed fixtures
  // are a hard requirement now rather than an optimisation.
  : !hasGhidraProjects()
    ? "No test Ghidra projects — run 'npm run fixtures:build' then 'npm run fixtures:ghidra'"
    : undefined;

after(async () => {
  await cleanupAllDaemons();
});

describe('E2E: Modification Tools', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;
  let binaryPath: string;

  before(async () => {
    console.log('Starting test daemon for modification tests...');
    daemon = await startTestDaemon(18434);
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: ANALYSIS_TIMEOUT });
    await client.waitForReady();

    // Set output format to JSON for easier parsing in tests
    await client.callTool('set_output_format', { format: 'json' });

    binaryPath = getTestProgramPath('simple_main');
    console.log(`Using binary: ${binaryPath}`);
  });

  after(async () => {
    if (client) client.disconnect();
    if (daemon) await daemon.stop();
  });

  describe('Structure Lifecycle', { timeout: ANALYSIS_TIMEOUT }, () => {
    before(async () => {
      await client.createSession(binaryPath);
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should create a structure with fields', async () => {
      const result = await call(client, 'create_structure', {
        name: 'TestStruct',
        category: '/Test',
        fields: [
          { name: 'id', dataType: 'int', offset: 0 },
          { name: 'value', dataType: 'double', offset: 8 },
          { name: 'flags', dataType: 'byte', offset: 16 },
        ],
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.name, 'TestStruct');
      assert.ok(result.size > 0, 'Structure should have non-zero size');
    });

    it('should create a structure with array fields', async () => {
      const result = await call(client, 'create_structure', {
        name: 'BufferStruct',
        category: '/Test',
        fields: [
          { name: 'header', dataType: 'int', offset: 0 },
          { name: 'data', dataType: 'byte[256]', offset: 4 },
          { name: 'checksum', dataType: 'int', offset: 260 },
        ],
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.name, 'BufferStruct');
      assert.ok(result.size >= 264, `Structure should be at least 264 bytes, got ${result.size}`);
    });

    it('should update a structure by adding a field', async () => {
      const result = await call(client, 'update_structure', {
        name: 'TestStruct',
        category: '/Test',
        operation: 'addField',
        fields: [
          { name: 'extra', dataType: 'pointer', offset: 24 },
        ],
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.size >= 32, 'Size should increase after adding pointer field');
    });

    it('should update a structure by removing a field', async () => {
      const result = await call(client, 'update_structure', {
        name: 'TestStruct',
        category: '/Test',
        operation: 'removeField',
        fieldName: 'extra',
      });

      assert.strictEqual(result.success, true);
    });

    it('should get data type details', async () => {
      const result = await call(client, 'get_data_type', {
        name: 'TestStruct',
        category: '/Test',
      });

      assert.strictEqual(result.name, 'TestStruct');
      assert.ok(result.fields, 'Should have fields array');
      assert.ok(result.fields.length >= 3, 'Should have at least 3 fields');

      const fieldNames = result.fields.map((f: any) => f.name);
      assert.ok(fieldNames.includes('id'), 'Should have id field');
      assert.ok(fieldNames.includes('value'), 'Should have value field');
    });

    it('should list data types with filter', async () => {
      const result = await call(client, 'list_data_types', {
        filter: 'Test*',
        category: '/Test',
      });

      assert.ok(result.dataTypes.length > 0, 'Should find Test* data types');
      assert.ok(
        result.dataTypes.some((dt: any) => dt.name === 'TestStruct'),
        'Should find TestStruct'
      );
    });

    it('should delete a data type', async () => {
      const result = await call(client, 'delete_data_type', {
        name: 'BufferStruct',
        category: '/Test',
      });

      assert.strictEqual(result.success, true);

      // Verify it's gone
      await assert.rejects(async () => {
        await call(client, 'get_data_type', {
          name: 'BufferStruct',
          category: '/Test',
        });
      }, /not found/i);
    });
  });

  describe('Enum and Union Creation', { timeout: ANALYSIS_TIMEOUT }, () => {
    before(async () => {
      await client.createSession(binaryPath);
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should create an enum', async () => {
      const result = await call(client, 'create_enum', {
        name: 'TestEnum',
        category: '/Test',
        values: {
          NONE: 0,
          ACTIVE: 1,
          PAUSED: 2,
          STOPPED: 3,
        },
        size: 4,
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.name, 'TestEnum');
      assert.strictEqual(result.size, 4);
    });

    it('should create a union', async () => {
      const result = await call(client, 'create_union', {
        name: 'TestUnion',
        category: '/Test',
        fields: [
          { name: 'asInt', dataType: 'int' },
          { name: 'asFloat', dataType: 'float' },
          { name: 'asBytes', dataType: 'byte[4]' },
        ],
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.name, 'TestUnion');
      assert.strictEqual(result.size, 4, 'Union size should be max of all fields');
    });

    it('should create a typedef', async () => {
      const result = await call(client, 'create_typedef', {
        name: 'DWORD',
        baseType: 'uint',
        category: '/Test',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.name, 'DWORD');
    });

    it('should get enum details with values', async () => {
      const result = await call(client, 'get_data_type', {
        name: 'TestEnum',
        category: '/Test',
      });

      assert.strictEqual(result.name, 'TestEnum');
      assert.strictEqual(result.type, 'enum');
      assert.ok(result.enumValues, 'Should have enumValues');
      assert.strictEqual(result.enumValues.ACTIVE, 1);
      assert.strictEqual(result.enumValues.STOPPED, 3);
    });
  });

  describe('Data Type Resolution', { timeout: ANALYSIS_TIMEOUT }, () => {
    before(async () => {
      await client.createSession(binaryPath);
      // A program type whose name differs from the builtin alias only by case.
      await call(client, 'create_typedef', {
        name: 'DWORD',
        baseType: 'uint',
        category: '/Win32',
      });
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should prefer a program type over a case-insensitive builtin alias', async () => {
      await call(client, 'create_structure', {
        name: 'ResolveExact',
        category: '/Test',
        fields: [{ name: 'flags', dataType: 'DWORD', offset: 0 }],
      });

      const detail = await call(client, 'get_data_type', {
        name: 'ResolveExact',
        category: '/Test',
      });
      const field = (detail.fields as Array<{ name: string; dataType: string }>)[0];
      assert.strictEqual(
        field.dataType,
        'DWORD',
        `'DWORD' must resolve to /Win32/DWORD, not the builtin dword/uint (got ${field.dataType})`
      );
    });

    it('should still accept a category-qualified name', async () => {
      await call(client, 'create_structure', {
        name: 'ResolveQualified',
        category: '/Test',
        fields: [{ name: 'flags', dataType: 'Win32/DWORD', offset: 0 }],
      });

      const detail = await call(client, 'get_data_type', {
        name: 'ResolveQualified',
        category: '/Test',
      });
      const field = (detail.fields as Array<{ name: string; dataType: string }>)[0];
      assert.strictEqual(field.dataType, 'DWORD');
    });

    it('should still resolve a builtin alias the program has no type for', async () => {
      await call(client, 'create_structure', {
        name: 'ResolveAlias',
        category: '/Test',
        fields: [{ name: 'count', dataType: 'uint32', offset: 0 }],
      });

      const detail = await call(client, 'get_data_type', {
        name: 'ResolveAlias',
        category: '/Test',
      });
      assert.strictEqual(detail.size, 4);
    });

    it('should reject an unknown type instead of silently using undefined1', async () => {
      await assert.rejects(
        () =>
          call(client, 'create_structure', {
            name: 'ResolveUnknown',
            category: '/Test',
            fields: [{ name: 'x', dataType: 'NoSuchTypeExists_zz', offset: 0 }],
          }),
        /Unknown data type/
      );
    });

    it('should reject an ambiguous name instead of picking one', async () => {
      await call(client, 'create_typedef', {
        name: 'AMBI',
        baseType: 'byte',
        category: '/AmbiA',
      });
      await call(client, 'create_typedef', {
        name: 'AMBI',
        baseType: 'double',
        category: '/AmbiB',
      });

      await assert.rejects(
        () =>
          call(client, 'create_structure', {
            name: 'ResolveAmbiguous',
            category: '/Test',
            fields: [{ name: 'x', dataType: 'AMBI', offset: 0 }],
          }),
        /Ambiguous data type/
      );

      // The qualified name still works, which is what the error tells the caller to use.
      const ok = await call(client, 'create_structure', {
        name: 'ResolveDisambiguated',
        category: '/Test',
        fields: [{ name: 'x', dataType: 'AmbiB/AMBI', offset: 0 }],
      });
      assert.strictEqual(ok.success, true);
    });

    it('should report the resolved type when retyping a variable', async () => {
      // A decompile satisfies the read-before-write guard and populates the locals.
      let funcName: string | undefined;
      for (const candidate of ['entry', 'main', '_main']) {
        try {
          await client.decompile({ name: candidate });
          funcName = candidate;
          break;
        } catch {
          /* try the next name */
        }
      }
      assert.ok(funcName, 'Expected one of entry/main/_main to decompile');

      const info = await call(client, 'get_function_info', { name: funcName });
      const locals = (info.localVariables ?? []) as Array<{ name: string }>;
      if (locals.length === 0) {
        return; // nothing to retype in this fixture build
      }

      const result = await call(client, 'set_function_variable_type', {
        functionAddress: info.entryPoint as string,
        variableName: locals[0].name,
        dataType: 'DWORD',
      });

      assert.strictEqual(result.success, true);
      // The path is whichever equivalent DWORD typedef the program holds — the point is
      // that it is a program typedef and not the builtin (which would report '/uint').
      assert.match(
        result.resolvedType as string,
        /\/DWORD$/,
        `retype should report the program's DWORD, not the builtin (got ${result.resolvedType})`
      );
    });
  });

  describe('Bookmark Lifecycle', { timeout: ANALYSIS_TIMEOUT }, () => {
    let testAddress: string;

    before(async () => {
      await client.createSession(binaryPath);

      // Get an address to use for bookmarks
      const { functions } = await client.listFunctions({ limit: 1 });
      testAddress = functions[0].address;
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should add a bookmark', async () => {
      const result = await call(client, 'add_bookmark', {
        address: testAddress,
        type: 'Note',
        category: 'Analysis',
        comment: 'Test bookmark for e2e testing',
      });

      assert.strictEqual(result.success, true);
    });

    it('should list bookmarks and find the added one', async () => {
      const result = await call(client, 'list_bookmarks', {
        type: 'Note',
        category: 'Analysis',
      });

      assert.ok(result.bookmarks.length > 0, 'Should have bookmarks');

      const found = result.bookmarks.some(
        (b: any) => b.address === testAddress && b.comment.includes('Test bookmark')
      );
      assert.ok(found, 'Should find the test bookmark');
    });

    it('should delete a bookmark', async () => {
      const result = await call(client, 'delete_bookmark', {
        address: testAddress,
        type: 'Note',
      });

      assert.strictEqual(result.success, true);
    });

    it('should verify bookmark was removed or changed', async () => {
      // The delete operation returned success, now verify the state
      const result = await call(client, 'list_bookmarks', {});

      // Either the bookmark should be gone, or at least our specific one shouldn't be there
      const ourBookmark = result.bookmarks.find(
        (b: any) => b.address === testAddress &&
                   b.type === 'Note' &&
                   b.category === 'Analysis' &&
                   b.comment?.includes('Test bookmark')
      );

      // The specific bookmark we added (Note type, Analysis category, with our comment)
      // should no longer exist after deletion
      assert.ok(
        !ourBookmark,
        `Our specific bookmark should be deleted. Found: ${JSON.stringify(ourBookmark)}`
      );
    });
  });

  describe('Comment Lifecycle', { timeout: ANALYSIS_TIMEOUT }, () => {
    let testAddress: string;

    before(async () => {
      await client.createSession(binaryPath);

      const { functions } = await client.listFunctions({ limit: 1 });
      testAddress = functions[0].address;
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should set an EOL comment', async () => {
      const result = await call(client, 'set_comment', {
        address: testAddress,
        comment: 'Test EOL comment',
        type: 'EOL',
      });

      assert.strictEqual(result.success, true);
    });

    it('should set a PLATE comment', async () => {
      const result = await call(client, 'set_comment', {
        address: testAddress,
        comment: 'Test PLATE comment - function header',
        type: 'PLATE',
      });

      assert.strictEqual(result.success, true);
    });

    it('should list comments and find them', async () => {
      const result = await call(client, 'list_comments', {
        limit: 100,
      });

      const eolComment = result.comments.find(
        (c: any) => c.address === testAddress && c.type === 'EOL'
      );
      assert.ok(eolComment, 'Should find EOL comment');
      assert.ok(eolComment.comment.includes('Test EOL comment'), 'Comment text should match');
    });

    it('should delete a specific comment type', async () => {
      const result = await call(client, 'delete_comment', {
        address: testAddress,
        type: 'EOL',
      });

      assert.strictEqual(result.success, true);
    });

    it('should delete all comments at address', async () => {
      const result = await call(client, 'delete_comment', {
        address: testAddress,
        type: 'ALL',
      });

      assert.strictEqual(result.success, true);
    });
  });

  describe('Label Lifecycle', { timeout: ANALYSIS_TIMEOUT }, () => {
    let testAddress: string;

    before(async () => {
      await client.createSession(binaryPath);

      // Get a data address (not a function) for labeling
      const { strings } = await client.listStrings({ limit: 1 });
      testAddress = strings[0].address;
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should create a label', async () => {
      const result = await call(client, 'create_label', {
        address: testAddress,
        name: 'my_test_label',
        primary: true,
      });

      assert.strictEqual(result.success, true);
    });

    it('should find the label in symbols', async () => {
      const result = await call(client, 'list_symbols', {
        filter: 'my_test*',
      });

      const found = result.symbols.some((s: any) => s.name === 'my_test_label');
      assert.ok(found, 'Should find created label');
    });

    it('should delete a label', async () => {
      const result = await call(client, 'delete_label', {
        address: testAddress,
        name: 'my_test_label',
      });

      assert.strictEqual(result.success, true);
    });
  });

  describe('Function Management', { timeout: ANALYSIS_TIMEOUT }, () => {
    let codeAddress: string;

    before(async () => {
      await client.createSession(binaryPath);

      // Get an existing function's address to use as reference
      const { functions } = await client.listFunctions({ limit: 5 });
      // Use an address near an existing function
      const addr = parseInt(functions[0].address, 16);
      codeAddress = `0x${(addr + 0x100).toString(16)}`;
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should rename a symbol', async () => {
      const { functions } = await client.listFunctions({ filter: '*process*', limit: 1 });

      if (functions.length > 0) {
        const result = await call(client, 'rename_symbol', {
          address: functions[0].address,
          newName: 'renamed_process_func',
          type: 'function',
        });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.newName, 'renamed_process_func');
      }
    });
  });

  describe('Wildcard Filter Support', { timeout: ANALYSIS_TIMEOUT }, () => {
    before(async () => {
      await client.createSession(binaryPath);
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should support * wildcard at end', async () => {
      const result = await call(client, 'list_functions', {
        filter: 'get*',
        limit: 100,
      });

      // All results should start with "get"
      for (const func of result.functions) {
        assert.ok(
          func.name.toLowerCase().startsWith('get'),
          `Function ${func.name} should start with "get"`
        );
      }
    });

    it('should support * wildcard at beginning', async () => {
      const result = await call(client, 'list_functions', {
        filter: '*data',
        limit: 100,
      });

      // All results should end with "data"
      for (const func of result.functions) {
        assert.ok(
          func.name.toLowerCase().endsWith('data'),
          `Function ${func.name} should end with "data"`
        );
      }
    });

    it('should support * wildcard in middle', async () => {
      const result = await call(client, 'list_functions', {
        filter: 'FUN_*0',
        limit: 100,
      });

      // Results should match FUN_*0 pattern
      for (const func of result.functions) {
        const matches = func.name.startsWith('FUN_') && func.name.endsWith('0');
        assert.ok(matches, `Function ${func.name} should match FUN_*0`);
      }
    });

    it('should support ? single character wildcard', async () => {
      // Create some test data first
      await call(client, 'create_structure', { name: 'TypeA', category: '/WildcardTest', fields: [{ name: 'x', dataType: 'int', offset: 0 }] });
      await call(client, 'create_structure', { name: 'TypeB', category: '/WildcardTest', fields: [{ name: 'x', dataType: 'int', offset: 0 }] });
      await call(client, 'create_structure', { name: 'TypeC', category: '/WildcardTest', fields: [{ name: 'x', dataType: 'int', offset: 0 }] });

      const result = await call(client, 'list_data_types', {
        filter: 'Type?',
        category: '/WildcardTest',
      });

      assert.ok(result.dataTypes.length >= 3, 'Should find Type? matches');

      for (const dt of result.dataTypes) {
        assert.ok(
          dt.name.match(/^Type.$/),
          `Data type ${dt.name} should match Type?`
        );
      }
    });

    it('should support multiple wildcards', async () => {
      const result = await call(client, 'list_symbols', {
        filter: '*_*_*',
        limit: 50,
      });

      // Results should have at least 2 underscores
      for (const sym of result.symbols) {
        const underscores = (sym.name.match(/_/g) || []).length;
        assert.ok(
          underscores >= 2,
          `Symbol ${sym.name} should have at least 2 underscores`
        );
      }
    });

    it('should be case insensitive by default', async () => {
      const upperResult = await call(client, 'list_functions', {
        filter: 'PROCESS*',
        limit: 100,
      });

      const lowerResult = await call(client, 'list_functions', {
        filter: 'process*',
        limit: 100,
      });

      // Should find the same functions regardless of case
      assert.strictEqual(
        upperResult.functions.length,
        lowerResult.functions.length,
        'Case should not affect results'
      );
    });

    it('should still support regex patterns', async () => {
      const result = await call(client, 'list_functions', {
        filter: '^(add|multiply)_numbers$',
        limit: 100,
      });

      for (const func of result.functions) {
        assert.ok(
          func.name === 'add_numbers' || func.name === 'multiply_numbers',
          `Function ${func.name} should match regex`
        );
      }
    });
  });

  describe('Disassembly Operations', { timeout: ANALYSIS_TIMEOUT }, () => {
    before(async () => {
      await client.createSession(binaryPath);
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('should get disassembly at an address', async () => {
      const { functions } = await client.listFunctions({ limit: 1 });

      const result = await call(client, 'get_disassembly', {
        address: functions[0].address,
        count: 10,
      });

      assert.ok(result.instructions.length > 0, 'Should have instructions');
      assert.ok(result.instructions[0].mnemonic, 'Instructions should have mnemonic');
      assert.ok(result.instructions[0].address, 'Instructions should have address');
    });

    it('should get disassembly with context', async () => {
      const { functions } = await client.listFunctions({ limit: 1 });

      const result = await call(client, 'get_disassembly', {
        address: functions[0].address,
        count: 10,
        context: 5,
      });

      assert.ok(result.instructions.length > 5, 'Should have instructions plus context');
    });
  });
});

describe('E2E: Save and Persist', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;
  let binaryPath: string;

  before(async () => {
    daemon = await startTestDaemon(18435);
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: ANALYSIS_TIMEOUT });
    await client.waitForReady();
    // Set output format to JSON for easier parsing in tests
    await client.callTool('set_output_format', { format: 'json' });
    binaryPath = getTestProgramPath('simple_main');
  });

  after(async () => {
    if (client) client.disconnect();
    if (daemon) await daemon.stop();
  });

  it('should handle save on non-project session', { timeout: ANALYSIS_TIMEOUT }, async () => {
    await client.createSession(binaryPath);

    // Make some modifications
    await call(client, 'create_structure', {
      name: 'PersistTest',
      category: '/Persist',
      fields: [
        { name: 'data', dataType: 'int', offset: 0 },
      ],
    });

    const { functions } = await client.listFunctions({ limit: 1 });
    await call(client, 'set_comment', {
      address: functions[0].address,
      comment: 'Persist test comment',
      type: 'EOL',
    });

    // Saving a session created from a binary (not a .gpr project) may fail
    // because there's no permanent project location
    try {
      const result = await call(client, 'save_session', {});
      // If it succeeds, that's fine too
      assert.strictEqual(result.success, true);
    } catch (error: any) {
      // Expected for non-project sessions - "Location does not exist for a save operation!"
      assert.ok(
        error.message.includes('Location') || error.message.includes('save'),
        `Expected save error, got: ${error.message}`
      );
    }

    await client.closeSession();
  });
});
