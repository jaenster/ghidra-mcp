/**
 * SQLite state database for persistent storage
 * Uses sql.js for pure JavaScript SQLite implementation
 */

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import initSqlJs, { type Database as SqlJsDatabase } from 'sql.js';
import type { SessionStatus } from '@ghidra-mcp/shared';

export interface LinkRow {
  id: string;
  source_session: string;
  source_address: string;
  target_session: string;
  target_address: string;
  link_type: string;
  anchor: number;
  metadata: string | null;
  created_at: string;
}

export interface SyncLogRow {
  id: string;
  link_id: string;
  change_type: string;
  old_value: string | null;
  new_value: string;
  status: string;
  error: string | null;
  created_at: string;
}

export interface DependencyViolationRow {
  id: string;
  run_id: string;
  file: string;
  include_path: string;
  owning_module: string;
  referenced_module: string;
  created_at: string;
}

interface SessionRow {
  id: string;
  binary_path: string;
  binary_hash: string;
  created_at: string;
  last_accessed_at: string;
  status: string;
  project_path: string;
}

interface AnnotationRow {
  id: string;
  session_id: string;
  address: string;
  type: string;
  value: string;
  created_at: string;
}

export class StateDatabase {
  private db: SqlJsDatabase | null = null;
  private dbPath: string;
  private initPromise: Promise<void>;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.initPromise = this.initialize();
  }

  /**
   * Initialize database
   */
  private async initialize(): Promise<void> {
    const SQL = await initSqlJs();

    // Load existing database or create new
    if (fs.existsSync(this.dbPath)) {
      const buffer = fs.readFileSync(this.dbPath);
      this.db = new SQL.Database(buffer);
    } else {
      this.db = new SQL.Database();
    }

    this.createTables();
  }

  /**
   * Wait for initialization
   */
  async ready(): Promise<void> {
    await this.initPromise;
  }

  /**
   * Create database tables
   */
  private createTables(): void {
    if (!this.db) throw new Error('Database not initialized');

    this.db.run(`
      -- Sessions table
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        binary_path TEXT NOT NULL,
        binary_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_accessed_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'starting',
        project_path TEXT
      )
    `);

    this.db.run(`
      -- Annotations table (renames, comments, types)
      CREATE TABLE IF NOT EXISTS annotations (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        address TEXT NOT NULL,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
      )
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_annotations_session
        ON annotations(session_id)
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_annotations_address
        ON annotations(session_id, address)
    `);

    this.db.run(`
      -- Decompilation cache
      CREATE TABLE IF NOT EXISTS decompile_cache (
        session_id TEXT NOT NULL,
        function_address TEXT NOT NULL,
        function_hash TEXT NOT NULL,
        pseudocode TEXT NOT NULL,
        cached_at TEXT NOT NULL,
        PRIMARY KEY (session_id, function_address),
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
      )
    `);

    this.db.run(`
      -- Export history (for code restoration)
      CREATE TABLE IF NOT EXISTS exports (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        function_address TEXT NOT NULL,
        function_name TEXT,
        signature TEXT,
        pseudocode TEXT,
        header_decl TEXT,
        exported_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
      )
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_exports_session
        ON exports(session_id)
    `);

    // Session aliases table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS session_aliases (
        alias TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_aliases_session
        ON session_aliases(session_id)
    `);

    // Cross-binary links table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS links (
        id TEXT PRIMARY KEY,
        source_session TEXT NOT NULL,
        source_address TEXT NOT NULL,
        target_session TEXT NOT NULL,
        target_address TEXT NOT NULL,
        link_type TEXT NOT NULL DEFAULT 'function',
        anchor INTEGER NOT NULL DEFAULT 0,
        metadata TEXT,
        created_at TEXT NOT NULL
      )
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_links_source
        ON links(source_session, source_address)
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_links_target
        ON links(target_session, target_address)
    `);

    // Sync log table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS sync_log (
        id TEXT PRIMARY KEY,
        link_id TEXT NOT NULL,
        change_type TEXT NOT NULL,
        old_value TEXT,
        new_value TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'applied',
        error TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (link_id) REFERENCES links(id)
      )
    `);

    // Dependency violations table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS dependency_violations (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        file TEXT NOT NULL,
        include_path TEXT NOT NULL,
        owning_module TEXT NOT NULL,
        referenced_module TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);

    this.db.run(`
      CREATE INDEX IF NOT EXISTS idx_dep_violations_run
        ON dependency_violations(run_id)
    `);

    // Shared structures table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS shared_structures (
        name TEXT PRIMARY KEY,
        category TEXT,
        fields_json TEXT NOT NULL,
        packed INTEGER DEFAULT 0,
        type_params_json TEXT,
        updated_at TEXT NOT NULL
      )
    `);

    // Shared structure targets table (with per-target type bindings for generics)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS shared_structure_targets (
        struct_name TEXT NOT NULL,
        session_alias TEXT NOT NULL,
        bindings_json TEXT,
        PRIMARY KEY (struct_name, session_alias),
        FOREIGN KEY (struct_name) REFERENCES shared_structures(name) ON DELETE CASCADE
      )
    `);

    // OAuth 2.1 authorization-server state (clients via DCR, auth codes, tokens)
    this.db.run(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )
    `);
    this.db.run(`
      CREATE TABLE IF NOT EXISTS oauth_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        scopes TEXT,
        resource TEXT,
        expires_at INTEGER NOT NULL
      )
    `);
    this.db.run(`
      CREATE TABLE IF NOT EXISTS oauth_tokens (
        token TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        client_id TEXT NOT NULL,
        scopes TEXT,
        resource TEXT,
        expires_at INTEGER
      )
    `);

    this.save();
  }

  /**
   * Save database to disk
   */
  private save(): void {
    if (!this.db) return;
    const data = this.db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(this.dbPath, buffer);
  }

  // =========================================================================
  // Session Operations
  // =========================================================================

  /**
   * Save a session to the database
   */
  saveSession(
    id: string,
    session: {
      binaryPath: string;
      binaryHash: string;
      createdAt: Date;
      lastAccessedAt: Date;
      status: SessionStatus;
      projectPath: string;
    }
  ): void {
    if (!this.db) throw new Error('Database not initialized');

    this.db.run(
      `INSERT OR REPLACE INTO sessions
        (id, binary_path, binary_hash, created_at, last_accessed_at, status, project_path)
      VALUES
        (?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        session.binaryPath,
        session.binaryHash,
        session.createdAt.toISOString(),
        session.lastAccessedAt.toISOString(),
        session.status,
        session.projectPath,
      ]
    );

    this.save();
  }

  /**
   * Update a session
   */
  updateSession(
    id: string,
    updates: Partial<{
      lastAccessedAt: Date;
      status: SessionStatus;
    }>
  ): void {
    if (!this.db) throw new Error('Database not initialized');

    const setClauses: string[] = [];
    const params: (string | number | null)[] = [];

    if (updates.lastAccessedAt) {
      setClauses.push('last_accessed_at = ?');
      params.push(updates.lastAccessedAt.toISOString());
    }

    if (updates.status) {
      setClauses.push('status = ?');
      params.push(updates.status);
    }

    if (setClauses.length === 0) return;

    params.push(id);
    this.db.run(
      `UPDATE sessions SET ${setClauses.join(', ')} WHERE id = ?`,
      params
    );

    this.save();
  }

  /**
   * Get all sessions
   */
  getSessions(): Array<{
    id: string;
    binaryPath: string;
    binaryHash: string;
    createdAt: Date;
    lastAccessedAt: Date;
    status: SessionStatus;
    projectPath: string;
  }> {
    if (!this.db) throw new Error('Database not initialized');

    const stmt = this.db.prepare('SELECT * FROM sessions');
    const results: Array<{
      id: string;
      binaryPath: string;
      binaryHash: string;
      createdAt: Date;
      lastAccessedAt: Date;
      status: SessionStatus;
      projectPath: string;
    }> = [];

    while (stmt.step()) {
      const row = stmt.getAsObject() as unknown as SessionRow;
      results.push({
        id: row.id,
        binaryPath: row.binary_path,
        binaryHash: row.binary_hash,
        createdAt: new Date(row.created_at),
        lastAccessedAt: new Date(row.last_accessed_at),
        status: row.status as SessionStatus,
        projectPath: row.project_path,
      });
    }

    stmt.free();
    return results;
  }

  /**
   * Get a session by ID
   */
  getSession(id: string): {
    id: string;
    binaryPath: string;
    binaryHash: string;
    createdAt: Date;
    lastAccessedAt: Date;
    status: SessionStatus;
    projectPath: string;
  } | null {
    if (!this.db) throw new Error('Database not initialized');

    const stmt = this.db.prepare('SELECT * FROM sessions WHERE id = ?');
    stmt.bind([id]);

    if (!stmt.step()) {
      stmt.free();
      return null;
    }

    const row = stmt.getAsObject() as unknown as SessionRow;
    stmt.free();

    return {
      id: row.id,
      binaryPath: row.binary_path,
      binaryHash: row.binary_hash,
      createdAt: new Date(row.created_at),
      lastAccessedAt: new Date(row.last_accessed_at),
      status: row.status as SessionStatus,
      projectPath: row.project_path,
    };
  }

  /**
   * Delete a session
   */
  deleteSession(id: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM sessions WHERE id = ?', [id]);
    this.save();
  }

  // =========================================================================
  // Annotation Operations
  // =========================================================================

  /**
   * Save an annotation
   */
  saveAnnotation(
    sessionId: string,
    address: string,
    type: 'rename' | 'comment' | 'type',
    value: string
  ): string {
    if (!this.db) throw new Error('Database not initialized');

    const id = crypto.randomUUID();
    this.db.run(
      `INSERT INTO annotations (id, session_id, address, type, value, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`,
      [id, sessionId, address, type, value, new Date().toISOString()]
    );

    this.save();
    return id;
  }

  /**
   * Get annotations for a session
   */
  getAnnotations(
    sessionId: string,
    options?: { address?: string; type?: string }
  ): Array<{
    id: string;
    address: string;
    type: string;
    value: string;
    createdAt: Date;
  }> {
    if (!this.db) throw new Error('Database not initialized');

    let sql = 'SELECT * FROM annotations WHERE session_id = ?';
    const params: (string | number | null)[] = [sessionId];

    if (options?.address) {
      sql += ' AND address = ?';
      params.push(options.address);
    }

    if (options?.type) {
      sql += ' AND type = ?';
      params.push(options.type);
    }

    sql += ' ORDER BY created_at DESC';

    const stmt = this.db.prepare(sql);
    stmt.bind(params);

    const results: Array<{
      id: string;
      address: string;
      type: string;
      value: string;
      createdAt: Date;
    }> = [];

    while (stmt.step()) {
      const row = stmt.getAsObject() as unknown as AnnotationRow;
      results.push({
        id: row.id,
        address: row.address,
        type: row.type,
        value: row.value,
        createdAt: new Date(row.created_at),
      });
    }

    stmt.free();
    return results;
  }

  // =========================================================================
  // Decompile Cache Operations
  // =========================================================================

  /**
   * Cache decompilation result
   */
  cacheDecompilation(
    sessionId: string,
    functionAddress: string,
    functionHash: string,
    pseudocode: string
  ): void {
    if (!this.db) throw new Error('Database not initialized');

    this.db.run(
      `INSERT OR REPLACE INTO decompile_cache
        (session_id, function_address, function_hash, pseudocode, cached_at)
      VALUES
        (?, ?, ?, ?, ?)`,
      [sessionId, functionAddress, functionHash, pseudocode, new Date().toISOString()]
    );

    this.save();
  }

  /**
   * Get cached decompilation
   */
  getCachedDecompilation(
    sessionId: string,
    functionAddress: string,
    functionHash: string
  ): string | null {
    if (!this.db) throw new Error('Database not initialized');

    const stmt = this.db.prepare(
      `SELECT pseudocode FROM decompile_cache
      WHERE session_id = ? AND function_address = ? AND function_hash = ?`
    );
    stmt.bind([sessionId, functionAddress, functionHash]);

    if (!stmt.step()) {
      stmt.free();
      return null;
    }

    const row = stmt.getAsObject() as { pseudocode: string };
    stmt.free();
    return row.pseudocode;
  }

  /**
   * Clear decompile cache for a session
   */
  clearDecompileCache(sessionId: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM decompile_cache WHERE session_id = ?', [sessionId]);
    this.save();
  }

  // =========================================================================
  // Export Operations
  // =========================================================================

  /**
   * Save an export
   */
  saveExport(
    sessionId: string,
    functionAddress: string,
    data: {
      functionName?: string;
      signature?: string;
      pseudocode?: string;
      headerDecl?: string;
    }
  ): string {
    if (!this.db) throw new Error('Database not initialized');

    const id = crypto.randomUUID();
    this.db.run(
      `INSERT INTO exports
        (id, session_id, function_address, function_name, signature, pseudocode, header_decl, exported_at)
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        sessionId,
        functionAddress,
        data.functionName ?? null,
        data.signature ?? null,
        data.pseudocode ?? null,
        data.headerDecl ?? null,
        new Date().toISOString(),
      ]
    );

    this.save();
    return id;
  }

  /**
   * Get exports for a session
   */
  getExports(sessionId: string): Array<{
    id: string;
    functionAddress: string;
    functionName: string | null;
    signature: string | null;
    pseudocode: string | null;
    headerDecl: string | null;
    exportedAt: Date;
  }> {
    if (!this.db) throw new Error('Database not initialized');

    const stmt = this.db.prepare(
      'SELECT * FROM exports WHERE session_id = ? ORDER BY exported_at DESC'
    );
    stmt.bind([sessionId]);

    const results: Array<{
      id: string;
      functionAddress: string;
      functionName: string | null;
      signature: string | null;
      pseudocode: string | null;
      headerDecl: string | null;
      exportedAt: Date;
    }> = [];

    while (stmt.step()) {
      const row = stmt.getAsObject() as {
        id: string;
        function_address: string;
        function_name: string | null;
        signature: string | null;
        pseudocode: string | null;
        header_decl: string | null;
        exported_at: string;
      };
      results.push({
        id: row.id,
        functionAddress: row.function_address,
        functionName: row.function_name,
        signature: row.signature,
        pseudocode: row.pseudocode,
        headerDecl: row.header_decl,
        exportedAt: new Date(row.exported_at),
      });
    }

    stmt.free();
    return results;
  }

  // =========================================================================
  // Session Alias Operations
  // =========================================================================

  setAlias(alias: string, sessionId: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run(
      `INSERT OR REPLACE INTO session_aliases (alias, session_id, created_at)
      VALUES (?, ?, ?)`,
      [alias, sessionId, new Date().toISOString()]
    );
    this.save();
  }

  removeAlias(alias: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM session_aliases WHERE alias = ?', [alias]);
    this.save();
  }

  removeAliasesForSession(sessionId: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM session_aliases WHERE session_id = ?', [sessionId]);
    this.save();
  }

  getAliasByName(alias: string): { alias: string; sessionId: string } | null {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT * FROM session_aliases WHERE alias = ?');
    stmt.bind([alias]);
    if (!stmt.step()) {
      stmt.free();
      return null;
    }
    const row = stmt.getAsObject() as { alias: string; session_id: string };
    stmt.free();
    return { alias: row.alias, sessionId: row.session_id };
  }

  getAliasesForSession(sessionId: string): string[] {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT alias FROM session_aliases WHERE session_id = ?');
    stmt.bind([sessionId]);
    const aliases: string[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject() as { alias: string };
      aliases.push(row.alias);
    }
    stmt.free();
    return aliases;
  }

  listAliases(): Array<{ alias: string; sessionId: string }> {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT * FROM session_aliases ORDER BY alias');
    const results: Array<{ alias: string; sessionId: string }> = [];
    while (stmt.step()) {
      const row = stmt.getAsObject() as { alias: string; session_id: string };
      results.push({ alias: row.alias, sessionId: row.session_id });
    }
    stmt.free();
    return results;
  }

  // =========================================================================
  // Shared Structure Operations
  // =========================================================================

  saveSharedStructure(
    name: string,
    data: {
      category?: string;
      fields: Array<{ name: string; dataType: string; offset: number; length: number; comment?: string }>;
      packed?: boolean;
      typeParams?: string[];
    }
  ): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run(
      `INSERT OR REPLACE INTO shared_structures (name, category, fields_json, packed, type_params_json, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)`,
      [
        name,
        data.category ?? null,
        JSON.stringify(data.fields),
        data.packed ? 1 : 0,
        data.typeParams ? JSON.stringify(data.typeParams) : null,
        new Date().toISOString(),
      ]
    );
    this.save();
  }

  getSharedStructure(name: string): {
    name: string;
    category: string | null;
    fields: Array<{ name: string; dataType: string; offset: number; length: number; comment?: string }>;
    packed: boolean;
    typeParams?: string[];
    updatedAt: Date;
    targets: Array<{ alias: string; bindings?: Record<string, string> }>;
  } | null {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT * FROM shared_structures WHERE name = ?');
    stmt.bind([name]);
    if (!stmt.step()) {
      stmt.free();
      return null;
    }
    const row = stmt.getAsObject() as {
      name: string;
      category: string | null;
      fields_json: string;
      packed: number;
      type_params_json: string | null;
      updated_at: string;
    };
    stmt.free();

    const targets = this.getStructureTargets(name);
    return {
      name: row.name,
      category: row.category,
      fields: JSON.parse(row.fields_json),
      packed: row.packed === 1,
      typeParams: row.type_params_json ? JSON.parse(row.type_params_json) : undefined,
      updatedAt: new Date(row.updated_at),
      targets,
    };
  }

  listSharedStructures(): Array<{
    name: string;
    category: string | null;
    fieldCount: number;
    packed: boolean;
    typeParams?: string[];
    updatedAt: Date;
    targets: Array<{ alias: string; bindings?: Record<string, string> }>;
  }> {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT * FROM shared_structures ORDER BY name');
    const results: Array<{
      name: string;
      category: string | null;
      fieldCount: number;
      packed: boolean;
      typeParams?: string[];
      updatedAt: Date;
      targets: Array<{ alias: string; bindings?: Record<string, string> }>;
    }> = [];
    while (stmt.step()) {
      const row = stmt.getAsObject() as {
        name: string;
        category: string | null;
        fields_json: string;
        packed: number;
        type_params_json: string | null;
        updated_at: string;
      };
      const fields = JSON.parse(row.fields_json) as unknown[];
      results.push({
        name: row.name,
        category: row.category,
        fieldCount: fields.length,
        packed: row.packed === 1,
        typeParams: row.type_params_json ? JSON.parse(row.type_params_json) : undefined,
        updatedAt: new Date(row.updated_at),
        targets: this.getStructureTargets(row.name),
      });
    }
    stmt.free();
    return results;
  }

  deleteSharedStructure(name: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM shared_structures WHERE name = ?', [name]);
    this.save();
  }

  setStructureTargets(
    structName: string,
    targets: Array<{ alias: string; bindings?: Record<string, string> }>
  ): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM shared_structure_targets WHERE struct_name = ?', [structName]);
    for (const target of targets) {
      this.db.run(
        'INSERT INTO shared_structure_targets (struct_name, session_alias, bindings_json) VALUES (?, ?, ?)',
        [structName, target.alias, target.bindings ? JSON.stringify(target.bindings) : null]
      );
    }
    this.save();
  }

  getStructureTargets(structName: string): Array<{ alias: string; bindings?: Record<string, string> }> {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT session_alias, bindings_json FROM shared_structure_targets WHERE struct_name = ?');
    stmt.bind([structName]);
    const targets: Array<{ alias: string; bindings?: Record<string, string> }> = [];
    while (stmt.step()) {
      const row = stmt.getAsObject() as { session_alias: string; bindings_json: string | null };
      targets.push({
        alias: row.session_alias,
        bindings: row.bindings_json ? JSON.parse(row.bindings_json) : undefined,
      });
    }
    stmt.free();
    return targets;
  }

  // =========================================================================
  // Link Operations
  // =========================================================================

  createLink(
    sourceSession: string,
    sourceAddress: string,
    targetSession: string,
    targetAddress: string,
    linkType: string = 'function',
    anchor: boolean = false,
    metadata?: Record<string, unknown>
  ): string {
    if (!this.db) throw new Error('Database not initialized');
    const id = crypto.randomUUID();
    this.db.run(
      `INSERT INTO links (id, source_session, source_address, target_session, target_address, link_type, anchor, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, sourceSession, sourceAddress, targetSession, targetAddress, linkType, anchor ? 1 : 0, metadata ? JSON.stringify(metadata) : null, new Date().toISOString()]
    );
    this.save();
    return id;
  }

  removeLink(id: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM links WHERE id = ?', [id]);
    this.save();
  }

  queryLinks(opts?: {
    sessionId?: string;
    address?: string;
    type?: string;
    anchor?: boolean;
  }): Array<{
    id: string;
    sourceSession: string;
    sourceAddress: string;
    targetSession: string;
    targetAddress: string;
    linkType: string;
    anchor: boolean;
    metadata: Record<string, unknown> | null;
    createdAt: Date;
  }> {
    if (!this.db) throw new Error('Database not initialized');

    let sql = 'SELECT * FROM links WHERE 1=1';
    const params: (string | number)[] = [];

    if (opts?.sessionId) {
      sql += ' AND (source_session = ? OR target_session = ?)';
      params.push(opts.sessionId, opts.sessionId);
    }
    if (opts?.address) {
      sql += ' AND (source_address = ? OR target_address = ?)';
      params.push(opts.address, opts.address);
    }
    if (opts?.type) {
      sql += ' AND link_type = ?';
      params.push(opts.type);
    }
    if (opts?.anchor !== undefined) {
      sql += ' AND anchor = ?';
      params.push(opts.anchor ? 1 : 0);
    }

    sql += ' ORDER BY created_at DESC';

    const stmt = this.db.prepare(sql);
    if (params.length > 0) stmt.bind(params);

    const results: Array<{
      id: string;
      sourceSession: string;
      sourceAddress: string;
      targetSession: string;
      targetAddress: string;
      linkType: string;
      anchor: boolean;
      metadata: Record<string, unknown> | null;
      createdAt: Date;
    }> = [];

    while (stmt.step()) {
      const row = stmt.getAsObject() as unknown as LinkRow;
      results.push({
        id: row.id,
        sourceSession: row.source_session,
        sourceAddress: row.source_address,
        targetSession: row.target_session,
        targetAddress: row.target_address,
        linkType: row.link_type,
        anchor: row.anchor === 1,
        metadata: row.metadata ? JSON.parse(row.metadata) : null,
        createdAt: new Date(row.created_at),
      });
    }

    stmt.free();
    return results;
  }

  getLinksForEntity(sessionId: string, address: string): Array<{
    id: string;
    sourceSession: string;
    sourceAddress: string;
    targetSession: string;
    targetAddress: string;
    linkType: string;
    anchor: boolean;
    metadata: Record<string, unknown> | null;
  }> {
    if (!this.db) throw new Error('Database not initialized');

    const stmt = this.db.prepare(
      `SELECT * FROM links
      WHERE (source_session = ? AND source_address = ?)
         OR (target_session = ? AND target_address = ?)`
    );
    stmt.bind([sessionId, address, sessionId, address]);

    const results: Array<{
      id: string;
      sourceSession: string;
      sourceAddress: string;
      targetSession: string;
      targetAddress: string;
      linkType: string;
      anchor: boolean;
      metadata: Record<string, unknown> | null;
    }> = [];

    while (stmt.step()) {
      const row = stmt.getAsObject() as unknown as LinkRow;
      results.push({
        id: row.id,
        sourceSession: row.source_session,
        sourceAddress: row.source_address,
        targetSession: row.target_session,
        targetAddress: row.target_address,
        linkType: row.link_type,
        anchor: row.anchor === 1,
        metadata: row.metadata ? JSON.parse(row.metadata) : null,
      });
    }

    stmt.free();
    return results;
  }

  bulkCreateLinks(links: Array<{
    sourceSession: string;
    sourceAddress: string;
    targetSession: string;
    targetAddress: string;
    linkType?: string;
    anchor?: boolean;
    metadata?: Record<string, unknown>;
  }>): number {
    if (!this.db) throw new Error('Database not initialized');

    const now = new Date().toISOString();
    this.db.run('BEGIN TRANSACTION');
    try {
      for (const link of links) {
        const id = crypto.randomUUID();
        this.db.run(
          `INSERT INTO links (id, source_session, source_address, target_session, target_address, link_type, anchor, metadata, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [id, link.sourceSession, link.sourceAddress, link.targetSession, link.targetAddress,
           link.linkType ?? 'function', link.anchor ? 1 : 0,
           link.metadata ? JSON.stringify(link.metadata) : null, now]
        );
      }
      this.db.run('COMMIT');
    } catch (err) {
      this.db.run('ROLLBACK');
      throw err;
    }

    this.save();
    return links.length;
  }

  clearLinks(opts?: { sourceSession?: string; targetSession?: string }): number {
    if (!this.db) throw new Error('Database not initialized');

    const conditions: string[] = [];
    const params: string[] = [];

    if (opts?.sourceSession) {
      conditions.push('source_session = ?');
      params.push(opts.sourceSession);
    }
    if (opts?.targetSession) {
      conditions.push('target_session = ?');
      params.push(opts.targetSession);
    }

    const where = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';
    this.db.run(`DELETE FROM links${where}`, params);
    const count = this.db.getRowsModified();
    this.save();
    return count;
  }

  // =========================================================================
  // Sync Log Operations
  // =========================================================================

  logSync(
    linkId: string,
    changeType: string,
    newValue: string,
    status: 'applied' | 'failed' = 'applied',
    oldValue?: string,
    error?: string
  ): string {
    if (!this.db) throw new Error('Database not initialized');
    const id = crypto.randomUUID();
    this.db.run(
      `INSERT INTO sync_log (id, link_id, change_type, old_value, new_value, status, error, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, linkId, changeType, oldValue ?? null, newValue, status, error ?? null, new Date().toISOString()]
    );
    this.save();
    return id;
  }

  getRecentSyncs(limit: number = 50): Array<{
    id: string;
    linkId: string;
    changeType: string;
    oldValue: string | null;
    newValue: string;
    status: string;
    error: string | null;
    createdAt: Date;
  }> {
    if (!this.db) throw new Error('Database not initialized');

    const stmt = this.db.prepare(
      'SELECT * FROM sync_log ORDER BY created_at DESC LIMIT ?'
    );
    stmt.bind([limit]);

    const results: Array<{
      id: string;
      linkId: string;
      changeType: string;
      oldValue: string | null;
      newValue: string;
      status: string;
      error: string | null;
      createdAt: Date;
    }> = [];

    while (stmt.step()) {
      const row = stmt.getAsObject() as unknown as SyncLogRow;
      results.push({
        id: row.id,
        linkId: row.link_id,
        changeType: row.change_type,
        oldValue: row.old_value,
        newValue: row.new_value,
        status: row.status,
        error: row.error,
        createdAt: new Date(row.created_at),
      });
    }

    stmt.free();
    return results;
  }

  isRecentSync(sessionId: string, address: string, changeType: string, withinMs: number = 5000): boolean {
    if (!this.db) throw new Error('Database not initialized');
    const cutoff = new Date(Date.now() - withinMs).toISOString();
    const stmt = this.db.prepare(
      `SELECT COUNT(*) as c FROM sync_log sl
       JOIN links l ON sl.link_id = l.id
       WHERE sl.change_type = ? AND sl.created_at > ? AND sl.status = 'applied'
         AND ((l.target_session = ? AND l.target_address = ?)
           OR (l.source_session = ? AND l.source_address = ?))`
    );
    stmt.bind([changeType, cutoff, sessionId, address, sessionId, address]);
    stmt.step();
    const row = stmt.getAsObject() as { c: number };
    stmt.free();
    return row.c > 0;
  }

  // =========================================================================
  // Dependency Violation Operations
  // =========================================================================

  storeDependencyRun(violations: Array<{
    file: string;
    includePath: string;
    owningModule: string;
    referencedModule: string;
  }>): string {
    if (!this.db) throw new Error('Database not initialized');
    const runId = crypto.randomUUID();
    const now = new Date().toISOString();

    for (const v of violations) {
      const id = crypto.randomUUID();
      this.db.run(
        `INSERT INTO dependency_violations (id, run_id, file, include_path, owning_module, referenced_module, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [id, runId, v.file, v.includePath, v.owningModule, v.referencedModule, now]
      );
    }

    this.save();
    return runId;
  }

  getDependencyRun(runId: string): Array<{
    file: string;
    includePath: string;
    owningModule: string;
    referencedModule: string;
  }> {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT * FROM dependency_violations WHERE run_id = ? ORDER BY file');
    stmt.bind([runId]);

    const results: Array<{
      file: string;
      includePath: string;
      owningModule: string;
      referencedModule: string;
    }> = [];

    while (stmt.step()) {
      const row = stmt.getAsObject() as unknown as DependencyViolationRow;
      results.push({
        file: row.file,
        includePath: row.include_path,
        owningModule: row.owning_module,
        referencedModule: row.referenced_module,
      });
    }

    stmt.free();
    return results;
  }

  getLatestDependencyRun(): { runId: string; violations: Array<{ file: string; includePath: string; owningModule: string; referencedModule: string }>; createdAt: Date } | null {
    if (!this.db) throw new Error('Database not initialized');

    const stmt = this.db.prepare(
      'SELECT run_id, created_at FROM dependency_violations ORDER BY created_at DESC LIMIT 1'
    );
    if (!stmt.step()) {
      stmt.free();
      return null;
    }
    const row = stmt.getAsObject() as { run_id: string; created_at: string };
    stmt.free();

    const violations = this.getDependencyRun(row.run_id);
    return { runId: row.run_id, violations, createdAt: new Date(row.created_at) };
  }

  // =========================================================================
  // OAuth 2.1 authorization-server state
  // =========================================================================

  saveOAuthClient(clientId: string, clientJson: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run(
      `INSERT OR REPLACE INTO oauth_clients (client_id, client_json, created_at) VALUES (?, ?, ?)`,
      [clientId, clientJson, Date.now()]
    );
    this.save();
  }

  getOAuthClient(clientId: string): string | undefined {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT client_json FROM oauth_clients WHERE client_id = ?');
    stmt.bind([clientId]);
    const json = stmt.step() ? (stmt.getAsObject().client_json as string) : undefined;
    stmt.free();
    return json;
  }

  saveAuthCode(code: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    scopes: string;
    resource: string | null;
    expiresAt: number;
  }): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run(
      `INSERT OR REPLACE INTO oauth_codes
        (code, client_id, redirect_uri, code_challenge, scopes, resource, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [code.code, code.clientId, code.redirectUri, code.codeChallenge, code.scopes, code.resource, code.expiresAt]
    );
    this.save();
  }

  /** Read an auth code without consuming it (used for PKCE challenge lookup). */
  getAuthCode(code: string): {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    scopes: string;
    resource: string | null;
    expiresAt: number;
  } | undefined {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT * FROM oauth_codes WHERE code = ?');
    stmt.bind([code]);
    const row = stmt.step() ? (stmt.getAsObject() as Record<string, unknown>) : undefined;
    stmt.free();
    if (!row) return undefined;
    return {
      clientId: row.client_id as string,
      redirectUri: row.redirect_uri as string,
      codeChallenge: row.code_challenge as string,
      scopes: (row.scopes as string) ?? '',
      resource: (row.resource as string) ?? null,
      expiresAt: row.expires_at as number,
    };
  }

  deleteAuthCode(code: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM oauth_codes WHERE code = ?', [code]);
    this.save();
  }

  saveOAuthToken(token: {
    token: string;
    kind: 'access' | 'refresh';
    clientId: string;
    scopes: string;
    resource: string | null;
    expiresAt: number | null;
  }): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run(
      `INSERT OR REPLACE INTO oauth_tokens (token, kind, client_id, scopes, resource, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [token.token, token.kind, token.clientId, token.scopes, token.resource, token.expiresAt]
    );
    this.save();
  }

  getOAuthToken(token: string): {
    kind: 'access' | 'refresh';
    clientId: string;
    scopes: string;
    resource: string | null;
    expiresAt: number | null;
  } | undefined {
    if (!this.db) throw new Error('Database not initialized');
    const stmt = this.db.prepare('SELECT * FROM oauth_tokens WHERE token = ?');
    stmt.bind([token]);
    const row = stmt.step() ? (stmt.getAsObject() as Record<string, unknown>) : undefined;
    stmt.free();
    if (!row) return undefined;
    return {
      kind: row.kind as 'access' | 'refresh',
      clientId: row.client_id as string,
      scopes: (row.scopes as string) ?? '',
      resource: (row.resource as string) ?? null,
      expiresAt: (row.expires_at as number) ?? null,
    };
  }

  deleteOAuthToken(token: string): void {
    if (!this.db) throw new Error('Database not initialized');
    this.db.run('DELETE FROM oauth_tokens WHERE token = ?', [token]);
    this.save();
  }

  // =========================================================================
  // Lifecycle
  // =========================================================================

  /**
   * Close the database connection
   */
  close(): void {
    if (this.db) {
      this.save();
      this.db.close();
      this.db = null;
    }
  }
}
