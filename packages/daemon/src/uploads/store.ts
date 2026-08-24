/**
 * Short-lived upload slots.
 *
 * The worker fetches the bytes it imports, and it runs somewhere that cannot see the
 * client's disk. Rather than push a binary through the MCP transport as base64, a client
 * asks for an upload slot, PUTs the file to the URL it gets back, and then names that
 * upload in import_program.
 *
 * The id is the capability: it is unguessable, single-use and expires, so the upload route
 * itself needs no session. Slots are created only by an authenticated MCP call.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface UploadSlot {
  id: string;
  filename: string;
  filePath: string;
  createdAt: Date;
  expiresAt: Date;
  /** Set once bytes have landed; a slot may only be filled once. */
  receivedBytes?: number;
  receivedAt?: Date;
  /** Set once an import has taken these bytes, so the slot cannot be used again. */
  spentAt?: Date;
}

export interface UploadStoreOptions {
  /** Where uploaded bytes are written. Should be on the daemon's data volume. */
  dir: string;
  /** How long a slot lives before it is swept, in ms. */
  ttlMs?: number;
  /** Largest upload accepted, in bytes. */
  maxBytes?: number;
}

export class UploadStore {
  private slots = new Map<string, UploadSlot>();
  private readonly dir: string;
  readonly ttlMs: number;
  readonly maxBytes: number;
  private sweeper: NodeJS.Timeout;

  constructor(options: UploadStoreOptions) {
    this.dir = options.dir;
    this.ttlMs = options.ttlMs ?? Number(process.env.GHIDRA_MCP_UPLOAD_TTL_MS ?? 3_600_000);
    this.maxBytes = options.maxBytes
      ?? Number(process.env.GHIDRA_MCP_UPLOAD_MAX_BYTES ?? 2 * 1024 * 1024 * 1024);
    fs.mkdirSync(this.dir, { recursive: true });
    this.sweeper = setInterval(() => this.sweep(), 60_000);
    this.sweeper.unref();
  }

  /** Reserve a slot. The returned id is the only thing that authorises writing to it. */
  create(filename?: string): UploadSlot {
    const id = crypto.randomBytes(24).toString('base64url');
    const safeName = sanitizeFilename(filename) || 'upload.bin';
    const now = new Date();
    const slot: UploadSlot = {
      id,
      filename: safeName,
      filePath: path.join(this.dir, `${id}-${safeName}`),
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.ttlMs),
    };
    this.slots.set(id, slot);
    return slot;
  }

  get(id: string): UploadSlot | undefined {
    const slot = this.slots.get(id);
    if (!slot) return undefined;
    if (slot.expiresAt.getTime() < Date.now()) {
      this.remove(id);
      return undefined;
    }
    return slot;
  }

  /**
   * Mark a slot as used by an import. The bytes stay until the slot expires: the import runs
   * as a background job, so the worker may not have fetched them yet.
   */
  markSpent(id: string): void {
    const slot = this.slots.get(id);
    if (slot) {
      slot.spentAt = new Date();
    }
  }

  markReceived(id: string, bytes: number): void {
    const slot = this.slots.get(id);
    if (!slot) return;
    slot.receivedBytes = bytes;
    slot.receivedAt = new Date();
  }

  /** Forget a slot and delete whatever it holds. */
  remove(id: string): void {
    const slot = this.slots.get(id);
    this.slots.delete(id);
    if (slot) {
      try {
        fs.rmSync(slot.filePath, { force: true });
      } catch {
        // best effort
      }
    }
  }

  list(): UploadSlot[] {
    return Array.from(this.slots.values());
  }

  private sweep(): void {
    const now = Date.now();
    for (const [id, slot] of this.slots) {
      if (slot.expiresAt.getTime() < now) {
        this.remove(id);
      }
    }
  }

  dispose(): void {
    clearInterval(this.sweeper);
  }
}

/** Keep a client-supplied name usable as a filename and confined to the upload dir. */
function sanitizeFilename(name?: string): string {
  if (!name) return '';
  return path.basename(name).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 100);
}
