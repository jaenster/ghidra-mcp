/**
 * Table discovery — reads known function-pointer tables on both platforms
 * to create verified anchor links between Win and Mac sessions.
 *
 * Uses read_memory to get raw bytes, then extracts pointers at the correct
 * stride/offset positions. This handles tables with non-trivial layouts
 * (multi-pointer entries, NULL gaps, etc.) correctly.
 */

import type { WorkerCommand, WorkerResponse } from '@ghidra-mcp/shared/protocol';

interface TableDef {
  name: string;
  winAddr: string;
  macAddr: string;
  count: number;
  stride: number;
  ptrOffsets: number[];
  macPtrOffsets?: number[];
}

const KNOWN_TABLES: TableDef[] = [
  { name: 'aQuestInitDataExtended (fpQuestInit)', winAddr: '00731510', macAddr: '003e2170', count: 37, stride: 24, ptrOffsets: [0] },
  { name: 'ApplicationBootstrapArray (init/shutdown)', winAddr: '00706554', macAddr: '003e0eb8', count: 6, stride: 8, ptrOffsets: [0, 4] },
  { name: 'S2C Packet Dispatch (handler/handlerUnit)', winAddr: '007114d0', macAddr: '003cfe80', count: 175, stride: 12, ptrOffsets: [0, 8] },
  { name: 'EQUIP BodyLocation Handlers', winAddr: '00721e60', macAddr: '003d0c5c', count: 9, stride: 4, ptrOffsets: [0] },
  { name: 'gaPlayerModeCallbacks', winAddr: '00732c10', macAddr: '003e1c0c', count: 20, stride: 4, ptrOffsets: [0] },
  { name: 'SKILLCLTDOFUNCS', winAddr: '00727ba8', macAddr: '00398b30', count: 130, stride: 4, ptrOffsets: [0] },
  { name: 'SKILLSRVDOFUNCS', winAddr: '007322b0', macAddr: '003c7ac0', count: 152, stride: 4, ptrOffsets: [0] },
  { name: 'gapObjectOperateCallbacks', winAddr: '00732cec', macAddr: '003e17d0', count: 10, stride: 4, ptrOffsets: [0] },
  { name: 'OBJECTSOPERATEFN', winAddr: '00732d18', macAddr: '003e180c', count: 74, stride: 4, ptrOffsets: [0] },
  { name: 'C2S Packet Dispatch (NET_D2GS_SERVER_INCOMING)', winAddr: '006e0d18', macAddr: '003e1e28', count: 103, stride: 8, ptrOffsets: [0] },
  { name: 'arrGeneralAiList (init/main/secondary)', winAddr: '0073ca18', macAddr: '003ba268', count: 148, stride: 16, ptrOffsets: [4, 8, 12] },
  { name: 'DropHandlerArray', winAddr: '006e2260', macAddr: '003e0fec', count: 21, stride: 16, ptrOffsets: [0] },
  { name: 'MISSILESCLTDOFUNCS', winAddr: '0072a398', macAddr: '003b1b80', count: 91, stride: 4, ptrOffsets: [0] },
  { name: 'STATESSETFUNC', winAddr: '0072a690', macAddr: '003b3d58', count: 19, stride: 4, ptrOffsets: [0] },
  { name: 'STATESREMFUNC', winAddr: '0072a710', macAddr: '003b3dd4', count: 12, stride: 4, ptrOffsets: [0] },
  { name: 'gaPropertyFuncTable', winAddr: '00745b58', macAddr: '003e05e0', count: 37, stride: 8, ptrOffsets: [0] },
  { name: 'Missiles_CltHitFunc', winAddr: '0072a530', macAddr: '003b1cf0', count: 50, stride: 4, ptrOffsets: [0] },
  { name: 'SKILLCLTSTFUNCS', winAddr: '00727a90', macAddr: '00398a18', count: 70, stride: 4, ptrOffsets: [0] },
  { name: 'SKILLSRVSTFUNCS', winAddr: '00732140', macAddr: '003c7954', count: 91, stride: 4, ptrOffsets: [0] },
  { name: 'MISSILESSRVDOFUNCS', winAddr: '0073c768', macAddr: '003bad20', count: 53, stride: 4, ptrOffsets: [0] },
  { name: 'MISSILESSRVHITFUNCS', winAddr: '0073c840', macAddr: '003badf4', count: 71, stride: 4, ptrOffsets: [0] },
  { name: 'gaPlayerModeMoveFuncs', winAddr: '006e1740', macAddr: '003e1c5c', count: 40, stride: 4, ptrOffsets: [0] },
];

function normalizeAddr(addr: string): string {
  return addr.replace(/^0x/i, '').padStart(8, '0').toLowerCase();
}

/** Read a little-endian uint32 from a buffer */
function readU32LE(buf: Buffer, offset: number): number {
  return buf.readUInt32LE(offset);
}

/** Read a big-endian uint32 from a buffer (Mach-O / PPC) */
function readU32BE(buf: Buffer, offset: number): number {
  return buf.readUInt32BE(offset);
}

/** Extract pointers from raw table bytes at given stride/offsets */
function extractPointers(
  buf: Buffer, count: number, stride: number, ptrOffsets: number[], le: boolean
): string[][] {
  const read = le ? readU32LE : readU32BE;
  const result: string[][] = [];
  for (let i = 0; i < count; i++) {
    const base = i * stride;
    const ptrs: string[] = [];
    for (const off of ptrOffsets) {
      const byteOff = base + off;
      if (byteOff + 4 > buf.length) break;
      const val = read(buf, byteOff);
      ptrs.push(val.toString(16).padStart(8, '0'));
    }
    result.push(ptrs);
  }
  return result;
}

interface DiscoverOptions {
  winSession: string;
  macSession: string;
  dryRun?: boolean;
  tables?: string[];
  sendCommand: (sessionId: string, command: WorkerCommand) => Promise<WorkerResponse>;
  bulkCreateLinks: (links: Array<{
    sourceSession: string; sourceAddress: string;
    targetSession: string; targetAddress: string;
    linkType?: string; anchor?: boolean; metadata?: Record<string, unknown>;
  }>) => number;
}

interface TableReport {
  name: string;
  entriesLinked: number;
  skippedNull: number;
}

async function readTableBytes(
  sessionId: string, address: string, length: number,
  sendCommand: DiscoverOptions['sendCommand']
): Promise<Buffer | null> {
  const result = await sendCommand(sessionId, {
    id: crypto.randomUUID(),
    command: 'read_memory',
    params: { address: `0x${address}`, length },
  } as unknown as WorkerCommand);

  if (!result.success) return null;
  const b64 = (result.result as { bytes?: string })?.bytes;
  if (!b64) return null;
  return Buffer.from(b64, 'base64');
}

export async function discoverTableAnchors(opts: DiscoverOptions): Promise<{
  tables: TableReport[];
  totalAnchors: number;
  dryRun: boolean;
}> {
  const { winSession, macSession, dryRun = false, tables: tableFilter, sendCommand, bulkCreateLinks } = opts;

  const tablesToProcess = tableFilter
    ? KNOWN_TABLES.filter(t => tableFilter.some(f => t.name.toLowerCase().includes(f.toLowerCase())))
    : KNOWN_TABLES;

  const reports: TableReport[] = [];
  const allLinks: Array<{
    sourceSession: string; sourceAddress: string;
    targetSession: string; targetAddress: string;
    linkType: string; anchor: boolean; metadata: Record<string, unknown>;
  }> = [];

  for (const table of tablesToProcess) {
    const macOffsets = table.macPtrOffsets ?? table.ptrOffsets;
    const winBytes = table.count * table.stride;
    const macBytes = table.count * table.stride;

    const [winBuf, macBuf] = await Promise.all([
      readTableBytes(winSession, table.winAddr, winBytes, sendCommand),
      readTableBytes(macSession, table.macAddr, macBytes, sendCommand),
    ]);

    let entriesLinked = 0;
    let skippedNull = 0;

    if (winBuf && macBuf) {
      // Win is always LE (x86 PE), Mac is also LE (x86 Mach-O for 1.14d)
      const winPtrs = extractPointers(winBuf, table.count, table.stride, table.ptrOffsets, true);
      const macPtrs = extractPointers(macBuf, table.count, table.stride, macOffsets, true);

      for (let i = 0; i < table.count; i++) {
        const wPtrs = winPtrs[i] ?? [];
        const mPtrs = macPtrs[i] ?? [];

        for (let p = 0; p < Math.min(wPtrs.length, mPtrs.length); p++) {
          const winAddr = wPtrs[p];
          const macAddr = mPtrs[p];

          if (winAddr === '00000000' || macAddr === '00000000') {
            skippedNull++;
            continue;
          }

          allLinks.push({
            sourceSession: winSession,
            sourceAddress: `0x${winAddr}`,
            targetSession: macSession,
            targetAddress: `0x${macAddr}`,
            linkType: 'table_entry',
            anchor: true,
            metadata: { tableName: table.name, entryIndex: i, ptrOffset: table.ptrOffsets[p] ?? macOffsets[p] },
          });
          entriesLinked++;
        }
      }
    }

    reports.push({ name: table.name, entriesLinked, skippedNull });
  }

  let totalAnchors = allLinks.length;

  if (!dryRun && allLinks.length > 0) {
    totalAnchors = bulkCreateLinks(allLinks);
  }

  return {
    tables: reports,
    totalAnchors,
    dryRun,
  };
}
