/**
 * Dependency validator — checks that reconstructed source files only include
 * headers from modules within their dependency tree.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

interface ModuleConfig {
  namespaces: string[];
  dependencies?: string[];
}

interface TypeOwnershipEntry {
  type: string;
  header: string;
}

interface Violation {
  file: string;
  includePath: string;
  owningModule: string;
  referencedModule: string;
}

/**
 * Build transitive dependency closure for each module (BFS)
 */
function buildClosures(modules: Record<string, ModuleConfig>): Map<string, Set<string>> {
  const closures = new Map<string, Set<string>>();

  for (const moduleName of Object.keys(modules)) {
    const closure = new Set<string>();
    const queue = [moduleName];
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (closure.has(current)) continue;
      closure.add(current);
      const deps = modules[current]?.dependencies ?? [];
      for (const dep of deps) {
        if (!closure.has(dep)) queue.push(dep);
      }
    }
    closures.set(moduleName, closure);
  }

  return closures;
}

/**
 * Map header paths to their owning module.
 * First path segment of the header = module name (lowercase convention).
 */
function buildHeaderToModule(
  modules: Record<string, ModuleConfig>,
  typeOwnership?: TypeOwnershipEntry[]
): Map<string, string> {
  const headerToModule = new Map<string, string>();

  // Module names map to lowercase directory names
  const lowerToModule = new Map<string, string>();
  for (const name of Object.keys(modules)) {
    lowerToModule.set(name.toLowerCase(), name);
  }

  // typeOwnership entries give us explicit header→module mappings
  if (typeOwnership) {
    for (const entry of typeOwnership) {
      const firstSeg = entry.header.split('/')[0];
      const mod = lowerToModule.get(firstSeg.toLowerCase());
      if (mod) {
        headerToModule.set(entry.header, mod);
      }
    }
  }

  return headerToModule;
}

/**
 * Determine which module owns a source file based on its directory path.
 */
function getFileModule(filePath: string, srcRoot: string, modules: Record<string, ModuleConfig>): string | null {
  const rel = path.relative(srcRoot, filePath).replace(/\\/g, '/');
  const firstSeg = rel.split('/')[0];

  // Direct module name match (case-insensitive)
  for (const [name] of Object.entries(modules)) {
    if (name.toLowerCase() === firstSeg.toLowerCase()) return name;
  }

  return null;
}

/**
 * Parse #include directives from a source file.
 * Only handles project-relative includes (quoted, not angle-bracket).
 */
function parseIncludes(content: string): string[] {
  const includes: string[] = [];
  const regex = /^#include\s+"([^"]+)"/gm;
  let match;
  while ((match = regex.exec(content)) !== null) {
    includes.push(match[1]);
  }
  return includes;
}

export async function validateDependencies(projectJsonPath?: string): Promise<{
  violations: Violation[];
  summary: { totalFiles: number; totalIncludes: number; violationCount: number; byModule: Record<string, number> };
}> {
  // Auto-detect project.json
  const projectPath = projectJsonPath ?? path.resolve('reconstructed/diablo2/project.json');
  if (!fs.existsSync(projectPath)) {
    throw new Error(`project.json not found at: ${projectPath}`);
  }

  const config = JSON.parse(fs.readFileSync(projectPath, 'utf-8'));
  const modules: Record<string, ModuleConfig> = config.modules ?? {};
  const typeOwnership: TypeOwnershipEntry[] = config.typeOwnership ?? [];

  if (Object.keys(modules).length === 0) {
    return {
      violations: [],
      summary: { totalFiles: 0, totalIncludes: 0, violationCount: 0, byModule: {} },
    };
  }

  const closures = buildClosures(modules);
  const headerToModule = buildHeaderToModule(modules, typeOwnership);

  // Module name lowercase → canonical name
  const lowerToModule = new Map<string, string>();
  for (const name of Object.keys(modules)) {
    lowerToModule.set(name.toLowerCase(), name);
  }

  const srcRoot = path.resolve(path.dirname(projectPath), 'src');
  const violations: Violation[] = [];
  let totalFiles = 0;
  let totalIncludes = 0;
  const byModule: Record<string, number> = {};

  // Scan all .cpp files in src/
  if (!fs.existsSync(srcRoot)) {
    throw new Error(`Source root not found: ${srcRoot}`);
  }

  const scanDir = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scanDir(fullPath);
      } else if (entry.name.endsWith('.cpp') || entry.name.endsWith('.h')) {
        totalFiles++;
        const owningModule = getFileModule(fullPath, srcRoot, modules);
        if (!owningModule) continue;

        const content = fs.readFileSync(fullPath, 'utf-8');
        const includes = parseIncludes(content);

        for (const inc of includes) {
          totalIncludes++;
          // Determine which module the included header belongs to
          let referencedModule = headerToModule.get(inc);
          if (!referencedModule) {
            const firstSeg = inc.split('/')[0];
            referencedModule = lowerToModule.get(firstSeg.toLowerCase());
          }
          if (!referencedModule) continue;

          // Check if it's in the closure
          const closure = closures.get(owningModule);
          if (closure && !closure.has(referencedModule)) {
            const relFile = path.relative(srcRoot, fullPath).replace(/\\/g, '/');
            violations.push({
              file: relFile,
              includePath: inc,
              owningModule,
              referencedModule,
            });
            byModule[owningModule] = (byModule[owningModule] ?? 0) + 1;
          }
        }
      }
    }
  };

  scanDir(srcRoot);

  return {
    violations,
    summary: {
      totalFiles,
      totalIncludes,
      violationCount: violations.length,
      byModule,
    },
  };
}
