#!/usr/bin/env node
/**
 * @ghidra-mcp/cli
 * Command-line interface for Ghidra MCP
 */

import { Command } from 'commander';
import { startCommand } from './commands/start.js';
import { stopCommand } from './commands/stop.js';
import { statusCommand } from './commands/status.js';
import { sessionsCommand } from './commands/sessions.js';
import { stdioCommand } from './commands/stdio.js';

const program = new Command()
  .name('ghidra-mcp')
  .description('Headless Ghidra MCP server for reverse engineering')
  .version('1.0.0');

// Start daemon
program
  .command('start')
  .description('Start the Ghidra MCP daemon')
  .option('-p, --port <port>', 'Port to listen on', '8432')
  .option('-f, --foreground', 'Run in foreground (don\'t daemonize)', false)
  .option('--force', 'Skip check for existing daemon (for testing)', false)
  .action(startCommand);

// Stop daemon
program
  .command('stop')
  .description('Stop the Ghidra MCP daemon')
  .action(stopCommand);

// Status
program
  .command('status')
  .description('Show daemon status')
  .action(statusCommand);

// Sessions management
const sessions = program
  .command('sessions')
  .description('Manage analysis sessions');

sessions
  .command('list')
  .description('List active sessions')
  .action(async () => sessionsCommand('list'));

sessions
  .command('create <binary>')
  .description('Create a new session for a binary')
  .option('--no-analyze', 'Skip auto-analysis')
  .action(async (binary, options) => sessionsCommand('create', { binary, ...options }));

sessions
  .command('close <sessionId>')
  .description('Close a session')
  .action(async (sessionId) => sessionsCommand('close', { sessionId }));

// Stdio mode (for MCP clients that use stdio transport)
program
  .command('stdio')
  .description('Run in stdio mode (for MCP clients)')
  .action(stdioCommand);

program.parse();
