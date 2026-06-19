import { exec, execSync, spawn, SpawnOptions } from 'child_process';

let active = false;
const originalExec = exec;
const originalExecSync = execSync;
const originalSpawn = spawn;

function agentshieldBin(): string {
  return process.env.AGENTSHIELD_BIN ?? 'agentshield';
}

function failOpen(): boolean {
  return process.env.AGENTSHIELD_FAIL_OPEN === '1';
}

export function analyze(command: string): 'allow' | 'block' | 'prompt' {
  try {
    const out = originalExecSync(
      `${agentshieldBin()} analyze --format json ${JSON.stringify(command)}`,
      {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }
    );
    const payload = JSON.parse(out) as { decision?: { kind?: string } };
    const kind = payload.decision?.kind;
    if (kind === 'block' || kind === 'prompt' || kind === 'allow') {
      return kind;
    }
    return failOpen() ? 'allow' : 'block';
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[agentshield] analyze failed: ${message}\n`);
    return failOpen() ? 'allow' : 'block';
  }
}

function guardedExec(
  command: string,
  options?: Parameters<typeof exec>[1],
  callback?: Parameters<typeof exec>[2]
): ReturnType<typeof exec> {
  const decision = analyze(command);
  if (decision === 'block') {
    throw new Error(`[agentshield] blocked: ${command}`);
  }
  return originalExec(command, options, callback);
}

function guardedSpawn(
  command: string,
  args?: readonly string[],
  options?: SpawnOptions
): ReturnType<typeof spawn> {
  const full = [command, ...(args ?? [])].join(' ');
  const decision = analyze(full);
  if (decision === 'block') {
    throw new Error(`[agentshield] blocked: ${full}`);
  }
  return originalSpawn(command, args, options);
}

export function activate(): void {
  if (active) return;
  (require('child_process') as typeof import('child_process')).exec = guardedExec as typeof exec;
  (require('child_process') as typeof import('child_process')).spawn = guardedSpawn as typeof spawn;
  active = true;
}

export function deactivate(): void {
  if (!active) return;
  (require('child_process') as typeof import('child_process')).exec = originalExec;
  (require('child_process') as typeof import('child_process')).spawn = originalSpawn;
  active = false;
}

export function isActive(): boolean {
  return active;
}