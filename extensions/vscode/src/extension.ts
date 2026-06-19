import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

let statusBar: vscode.StatusBarItem;
let pollTimer: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext): void {
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'agentshield.showStatus';
  context.subscriptions.push(statusBar);

  if (vscode.workspace.getConfiguration('agentshield').get<boolean>('enabled', true)) {
    configureTerminal();
  }
  updateStatusBar();
  pollTimer = setInterval(updateStatusBar, 5000);
  context.subscriptions.push({ dispose: () => clearInterval(pollTimer) });

  context.subscriptions.push(
    vscode.commands.registerCommand('agentshield.showStatus', showStatus),
    vscode.commands.registerCommand('agentshield.enable', enableAgentShield),
    vscode.commands.registerCommand('agentshield.toggleProtection', toggleProtection)
  );
}

export function deactivate(): void {
  if (pollTimer) clearInterval(pollTimer);
}

async function toggleProtection(): Promise<void> {
  const config = vscode.workspace.getConfiguration('agentshield');
  const enabled = config.get<boolean>('enabled', true);
  await config.update('enabled', !enabled, vscode.ConfigurationTarget.Global);
  if (!enabled) {
    configureTerminal();
    vscode.window.showInformationMessage('AgentShield protection enabled.');
  } else {
    vscode.window.showInformationMessage('AgentShield protection disabled.');
  }
  updateStatusBar();
}

function configureTerminal(): void {
  const config = vscode.workspace.getConfiguration('agentshield');
  if (!config.get<boolean>('enabled', true)) return;

  const binary = config.get<string>('binaryPath', 'agentshield');
  const terminal = vscode.workspace.getConfiguration('terminal.integrated');

  const linuxEnv = terminal.get<Record<string, string>>('env.linux') ?? {};
  if (!linuxEnv.SHELL && !linuxEnv.AGENTSHIELD_BIN) {
    void terminal
      .update(
        'env.linux',
        { ...linuxEnv, SHELL: binary, AGENTSHIELD_AGENT: 'vscode' },
        vscode.ConfigurationTarget.Global
      )
      .then(undefined, (err: unknown) => {
        vscode.window.showWarningMessage(`AgentShield: failed to set Linux terminal env: ${err}`);
      });
  }

  const osxEnv = terminal.get<Record<string, string>>('env.osx') ?? {};
  if (!osxEnv.SHELL && !osxEnv.AGENTSHIELD_BIN) {
    void terminal
      .update(
        'env.osx',
        { ...osxEnv, SHELL: binary, AGENTSHIELD_AGENT: 'vscode' },
        vscode.ConfigurationTarget.Global
      )
      .then(undefined, (err: unknown) => {
        vscode.window.showWarningMessage(`AgentShield: failed to set macOS terminal env: ${err}`);
      });
  }

  const winEnv = terminal.get<Record<string, string>>('env.windows') ?? {};
  if (!winEnv.AGENTSHIELD_BIN) {
    void terminal
      .update(
        'env.windows',
        { ...winEnv, AGENTSHIELD_BIN: binary, AGENTSHIELD_AGENT: 'vscode' },
        vscode.ConfigurationTarget.Global
      )
      .then(undefined, (err: unknown) => {
        vscode.window.showWarningMessage(`AgentShield: failed to set Windows terminal env: ${err}`);
      });
  }
}

async function enableAgentShield(): Promise<void> {
  const binary = await vscode.window.showInputBox({
    prompt: 'Path to agentshield binary',
    value: 'agentshield',
  });
  if (!binary) return;
  const config = vscode.workspace.getConfiguration('agentshield');
  await config.update('binaryPath', binary, vscode.ConfigurationTarget.Global);
  await config.update('enabled', true, vscode.ConfigurationTarget.Global);
  configureTerminal();
  vscode.window.showInformationMessage('AgentShield enabled for integrated terminal.');
}

function logDirectory(): string {
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA ?? os.homedir(), 'agentshield', 'logs');
  }
  return path.join(os.homedir(), '.local', 'share', 'agentshield', 'logs');
}

function daemonStatus(): { active: boolean; version?: string; blocked?: number } {
  const binary = vscode.workspace.getConfiguration('agentshield').get<string>('binaryPath', 'agentshield');
  try {
    const out = execSync(`${binary} status --format json`, { encoding: 'utf8', timeout: 2000 });
    const payload = JSON.parse(out) as {
      daemon?: { active?: boolean; version?: string; blocked_count?: number };
    };
    return {
      active: payload.daemon?.active ?? false,
      version: payload.daemon?.version,
      blocked: payload.daemon?.blocked_count,
    };
  } catch {
    return { active: false };
  }
}

function readTodayStats(): { total: number; blocked: number } {
  const today = new Date().toISOString().slice(0, 10);
  const dir = logDirectory();
  let total = 0;
  let blocked = 0;
  try {
    for (const file of fs.readdirSync(dir)) {
      if (!file.includes(today) || !file.endsWith('.jsonl')) continue;
      const lines = fs.readFileSync(path.join(dir, file), 'utf8').split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line) as { decision?: string };
          total++;
          if (entry.decision === 'block') blocked++;
        } catch {
          continue;
        }
      }
    }
  } catch {
    return { total: 0, blocked: 0 };
  }
  return { total, blocked };
}

function updateStatusBar(): void {
  const config = vscode.workspace.getConfiguration('agentshield');
  if (!config.get<boolean>('enabled', true)) {
    statusBar.text = '$(shield) AgentShield: off';
    statusBar.backgroundColor = undefined;
    statusBar.show();
    return;
  }

  const daemon = daemonStatus();
  const { total, blocked } = readTodayStats();
  const blockedCount = Math.max(blocked, daemon.blocked ?? 0);

  if (blockedCount > 0) {
    statusBar.text = `$(shield) AgentShield: $(error) ${blockedCount} blocked`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else if (total > 0) {
    statusBar.text = `$(shield) AgentShield: active (${total})`;
    statusBar.backgroundColor = undefined;
  } else if (daemon.active) {
    statusBar.text = `$(shield) AgentShield: daemon ${daemon.version ?? ''}`.trim();
    statusBar.backgroundColor = undefined;
  } else {
    statusBar.text = '$(shield) AgentShield: active';
    statusBar.backgroundColor = undefined;
  }
  statusBar.tooltip = `AgentShield security runtime\nDaemon: ${daemon.active ? 'connected' : 'offline'}\nCommands today: ${total}\nBlocked: ${blockedCount}`;
  statusBar.show();
}

function showStatus(): void {
  const daemon = daemonStatus();
  const { total, blocked } = readTodayStats();
  vscode.window.showInformationMessage(
    `AgentShield: ${total} commands today, ${blocked} blocked. Daemon: ${daemon.active ? 'active' : 'offline'}. Logs: ${logDirectory()}`
  );
}