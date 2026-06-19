import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

let statusBar: vscode.StatusBarItem;
let pollTimer: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext): void {
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'agentshield.showStatus';
  context.subscriptions.push(statusBar);

  configureTerminal();
  updateStatusBar();
  pollTimer = setInterval(updateStatusBar, 5000);
  context.subscriptions.push({ dispose: () => clearInterval(pollTimer) });

  context.subscriptions.push(
    vscode.commands.registerCommand('agentshield.showStatus', showStatus),
    vscode.commands.registerCommand('agentshield.enable', enableAgentShield)
  );
}

export function deactivate(): void {
  if (pollTimer) clearInterval(pollTimer);
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

  const { total, blocked } = readTodayStats();
  if (blocked > 0) {
    statusBar.text = `$(shield) AgentShield: $(error) ${blocked} blocked`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else if (total > 0) {
    statusBar.text = `$(shield) AgentShield: active (${total})`;
    statusBar.backgroundColor = undefined;
  } else {
    statusBar.text = '$(shield) AgentShield: active';
    statusBar.backgroundColor = undefined;
  }
  statusBar.tooltip = `AgentShield security runtime\nCommands today: ${total}\nBlocked: ${blocked}`;
  statusBar.show();
}

function showStatus(): void {
  const { total, blocked } = readTodayStats();
  vscode.window.showInformationMessage(
    `AgentShield: ${total} commands today, ${blocked} blocked. Logs: ${logDirectory()}`
  );
}