import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';

const PIPE_PATH = '\\\\.\\pipe\\agentshield';

let reqId = 0;
let sessionId: string | undefined;

function socketPath(): string {
  if (process.platform === 'win32') {
    return PIPE_PATH;
  }
  const runtime = process.env.XDG_RUNTIME_DIR ?? '/tmp';
  return path.join(runtime, 'agentshield', 'daemon.sock');
}

export function daemonAvailable(): boolean {
  if (process.platform === 'win32') {
    try {
      fs.accessSync(PIPE_PATH, fs.constants.R_OK | fs.constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }
  return fs.existsSync(socketPath());
}

export async function analyzeViaDaemon(
  command: string,
  cwd?: string
): Promise<Record<string, unknown> | null> {
  const req = {
    id: ++reqId,
    method: 'analyze',
    params: {
      command,
      cwd: cwd ?? process.cwd(),
      session_id: sessionId ?? null,
    },
  };

  try {
    const resp = await callDaemon(req);
    if (resp.error) return null;
    const result = resp.result as Record<string, unknown> | undefined;
    if (result?.session_id && typeof result.session_id === 'string') {
      sessionId = result.session_id;
    }
    return result ?? null;
  } catch {
    return null;
  }
}

async function callDaemon(req: Record<string, unknown>): Promise<{
  result?: unknown;
  error?: { message: string };
}> {
  const payload = `${JSON.stringify(req)}\n`;

  if (process.platform === 'win32') {
    return new Promise((resolve, reject) => {
      const client = net.createConnection(PIPE_PATH, () => {
        client.write(payload);
      });
      let buf = '';
      client.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        if (buf.includes('\n')) {
          client.end();
          resolve(JSON.parse(buf.trim()) as { result?: unknown; error?: { message: string } });
        }
      });
      client.on('error', reject);
    });
  }

  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath(), () => {
      client.write(payload);
    });
    let buf = '';
    client.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.includes('\n')) {
        client.end();
        resolve(JSON.parse(buf.trim()) as { result?: unknown; error?: { message: string } });
      }
    });
    client.on('error', reject);
  });
}