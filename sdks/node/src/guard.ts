import { analyze, analyzeAsync } from './hooks';

export type AnalysisType = 'command' | 'filesystem' | 'network' | 'tool_metadata';

export interface GuardOptions {
  analysisType?: AnalysisType;
  toolRules?: Record<string, unknown>;
}

export function guard<T extends (...args: unknown[]) => unknown>(
  fn: T,
  options: GuardOptions = {}
): T {
  const analysisType = options.analysisType ?? 'tool_metadata';

  return (async (...args: unknown[]) => {
    let label: string;
    if (analysisType === 'command' && args.length > 0) {
      label = String(args[0]);
    } else if (analysisType === 'filesystem' && args.length > 0) {
      label = `cat ${String(args[0])}`;
    } else if (analysisType === 'network' && args.length > 0) {
      label = `curl ${String(args[0])}`;
    } else {
      label = JSON.stringify({
        tool: fn.name,
        args,
        rules: options.toolRules ?? {},
      });
    }

    const decision = await analyzeAsync(label);
    if (decision === 'block') {
      throw new Error(`[agentshield] blocked tool ${fn.name}`);
    }
    return fn(...args);
  }) as T;
}