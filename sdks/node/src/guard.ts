import { analyze } from './hooks';

export function guard<T extends (...args: unknown[]) => unknown>(fn: T): T {
  return ((...args: unknown[]) => {
    const label = `${fn.name}(${JSON.stringify(args)})`;
    if (analyze(label) === 'block') {
      throw new Error(`[agentshield] blocked tool ${fn.name}`);
    }
    return fn(...args);
  }) as T;
}