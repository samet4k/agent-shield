import { activate, deactivate } from './hooks';

export async function session<T>(fn: () => Promise<T> | T): Promise<T> {
  activate();
  try {
    return await fn();
  } finally {
    deactivate();
  }
}