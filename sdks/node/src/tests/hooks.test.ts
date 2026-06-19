import test from 'node:test';
import assert from 'node:assert/strict';
import { guard } from '../guard';

test('guard wraps tool metadata', async () => {
  const fn = guard(function demo(value: string) {
    return value.toUpperCase();
  });
  const out = await fn('hi');
  assert.equal(out, 'HI');
});