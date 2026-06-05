// Phase 10 (Track J.8) — TypeScript PROTOTYPE_POLLUTION benign
// control fixture.
//
// Uses `Object.create(null)` as the merge target so even a payload
// whose top-level key is `__proto__` cannot reach
// `Object.prototype`.
import * as _ from 'lodash';

export function deepMerge(target: any, source: any): any {
  return (_ as any).merge(target, source);
}

export function run(payload: string): any {
  const parsed = JSON.parse(payload);
  const target: any = Object.create(null);
  return deepMerge(target, parsed);
}
