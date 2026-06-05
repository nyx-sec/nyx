// Phase 10 (Track J.8) — TypeScript PROTOTYPE_POLLUTION vuln fixture.
//
// Same shape as the JS sibling: parse the attacker-controlled JSON
// string, deep-merge it into a vanilla `{}` target, get prototype
// pollution when the payload carries a `__proto__` key.
import * as _ from 'lodash';

export function deepMerge(target: any, source: any): any {
  return (_ as any).merge(target, source);
}

export function run(payload: string): any {
  const parsed = JSON.parse(payload);
  const target: any = {};
  return deepMerge(target, parsed);
}
