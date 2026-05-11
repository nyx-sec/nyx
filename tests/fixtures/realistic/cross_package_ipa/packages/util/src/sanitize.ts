// Cross-package fixture for Phase 09: passthrough function whose name is
// NOT in the JS/TS intrinsic sanitizer matcher list, so the only way for
// the engine to know it preserves taint is via the cross-package SSA
// summary lookup that step 0.7 of `resolve_callee_full` performs.
export function escapeHtmlNoop(s: string): string {
  return s;
}
